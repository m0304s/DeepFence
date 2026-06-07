"""eve.json 비동기 테일링 및 FlowRecord 파싱."""

import json
import os
from ipaddress import ip_address
from pathlib import Path
from typing import Iterable

from deepfence_common.schemas import FlowKey, FlowRecord
from deepfence_common.logging import configure_logging
from deepfence_common.config import RuntimePaths
from deepfence_common.netflow_features import build_netflow_v1_features

# P1: 멀티캐스트/브로드캐스트 필터
_MULTICAST_PREFIX = 224
_BROADCAST_SUFFIX = "255"

# P1: 주요 CDN/클라우드 IP 대역 화이트리스트 (CIDR 프리픽스 기반)
_CLOUD_PREFIXES = (
    "142.250.",  # Google
    "142.251.",  # Google
    "172.217.",  # Google
    "216.58.",   # Google
    "64.233.",   # Google
    "17.248.",   # Apple
    "17.249.",   # Apple
    "17.250.",   # Apple
    "17.251.",   # Apple
    "17.252.",   # Apple
    "17.253.",   # Apple
    "140.82.112.", # GitHub
    "140.82.113.", # GitHub
    "140.82.114.", # GitHub
    "140.82.121.", # GitHub
    "20.",       # Microsoft Azure
    "52.",       # Microsoft Azure/AWS
    "13.",       # Microsoft Azure
    "104.16.",   # Cloudflare
    "104.17.",   # Cloudflare
    "104.18.",   # Cloudflare
    "104.19.",   # Cloudflare
    "104.20.",   # Cloudflare
    "104.21.",   # Cloudflare
    "125.209.",  # Naver
    "223.130.",  # Naver
    "31.13.",    # Meta/Facebook
    "157.240.",  # Meta/Facebook
    "151.101.",  # Reddit/Fastly CDN
)


class SuricataTailer:
    """Suricata의 eve.json 로그를 실시간으로 읽어 FlowRecord로 변환."""
    
    def __init__(self, log_dir: Path, paths: RuntimePaths, feature_set: str = "cicflowmeter_v1"):
        self._eve_path = log_dir / "eve.json"
        self._logger = configure_logging("deepfence.tailer")
        self._file = None
        self._inode = None
        self._feature_set = feature_set
        
        feature_names_path = paths.processed_dir / "feature_names.json"
        with feature_names_path.open(encoding="utf-8") as f:
            self._feature_names = json.load(f)
            
        self._flow_cache = {}  # flow_id -> {"dns": set(), "http": set(), "tls": {}, "http_meta": {}}
        self._processed_flow_ids = set()

    def _open_file(self) -> bool:
        try:
            if not self._eve_path.exists():
                return False
            self._file = open(self._eve_path, "r", encoding="utf-8")
            self._inode = os.fstat(self._file.fileno()).st_ino
            # 실시간 분석을 위해 끝에서부터 시작
            self._file.seek(0, os.SEEK_END)
            return True
        except Exception:
            return False

    def tail(self) -> Iterable[FlowRecord]:
        """비동기적으로 새로 추가된 라인을 읽어 FlowRecord로 반환."""
        if not self._file:
            if not self._open_file():
                return
                
        while True:
            # 파일 로테이션 감지
            try:
                current_inode = os.stat(self._eve_path).st_ino
                if current_inode != self._inode:
                    self._file.close()
                    self._open_file()
            except FileNotFoundError:
                pass

            line = self._file.readline()
            if not line:
                break
                
            try:
                event = json.loads(line)
                flow_record = self._parse_event(event)
                if flow_record:
                    yield flow_record
            except json.JSONDecodeError:
                continue

    @staticmethod
    def _is_noise_ip(ip: str) -> bool:
        """P1: 멀티캐스트, 브로드캐스트, 링크로컬 트래픽 필터."""
        if not ip:
            return True
        if ip.endswith("." + _BROADCAST_SUFFIX):
            return True
        try:
            addr = ip_address(ip)
            return addr.is_multicast or addr.is_link_local
        except ValueError:
            return False

    @staticmethod
    def _is_cloud_ip(ip: str) -> bool:
        """P1: 주요 CDN/클라우드 IP 대역 여부 확인."""
        return ip.startswith(_CLOUD_PREFIXES)

    def _parse_event(self, event: dict) -> FlowRecord | None:
        """Suricata 이벤트를 DeepFence FlowRecord ML 피처 구조로 매핑."""
        event_type = event.get("event_type")
        flow_id = event.get("flow_id")
        
        # P2: DNS 쿼리 캐싱
        if event_type == "dns":
            dns_data = event.get("dns", {})
            rrname = dns_data.get("rrname")
            if rrname and flow_id:
                cache = self._flow_cache.setdefault(
                    flow_id, {"dns": set(), "http": set(), "tls": {}, "http_meta": {}}
                )
                cache["dns"].add(rrname)
            return None
            
        # P2: HTTP 메타데이터 캐싱
        if event_type == "http":
            http_data = event.get("http", {})
            url = http_data.get("url")
            if flow_id:
                cache = self._flow_cache.setdefault(
                    flow_id, {"dns": set(), "http": set(), "tls": {}, "http_meta": {}}
                )
                if url:
                    cache["http"].add(url)
                cache["http_meta"] = {
                    "method": http_data.get("http_method", ""),
                    "status": http_data.get("status", 0),
                    "content_type": http_data.get("http_content_type", ""),
                    "length": http_data.get("length", 0),
                    "hostname": http_data.get("hostname", ""),
                    "user_agent": http_data.get("http_user_agent", ""),
                }
            return None

        # P2: TLS 메타데이터 캐싱
        if event_type == "tls":
            tls_data = event.get("tls", {})
            if flow_id:
                cache = self._flow_cache.setdefault(
                    flow_id, {"dns": set(), "http": set(), "tls": {}, "http_meta": {}}
                )
                cache["tls"] = {
                    "sni": tls_data.get("sni", ""),
                    "version": tls_data.get("version", ""),
                    "ja3": tls_data.get("ja3", {}).get("hash", ""),
                    "ja3s": tls_data.get("ja3s", {}).get("hash", ""),
                }
            return None
        
        # P3: Suricata 네이티브 얼럿 처리
        if event_type == "alert":
            alert_data = event.get("alert", {})
            signature = alert_data.get("signature", "Unknown Suricata Alert")
            signature_id = alert_data.get("signature_id", 0)
            severity = alert_data.get("severity", 3)
            
            # 우리가 동적으로 추가한 차단 룰로 인한 얼럿은 무시 (무한 루프 방지)
            if signature_id >= 1000000 or signature.startswith("DeepFence ML Block"):
                return None
                
            src_ip = event.get("src_ip", "")
            dst_ip = event.get("dest_ip", "")
            src_port = event.get("src_port", 0)
            dst_port = event.get("dest_port", 0)
            protocol = event.get("proto", "TCP")
            
            if self._is_noise_ip(dst_ip) or self._is_noise_ip(src_ip):
                return None
                
            key = FlowKey(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol
            )
            
            features = self._empty_features()
            metadata = {
                "source": "suricata-alert",
                "suricata_alert_signature": signature,
                "suricata_alert_severity": severity,
            }
            return FlowRecord(key=key, features=features, metadata=metadata, pre_scaled=False)
            
        # flow 이벤트만 처리
        if event_type != "flow":
            return None

        # P0: 중복 플로우 필터링
        # macOS lo0에서는 짧은 로컬 TCP 요청이 state=new/reason=timeout으로 배출되는 경우가 있다.
        # timeout reason은 Suricata가 더 이상 관찰하지 않는 플로우이므로 실시간 분석 대상으로 허용한다.
        flow_data = event.get("flow", {})
        state = flow_data.get("state", "")
        reason = flow_data.get("reason", "")
        if state != "closed" and reason != "timeout":
            return None
        if flow_id in self._processed_flow_ids:
            return None
        self._processed_flow_ids.add(flow_id)
        if len(self._processed_flow_ids) > 20000:
            self._processed_flow_ids.clear()
            
        cache = self._flow_cache.pop(
            flow_id, {"dns": set(), "http": set(), "tls": {}, "http_meta": {}}
        )
            
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dest_ip", "")
        src_port = event.get("src_port", 0)
        dst_port = event.get("dest_port", 0)
        protocol = event.get("proto", "TCP")

        # P1: 멀티캐스트/브로드캐스트 노이즈 제거
        if self._is_noise_ip(dst_ip) or self._is_noise_ip(src_ip):
            return None
        
        key = FlowKey(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol
        )
        
        fwd_pkts = float(flow_data.get("pkts_toserver", 0))
        bwd_pkts = float(flow_data.get("pkts_toclient", 0))
        fwd_bytes = float(flow_data.get("bytes_toserver", 0))
        bwd_bytes = float(flow_data.get("bytes_toclient", 0))
        duration = float(flow_data.get("age", 0.0))
        if duration <= 0.0:
            duration = 1e-6
        
        total_pkts = fwd_pkts + bwd_pkts
        total_bytes = fwd_bytes + bwd_bytes
        
        features = self._empty_features()
        
        # P2: Suricata에서 추출 가능한 피처를 최대한 매핑
        fwd_pkt_len_mean = fwd_bytes / fwd_pkts if fwd_pkts > 0 else 0.0
        bwd_pkt_len_mean = bwd_bytes / bwd_pkts if bwd_pkts > 0 else 0.0
        pkt_len_mean = total_bytes / total_pkts if total_pkts > 0 else 0.0
        
        if self._feature_set == "netflow_v1":
            features.update(
                build_netflow_v1_features(
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    app_proto=event.get("app_proto", ""),
                    in_bytes=fwd_bytes,
                    out_bytes=bwd_bytes,
                    in_pkts=fwd_pkts,
                    out_pkts=bwd_pkts,
                    tcp_flags=_tcp_flags_from_event(event),
                    duration_milliseconds=duration * 1000.0,
                )
            )
        else:
            features.update({
                "Dst Port": float(dst_port),
                "Protocol": 6.0 if protocol.upper() == "TCP" else 17.0,
                "Flow Duration": duration,
                "Tot Fwd Pkts": fwd_pkts,
                "Tot Bwd Pkts": bwd_pkts,
                "TotLen Fwd Pkts": fwd_bytes,
                "TotLen Bwd Pkts": bwd_bytes,
                "Fwd Pkt Len Max": fwd_bytes,  # 근사값 (패킷 개별 크기 없으므로)
                "Fwd Pkt Len Min": fwd_pkt_len_mean,
                "Fwd Pkt Len Mean": fwd_pkt_len_mean,
                "Bwd Pkt Len Max": bwd_bytes,
                "Bwd Pkt Len Min": bwd_pkt_len_mean,
                "Bwd Pkt Len Mean": bwd_pkt_len_mean,
                "Flow Byts/s": total_bytes / duration,
                "Flow Pkts/s": total_pkts / duration,
                "Pkt Len Min": min(fwd_pkt_len_mean, bwd_pkt_len_mean) if total_pkts > 0 else 0.0,
                "Pkt Len Max": max(fwd_bytes, bwd_bytes),
                "Pkt Len Mean": pkt_len_mean,
                "Pkt Size Avg": pkt_len_mean,
                "Fwd Seg Size Avg": fwd_pkt_len_mean,
                "Bwd Seg Size Avg": bwd_pkt_len_mean,
                "Subflow Fwd Pkts": fwd_pkts,
                "Subflow Fwd Byts": fwd_bytes,
                "Subflow Bwd Pkts": bwd_pkts,
                "Subflow Bwd Byts": bwd_bytes,
                "Fwd Pkts/s": fwd_pkts / duration,
                "Bwd Pkts/s": bwd_pkts / duration,
                "Down/Up Ratio": bwd_pkts / fwd_pkts if fwd_pkts > 0 else 0.0,
                "Fwd Act Data Pkts": max(0, fwd_pkts - 1),  # SYN 제외 근사
            })
        
        # P1: CDN/클라우드 트래픽 메타데이터 표시
        is_cloud = self._is_cloud_ip(dst_ip) or self._is_cloud_ip(src_ip)

        # HTTP URL에서 path와 query 분리 추출
        from urllib.parse import urlparse, unquote
        http_urls = list(cache["http"])
        http_path_str = ""
        http_query_str = ""
        if http_urls:
            # 여러 URL이 있을 경우 모두 합쳐서 검사 (SQL 인젝션 등 다수 요청 대비)
            all_paths = []
            all_queries = []
            for raw_url in http_urls:
                try:
                    parsed = urlparse(raw_url)
                    if parsed.path:
                        all_paths.append(unquote(parsed.path))
                    if parsed.query:
                        all_queries.append(unquote(parsed.query))
                except Exception:
                    all_paths.append(raw_url)
            http_path_str = " | ".join(all_paths)
            http_query_str = " | ".join(all_queries)

        metadata = {
            "source": "suricata-eve",
            "flow_state": state,
            "flow_reason": reason,
            "packet_count": int(total_pkts),
            "forward_packets": int(fwd_pkts),
            "backward_packets": int(bwd_pkts),
            "total_payload_bytes": int(total_bytes),
            "app_proto": event.get("app_proto", ""),
            "dns_queries": ",".join(cache["dns"]),
            "http_path": http_path_str,
            "http_query": http_query_str if http_query_str else None,
            "http_is_plaintext": bool(cache["http"] or cache.get("http_meta", {}).get("method")),
            "http_host": cache.get("http_meta", {}).get("hostname", ""),
            "http_user_agent": cache.get("http_meta", {}).get("user_agent", ""),
            "tls_sni": cache.get("tls", {}).get("sni", ""),
            "tls_version": cache.get("tls", {}).get("version", ""),
            "tls_ja3": cache.get("tls", {}).get("ja3", ""),
            "http_method": cache.get("http_meta", {}).get("method", ""),
            "http_status": cache.get("http_meta", {}).get("status", 0),
            "dst_is_trusted_service": is_cloud,
            "likely_response_traffic": src_port in (80, 443, 8080, 8443),
        }

        # 메모리 릭 방지: 캐시 10000개 제한
        if len(self._flow_cache) > 10000:
            self._flow_cache.clear()
            
        return FlowRecord(key=key, features=features, metadata=metadata, pre_scaled=False)

    def _empty_features(self) -> dict[str, float]:
        return {name: 0.0 for name in self._feature_names}


def _tcp_flags_from_event(event: dict) -> object:
    tcp = event.get("tcp", {})
    if isinstance(tcp, dict):
        for key in ("tcp_flags", "tcp_flags_ts", "tcp_flags_tc"):
            if key in tcp:
                return tcp[key]
    flow = event.get("flow", {})
    if isinstance(flow, dict):
        return flow.get("tcp_flags", 0)
    return 0
