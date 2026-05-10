"""플로우 스냅샷 기반 피처 추출."""

from __future__ import annotations

import json
from ipaddress import ip_address
from pathlib import Path

import numpy as np

from deepfence_common import FlowRecord, RuntimePaths, load_asset_catalog

from deepfence_sensor.flow_table import FlowSnapshot


def _mean(values: list[float]) -> float:
    return float(np.mean(values)) if values else 0.0


def _std(values: list[float]) -> float:
    return float(np.std(values)) if values else 0.0


def _var(values: list[float]) -> float:
    return float(np.var(values)) if values else 0.0


def _max(values: list[float]) -> float:
    return float(max(values)) if values else 0.0


def _min(values: list[float]) -> float:
    return float(min(values)) if values else 0.0


def _diffs(values: list[float]) -> list[float]:
    return [right - left for left, right in zip(values, values[1:], strict=False)]


def _is_private_ip(value: str) -> bool:
    try:
        return ip_address(value).is_private
    except ValueError:
        return False


def _is_likely_server_port(port: int) -> bool:
    return port in {22, 53, 80, 123, 443, 445, 5223, 5228, 8080, 8443}


class FeatureExtractor:
    """플로우 스냅샷을 모델 입력 피처로 변환."""

    def __init__(self, paths: RuntimePaths):
        feature_names_path = paths.processed_dir / "feature_names.json"
        with feature_names_path.open(encoding="utf-8") as file:
            self._feature_names = json.load(file)
        self._asset_catalog = load_asset_catalog(paths.project_root)

    def extract(self, snapshot: FlowSnapshot) -> FlowRecord:
        """플로우 1건에서 피처 벡터 생성."""
        features = {name: 0.0 for name in self._feature_names}

        forward = snapshot.forward_packets
        backward = snapshot.backward_packets
        packets = [*forward, *backward]
        packets.sort(key=lambda packet: packet.timestamp)

        duration = max(snapshot.ended_at - snapshot.started_at, 1e-6)
        all_lengths = [float(packet.length) for packet in packets]
        fwd_lengths = [float(packet.length) for packet in forward]
        bwd_lengths = [float(packet.length) for packet in backward]
        timestamps = [packet.timestamp for packet in packets]
        fwd_timestamps = [packet.timestamp for packet in forward]
        bwd_timestamps = [packet.timestamp for packet in backward]

        flow_iat = _diffs(timestamps)
        fwd_iat = _diffs(fwd_timestamps)
        bwd_iat = _diffs(bwd_timestamps)

        flow_bytes = sum(all_lengths)
        fwd_bytes = sum(fwd_lengths)
        bwd_bytes = sum(bwd_lengths)
        total_packets = len(packets)
        fwd_count = len(forward)
        bwd_count = len(backward)

        flag_counts: dict[str, int] = {
            "FIN": 0,
            "SYN": 0,
            "RST": 0,
            "PSH": 0,
            "ACK": 0,
            "URG": 0,
            "CWE": 0,
            "ECE": 0,
        }
        for packet in packets:
            for flag in packet.flags:
                if flag in flag_counts:
                    flag_counts[flag] += 1

        fwd_psh = sum(1 for packet in forward if "PSH" in packet.flags)
        fwd_urg = sum(1 for packet in forward if "URG" in packet.flags)
        fwd_header_len = sum(packet.header_length for packet in forward)
        bwd_header_len = sum(packet.header_length for packet in backward)
        init_fwd_win = float(forward[0].window_bytes if forward else 0)
        init_bwd_win = float(backward[0].window_bytes if backward else 0)
        fwd_act_data_pkts = sum(1 for packet in forward if packet.payload_bytes > 0)
        fwd_seg_size_min = _min([float(packet.payload_bytes or packet.length) for packet in forward])
        src_asset = self._asset_catalog.get(snapshot.key.src_ip)
        dst_asset = self._asset_catalog.get(snapshot.key.dst_ip)
        src_roles = ",".join(src_asset.roles) if src_asset and src_asset.roles else "-"
        dst_roles = ",".join(dst_asset.roles) if dst_asset and dst_asset.roles else "-"
        dst_is_trusted_service = bool(
            dst_asset
            and snapshot.key.dst_port in dst_asset.trusted_server_ports
        )
        src_is_trusted_service = bool(
            src_asset
            and snapshot.key.src_port in src_asset.trusted_server_ports
        )

        features.update(
            {
                "Dst Port": float(snapshot.key.dst_port),
                "Protocol": 6.0 if snapshot.key.protocol.upper() == "TCP" else 17.0,
                "Flow Duration": duration,
                "Tot Fwd Pkts": float(fwd_count),
                "Tot Bwd Pkts": float(bwd_count),
                "TotLen Fwd Pkts": fwd_bytes,
                "TotLen Bwd Pkts": bwd_bytes,
                "Fwd Pkt Len Max": _max(fwd_lengths),
                "Fwd Pkt Len Min": _min(fwd_lengths),
                "Fwd Pkt Len Mean": _mean(fwd_lengths),
                "Fwd Pkt Len Std": _std(fwd_lengths),
                "Bwd Pkt Len Max": _max(bwd_lengths),
                "Bwd Pkt Len Min": _min(bwd_lengths),
                "Bwd Pkt Len Mean": _mean(bwd_lengths),
                "Bwd Pkt Len Std": _std(bwd_lengths),
                "Flow Byts/s": flow_bytes / duration,
                "Flow Pkts/s": float(total_packets) / duration,
                "Flow IAT Mean": _mean(flow_iat),
                "Flow IAT Std": _std(flow_iat),
                "Flow IAT Max": _max(flow_iat),
                "Flow IAT Min": _min(flow_iat),
                "Fwd IAT Tot": sum(fwd_iat),
                "Fwd IAT Mean": _mean(fwd_iat),
                "Fwd IAT Std": _std(fwd_iat),
                "Fwd IAT Max": _max(fwd_iat),
                "Fwd IAT Min": _min(fwd_iat),
                "Bwd IAT Tot": sum(bwd_iat),
                "Bwd IAT Mean": _mean(bwd_iat),
                "Bwd IAT Std": _std(bwd_iat),
                "Bwd IAT Max": _max(bwd_iat),
                "Bwd IAT Min": _min(bwd_iat),
                "Fwd PSH Flags": float(fwd_psh),
                "Fwd URG Flags": float(fwd_urg),
                "Fwd Header Len": float(fwd_header_len),
                "Bwd Header Len": float(bwd_header_len),
                "Fwd Pkts/s": float(fwd_count) / duration,
                "Bwd Pkts/s": float(bwd_count) / duration,
                "Pkt Len Min": _min(all_lengths),
                "Pkt Len Max": _max(all_lengths),
                "Pkt Len Mean": _mean(all_lengths),
                "Pkt Len Std": _std(all_lengths),
                "Pkt Len Var": _var(all_lengths),
                "FIN Flag Cnt": float(flag_counts["FIN"]),
                "SYN Flag Cnt": float(flag_counts["SYN"]),
                "RST Flag Cnt": float(flag_counts["RST"]),
                "PSH Flag Cnt": float(flag_counts["PSH"]),
                "ACK Flag Cnt": float(flag_counts["ACK"]),
                "URG Flag Cnt": float(flag_counts["URG"]),
                "CWE Flag Count": float(flag_counts["CWE"]),
                "ECE Flag Cnt": float(flag_counts["ECE"]),
                "Down/Up Ratio": float(bwd_count / fwd_count) if fwd_count else 0.0,
                "Pkt Size Avg": _mean(all_lengths),
                "Fwd Seg Size Avg": _mean(fwd_lengths),
                "Bwd Seg Size Avg": _mean(bwd_lengths),
                "Subflow Fwd Pkts": float(fwd_count),
                "Subflow Fwd Byts": fwd_bytes,
                "Subflow Bwd Pkts": float(bwd_count),
                "Subflow Bwd Byts": bwd_bytes,
                "Init Fwd Win Byts": init_fwd_win,
                "Init Bwd Win Byts": init_bwd_win,
                "Fwd Act Data Pkts": float(fwd_act_data_pkts),
                "Fwd Seg Size Min": fwd_seg_size_min,
                "Active Mean": duration,
                "Active Std": 0.0,
                "Active Max": duration,
                "Active Min": duration,
                "Idle Mean": 0.0,
                "Idle Std": 0.0,
                "Idle Max": 0.0,
                "Idle Min": 0.0,
            }
        )

        return FlowRecord(
            key=snapshot.key,
            features=features,
            metadata={
                "source": "샘플-패킷-시퀀스",
                "packet_count": total_packets,
                "forward_packets": fwd_count,
                "backward_packets": bwd_count,
                "src_asset_roles": src_roles,
                "dst_asset_roles": dst_roles,
                "src_is_trusted_service": src_is_trusted_service,
                "dst_is_trusted_service": dst_is_trusted_service,
                "src_is_private": _is_private_ip(snapshot.key.src_ip),
                "dst_is_private": _is_private_ip(snapshot.key.dst_ip),
                "src_is_likely_server_port": _is_likely_server_port(snapshot.key.src_port),
                "dst_is_likely_server_port": _is_likely_server_port(snapshot.key.dst_port),
                "likely_response_traffic": (
                    not _is_private_ip(snapshot.key.src_ip)
                    and _is_private_ip(snapshot.key.dst_ip)
                    and _is_likely_server_port(snapshot.key.src_port)
                    and snapshot.key.dst_port >= 49152
                ),
                "likely_outbound_client_traffic": (
                    _is_private_ip(snapshot.key.src_ip)
                    and not _is_private_ip(snapshot.key.dst_ip)
                    and _is_likely_server_port(snapshot.key.dst_port)
                ),
            },
            pre_scaled=False,
        )
