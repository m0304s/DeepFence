"""Suricata 차단 룰셋 동적 업데이트."""

import subprocess
from pathlib import Path

from deepfence_common.logging import configure_logging
from deepfence_common.config import RuntimeConfig
from .xdp_manager import XDPManager

class SuricataUpdater:
    """ML/정책 엔진이 악성으로 판정한 IP를 Suricata 룰 및 XDP에 등록하여 차단."""
    
    def __init__(self, config: RuntimeConfig):
        self._config = config
        self._logger = configure_logging("deepfence.blocker.suricata")
        self._rules_path = Path("/tmp/suricata_deepfence/deepfence-block.rules")
        self._blocked_ips: dict[str, float] = {}  # IP -> expire timestamp
        
        # XDP 매니저 초기화 (환경 변수 또는 config.py에 설정된 네트워크 인터페이스 기준)
        interface_name = getattr(self._config, "capture_interface", "ens3")
        self._xdp_manager = XDPManager(interface=interface_name)
        
        # 룰 파일 초기화
        self._rules_path.parent.mkdir(parents=True, exist_ok=True)
        if not self._rules_path.exists():
            self._rules_path.touch()

    def block_ip(self, ip: str, reason: str):
        """특정 IP를 Suricata 인라인에서 즉시 차단하도록 룰 추가 후 리로드 및 XDP 하드웨어 차단."""
        import time
        now = time.time()
        
        # 이미 차단되어 있고 TTL 갱신
        if ip in self._blocked_ips:
            self._blocked_ips[ip] = now + self._config.suricata_block_ttl_seconds
            return
            
        self._blocked_ips[ip] = now + self._config.suricata_block_ttl_seconds
        
        # 1. 0초 지연 XDP 하드웨어 차단 (가상화 환경에서 놓칠 수 있음)
        self._xdp_manager.block_ip(ip)
        
        # 2. 리눅스 커널 방화벽(iptables) 연동 (가장 확실한 2중 차단)
        try:
            import os
            os.system(f"sudo iptables -I INPUT -s {ip} -j DROP")
            os.system(f"sudo iptables -I FORWARD -s {ip} -j DROP")
        except Exception as e:
            self._logger.error(f"iptables 차단 실패: {e}")
            
        # 3. 기존 파일 기반 Suricata 룰 업데이트 (백업/로깅용)
        self._rewrite_rules()
        self._logger.info(f"차단 룰 추가 완료 (XDP+Suricata): IP={ip}, Reason={reason}")
        self._reload_suricata()

    def cleanup_expired_rules(self):
        """TTL이 만료된 차단 IP를 룰 및 XDP에서 제거."""
        import time
        now = time.time()
        expired = [ip for ip, expire_at in self._blocked_ips.items() if now > expire_at]
        
        if not expired:
            return
            
        for ip in expired:
            del self._blocked_ips[ip]
            self._xdp_manager.unblock_ip(ip)  # XDP에서도 해제
            
            # iptables 해제
            try:
                import os
                os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")
                os.system(f"sudo iptables -D FORWARD -s {ip} -j DROP")
            except Exception:
                pass
                
            self._logger.info(f"차단 만료 해제 (XDP+iptables+Suricata): IP={ip}")
            
        self._rewrite_rules()
        self._reload_suricata()

    def _rewrite_rules(self):
        """현재 _blocked_ips 목록을 기반으로 룰 파일을 완전히 다시 씀."""
        lines = []
        for i, ip in enumerate(self._blocked_ips.keys()):
            sid = 1000000 + i
            lines.append(f'drop ip {ip} any -> any any (msg:"DeepFence ML Block"; sid:{sid}; rev:1;)\\n')
            lines.append(f'drop ip any any -> {ip} any (msg:"DeepFence ML Block"; sid:{sid+50000}; rev:1;)\\n')
            
        with self._rules_path.open("w", encoding="utf-8") as f:
            f.writelines(lines)

    def _reload_suricata(self):
        """Suricata 프로세스에 USR2 시그널을 보내어 트래픽 중단 없이 룰을 즉시 리로드."""
        try:
            pid_str = subprocess.check_output(["pgrep", "-f", "suricata"]).decode("utf-8").strip()
            if pid_str:
                # pgrep 결과가 여러 줄일 경우, 진짜 줄바꿈 기호(\n)로 잘라서 첫 번째 PID만 가져옵니다.
                first_pid_str = pid_str.split("\n")[0].strip()
                pid = int(first_pid_str)
                subprocess.run(["kill", "-USR2", str(pid)], check=True)
                self._logger.info(f"Suricata 룰 라이브 리로드 완료 (PID: {pid})")
        except subprocess.CalledProcessError:
            self._logger.debug("Suricata 프로세스를 찾을 수 없어 리로드 생략 (프로그램 종료 중일 수 있음)")
        except ValueError as e:
            self._logger.error(f"PID 변환 오류: {pid_str} -> {e}")
        except Exception as e:
            self._logger.error(f"Suricata 리로드 실패: {e}")
