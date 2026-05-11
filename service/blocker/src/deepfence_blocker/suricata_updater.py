"""Suricata 차단 룰셋 동적 업데이트."""

import subprocess
from pathlib import Path

from deepfence_common.logging import configure_logging
from deepfence_common.config import RuntimeConfig

class SuricataUpdater:
    """ML/정책 엔진이 악성으로 판정한 IP를 Suricata 룰에 등록하고 라이브 리로드 수행."""
    
    def __init__(self, config: RuntimeConfig):
        self._config = config
        self._logger = configure_logging("deepfence.blocker.suricata")
        self._rules_path = Path("/tmp/suricata_deepfence/deepfence-block.rules")
        self._blocked_ips = set()
        
        # 룰 파일 초기화
        self._rules_path.parent.mkdir(parents=True, exist_ok=True)
        if not self._rules_path.exists():
            self._rules_path.touch()

    def block_ip(self, ip: str, reason: str):
        """특정 IP를 Suricata 인라인에서 즉시 차단하도록 룰 추가 후 리로드."""
        if ip in self._blocked_ips:
            return
            
        self._blocked_ips.add(ip)
        
        sid = 1000000 + len(self._blocked_ips)
        # 패킷을 드롭하는 인라인 차단 룰 생성
        rule_in = f'drop ip {ip} any -> any any (msg:"DeepFence ML Block - {reason}"; sid:{sid}; rev:1;)\n'
        rule_out = f'drop ip any any -> {ip} any (msg:"DeepFence ML Block - {reason}"; sid:{sid+50000}; rev:1;)\n'
        
        with self._rules_path.open("a", encoding="utf-8") as f:
            f.write(rule_in)
            f.write(rule_out)
            
        self._logger.info(f"Suricata 차단 룰 추가 완료: IP={ip}, Reason={reason}")
        self._reload_suricata()

    def _reload_suricata(self):
        """Suricata 프로세스에 USR2 시그널을 보내어 트래픽 중단 없이 룰을 즉시 리로드."""
        try:
            pid_str = subprocess.check_output(["pgrep", "-f", "suricata"]).decode("utf-8").strip()
            if pid_str:
                pid = int(pid_str.split("\\n")[0])
                subprocess.run(["kill", "-USR2", str(pid)], check=True)
                self._logger.info(f"Suricata 룰 라이브 리로드 완료 (PID: {pid})")
        except Exception as e:
            self._logger.error(f"Suricata 리로드 실패: {e}")
