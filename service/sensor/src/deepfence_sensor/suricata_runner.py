"""Suricata 서브프로세스 관리 모듈."""

import subprocess
import time
from pathlib import Path

from deepfence_common.config import RuntimeConfig
from deepfence_common.logging import configure_logging

class SuricataRunner:
    def __init__(self, config: RuntimeConfig, log_dir: Path):
        self._config = config
        self._logger = configure_logging("deepfence.suricata")
        self._log_dir = log_dir
        self._process: subprocess.Popen | None = None

    def start(self):
        self._log_dir.mkdir(parents=True, exist_ok=True)
        rules_path = Path("/tmp/suricata_deepfence/deepfence-block.rules")
        if not rules_path.exists():
            rules_path.touch()
        
        
        # Suricata 실행 명령어 구성
        # 상용 장비(Inline)에서는 NFQ (-q 0) 모드를 쓰지만, 
        # 로컬 테스트 환경을 위해 pcap 모드(-i) 사용을 기본으로 함
        cmd = [
            "suricata",
            "-i", self._config.capture_interface,
            "-l", str(self._log_dir),
            "-S", "/tmp/suricata_deepfence/deepfence-block.rules",
            "--set", "outputs.1.eve-log.enabled=yes",
            "--set", "outputs.1.eve-log.filename=eve.json",
            "--set", "outputs.1.eve-log.types.0=flow",
            "--set", "outputs.1.eve-log.types.1=http",
            "--set", "outputs.1.eve-log.types.2=dns",
            "--set", "outputs.1.eve-log.types.3=alert",
            "--set", "outputs.1.eve-log.types.4=tls",
            # Flow Timeout 단축 (기본 TCP=600s, UDP=30s → 실시간 분석용으로 축소)
            "--set", "flow.timeouts.default.new=5",
            "--set", "flow.timeouts.default.established=10",
            "--set", "flow.timeouts.default.closed=0",
            "--set", "flow.timeouts.tcp.new=5",
            "--set", "flow.timeouts.tcp.established=10",
            "--set", "flow.timeouts.tcp.closed=2",
            "--set", "flow.timeouts.udp.new=5",
            "--set", "flow.timeouts.udp.established=5",
        ]
        
        try:
            self._logger.info(f"Suricata 구동: {' '.join(cmd)}")
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self._logger.info("Suricata 서브프로세스가 백그라운드에서 시작되었습니다.")
        except FileNotFoundError:
            self._logger.error("Suricata가 시스템에 설치되어 있지 않습니다. (brew install suricata 필요)")
        except Exception as e:
            self._logger.error(f"Suricata 실행 중 오류 발생: {e}")

    def stop(self):
        if self._process:
            self._logger.info("Suricata 서브프로세스 종료 중...")
            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                self._process.kill()
                self._process.wait(timeout=1)
            self._process = None
            self._logger.info("Suricata가 종료되었습니다.")
