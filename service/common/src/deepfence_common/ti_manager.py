"""위협 인텔리전스(TI) 캐싱 및 조회 관리."""

import threading
import time
import urllib.request
import ssl

from deepfence_common.config import RuntimeConfig
from deepfence_common.logging import configure_logging


class ThreatIntelligenceManager:
    """외부 TI 피드를 가져와 캐싱 및 실시간 대조 기능 제공."""

    def __init__(self, config: RuntimeConfig):
        self._config = config
        self._logger = configure_logging("deepfence.ti")
        self._malicious_ips: set[str] = set()
        self._malicious_domains: set[str] = set()
        
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self):
        """TI 업데이트 백그라운드 스레드 시작."""
        if not self._config.ti_enabled:
            self._logger.info("TI 기능이 비활성화되어 있습니다.")
            return
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._update_loop, daemon=True, name="ti-updater")
        self._thread.start()
        self._logger.info("TI 업데이트 데몬 스레드 시작")

    def stop(self):
        """스레드 종료."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _update_loop(self):
        """주기적 업데이트 루프."""
        self._update_feeds()
        while self._running:
            for _ in range(self._config.ti_update_interval_seconds):
                if not self._running:
                    return
                time.sleep(1.0)
            self._update_feeds()

    def _update_feeds(self):
        try:
            self._update_ips()
            self._update_domains()
            self._logger.info(
                "TI 피드 업데이트 완료: IPs=%d, Domains=%d", 
                len(self._malicious_ips), 
                len(self._malicious_domains)
            )
        except Exception as e:
            self._logger.error("TI 피드 업데이트 실패: %s", e)

    def _update_ips(self):
        url = self._config.ti_ip_feed_url
        if not url:
            return
        new_ips = set()
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            for line in response:
                line = line.decode('utf-8', errors='ignore').strip()
                if not line or line.startswith('#'):
                    continue
                new_ips.add(line)
        self._malicious_ips = new_ips

    def _update_domains(self):
        url = self._config.ti_domain_feed_url
        if not url:
            return
        new_domains = set()
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            for line in response:
                line = line.decode('utf-8', errors='ignore').strip()
                if not line or line.startswith('#'):
                    continue
                # URLhaus hostfile format check
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "127.0.0.1":
                    new_domains.add(parts[1].lower())
                else:
                    new_domains.add(line.lower())
        self._malicious_domains = new_domains

    def is_malicious_ip(self, ip: str) -> bool:
        """알려진 악성 IP 여부 확인."""
        if not self._config.ti_enabled:
            return False
        return ip in self._malicious_ips

    def is_malicious_domain(self, domain: str) -> bool:
        """알려진 악성 도메인 여부 확인."""
        if not self._config.ti_enabled:
            return False
        return domain.lower() in self._malicious_domains
