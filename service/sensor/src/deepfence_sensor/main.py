"""센서 진입점 (Suricata 기반 분산형 아키텍처)."""

import time
from pathlib import Path

from deepfence_common import RuntimeConfig, RuntimePaths, log_context
from deepfence_common.logging import configure_logging

from deepfence_sensor.suricata_runner import SuricataRunner
from deepfence_sensor.suricata_source import SuricataTailer
from deepfence_sensor.mock_source import load_mock_flow


def emit_sample_flow(paths: RuntimePaths, config: RuntimeConfig):
    """샘플 플로우 1건 생성."""
    logger = configure_logging("deepfence.sensor")
    flow = load_mock_flow(paths, config)
    logger.info("샘플 플로우 생성: %s -> %s", flow.key.src_ip, flow.key.dst_ip)
    return flow


def build_live_runtime(paths: RuntimePaths, config: RuntimeConfig):
    """상시 수집형 센서 구성 (Suricata 서브프로세스 및 꼬리읽기)."""
    log_dir = Path("/tmp/suricata_deepfence")
    runner = SuricataRunner(config, log_dir)
    tailer = SuricataTailer(log_dir, paths)
    
    # 여기서 프로세스를 시작하지만 외부 관리자가 통제할 수도 있음.
    runner.start()
    time.sleep(2)  # Suricata 초기화 대기
    return runner, tailer


def collect_live_flows(tailer: SuricataTailer, config: RuntimeConfig):
    """실시간 Suricata 이벤트 파싱 후 플로우 반환."""
    # 비동기로 쌓인 이벤트를 한번에 읽어들임.
    flows = list(tailer.tail())
    return flows


def flush_live_flows(tailer: SuricataTailer, config: RuntimeConfig):
    """남아 있는 플로우 반환."""
    return collect_live_flows(tailer, config)


def main() -> None:
    """센서 런타임 시작."""
    logger = configure_logging("deepfence.sensor")
    logger.info("센서 런타임 시작 (Suricata Mode)")
