"""센서 진입점."""

from deepfence_common import RuntimeConfig, RuntimePaths
from deepfence_common.logging import configure_logging

from deepfence_sensor.mock_source import load_mock_flow


def emit_sample_flow(paths: RuntimePaths, config: RuntimeConfig):
    """샘플 플로우 1건 생성."""
    logger = configure_logging("deepfence.sensor")
    flow = load_mock_flow(paths, config)
    logger.info("샘플 플로우 생성: %s -> %s", flow.key.src_ip, flow.key.dst_ip)
    return flow


def main() -> None:
    """센서 런타임 시작."""
    logger = configure_logging("deepfence.sensor")
    logger.info("센서 런타임 시작")
