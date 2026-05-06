"""센서 진입점."""

from deepfence_common import RuntimeConfig, RuntimePaths
from deepfence_common.logging import configure_logging

from deepfence_sensor.feature_extractor import FeatureExtractor
from deepfence_sensor.flow_table import FlowTable
from deepfence_sensor.live_source import capture_live_packets, current_timestamp
from deepfence_sensor.mock_source import load_mock_flow


def emit_sample_flow(paths: RuntimePaths, config: RuntimeConfig):
    """샘플 플로우 1건 생성."""
    logger = configure_logging("deepfence.sensor")
    flow = load_mock_flow(paths, config)
    logger.info("샘플 플로우 생성: %s -> %s", flow.key.src_ip, flow.key.dst_ip)
    return flow


def capture_live_flow(paths: RuntimePaths, config: RuntimeConfig):
    """실시간 패킷으로 플로우 1건 생성."""
    logger = configure_logging("deepfence.sensor")
    table = FlowTable()

    for packet in capture_live_packets(config):
        table.observe(packet)

    snapshot = table.export_one()
    extractor = FeatureExtractor(paths)
    flow = extractor.extract(snapshot)
    flow.metadata["source"] = "실시간-패킷-수집"
    flow.metadata["capture_interface"] = config.capture_interface
    logger.info(
        "실시간 플로우 생성: %s -> %s (%s)",
        flow.key.src_ip,
        flow.key.dst_ip,
        config.capture_interface,
    )
    return flow


def build_live_runtime(paths: RuntimePaths):
    """상시 수집형 센서 구성."""
    return FlowTable(), FeatureExtractor(paths)


def collect_live_flows(table: FlowTable, extractor: FeatureExtractor, config: RuntimeConfig):
    """실시간 패킷 묶음 수집 후 종료된 플로우 반환."""
    for packet in capture_live_packets(config):
        table.observe(packet)

    snapshots = table.export_expired(
        current_time=current_timestamp(),
        idle_timeout_seconds=config.flow_idle_timeout_seconds,
    )
    return [extractor.extract(snapshot) for snapshot in snapshots]


def flush_live_flows(table: FlowTable, extractor: FeatureExtractor):
    """남아 있는 플로우 전체 반환."""
    return [extractor.extract(snapshot) for snapshot in table.export_all()]


def main() -> None:
    """센서 런타임 시작."""
    logger = configure_logging("deepfence.sensor")
    logger.info("센서 런타임 시작")
