"""센서 진입점."""

from deepfence_common import RuntimeConfig, RuntimePaths
from deepfence_common.logging import configure_logging

from deepfence_sensor.feature_extractor import FeatureExtractor
from deepfence_sensor.flow_table import FlowTable
from deepfence_sensor.live_source import capture_live_packets, current_timestamp
from deepfence_sensor.mock_source import load_mock_flow


def _should_skip_live_snapshot(snapshot) -> bool:
    """실시간 추론에서 제외할 짧은 플로우 판별."""
    total_packets = len(snapshot.forward_packets) + len(snapshot.backward_packets)
    if total_packets < 3:
        return True

    if snapshot.key.protocol.upper() == "TCP":
        forward_flags = set().union(*(packet.flags for packet in snapshot.forward_packets))
        backward_flags = set().union(*(packet.flags for packet in snapshot.backward_packets))
        handshake_complete = "SYN" in forward_flags and "SYN" in backward_flags and "ACK" in forward_flags
        if not handshake_complete:
            return True

    return False


def _build_live_flow(snapshot, extractor: FeatureExtractor, config: RuntimeConfig):
    """실시간 스냅샷을 FlowRecord로 변환."""
    flow = extractor.extract(snapshot)
    flow.metadata["source"] = "실시간-패킷-수집"
    flow.metadata["capture_interface"] = config.capture_interface
    return flow


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
    logger = configure_logging("deepfence.sensor")
    for packet in capture_live_packets(config):
        table.observe(packet)

    snapshots = table.export_expired(
        current_time=current_timestamp(),
        idle_timeout_seconds=config.flow_idle_timeout_seconds,
    )

    flows = []
    for snapshot in snapshots:
        if _should_skip_live_snapshot(snapshot):
            logger.info(
                "짧은 플로우 제외: %s:%s -> %s:%s proto=%s packets=%s",
                snapshot.key.src_ip,
                snapshot.key.src_port,
                snapshot.key.dst_ip,
                snapshot.key.dst_port,
                snapshot.key.protocol,
                len(snapshot.forward_packets) + len(snapshot.backward_packets),
            )
            continue
        flows.append(_build_live_flow(snapshot, extractor, config))
    return flows


def flush_live_flows(table: FlowTable, extractor: FeatureExtractor, config: RuntimeConfig):
    """남아 있는 플로우 전체 반환."""
    logger = configure_logging("deepfence.sensor")
    flows = []
    for snapshot in table.export_all():
        if _should_skip_live_snapshot(snapshot):
            logger.info(
                "종료 시 짧은 플로우 제외: %s:%s -> %s:%s proto=%s packets=%s",
                snapshot.key.src_ip,
                snapshot.key.src_port,
                snapshot.key.dst_ip,
                snapshot.key.dst_port,
                snapshot.key.protocol,
                len(snapshot.forward_packets) + len(snapshot.backward_packets),
            )
            continue
        flows.append(_build_live_flow(snapshot, extractor, config))
    return flows


def main() -> None:
    """센서 런타임 시작."""
    logger = configure_logging("deepfence.sensor")
    logger.info("센서 런타임 시작")
