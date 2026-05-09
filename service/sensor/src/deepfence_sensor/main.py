"""센서 진입점."""

from deepfence_common import RuntimeConfig, RuntimePaths
from deepfence_common.logging import configure_logging

from deepfence_sensor.feature_extractor import FeatureExtractor
from deepfence_sensor.flow_table import FlowTable
from deepfence_sensor.live_source import capture_live_packets, current_timestamp
from deepfence_sensor.mock_source import load_mock_flow


def _skip_reason_for_live_snapshot(snapshot) -> str | None:
    """실시간 추론에서 제외할 플로우 사유."""
    total_packets = len(snapshot.forward_packets) + len(snapshot.backward_packets)
    if total_packets < 3:
        return "too-few-packets"

    if snapshot.key.protocol.upper() == "TCP":
        forward_flags = set().union(*(packet.flags for packet in snapshot.forward_packets), frozenset())
        backward_flags = set().union(*(packet.flags for packet in snapshot.backward_packets), frozenset())
        all_packets = [*snapshot.forward_packets, *snapshot.backward_packets]

        # 이미 데이터가 오갔거나 연결 종료 플래그가 있으면 성립된 세션으로 본다.
        if any(packet.payload_bytes > 0 for packet in all_packets):
            return None
        if "FIN" in forward_flags or "FIN" in backward_flags or "RST" in forward_flags or "RST" in backward_flags:
            return None

        # 정방향 SYN, 역방향 SYN/ACK, 정방향 ACK가 모두 있으면 정상 3-way handshake로 본다.
        handshake_complete = (
            "SYN" in forward_flags
            and "SYN" in backward_flags
            and "ACK" in backward_flags
            and "ACK" in forward_flags
        )
        if handshake_complete:
            return None

        # 캡처 시점이 중간이더라도 양방향 ACK가 충분하면 이미 성립된 연결로 본다.
        ack_bidirectional = "ACK" in forward_flags and "ACK" in backward_flags
        if ack_bidirectional and total_packets >= 4:
            return None

        return "incomplete-tcp-session"

    return None


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
        skip_reason = _skip_reason_for_live_snapshot(snapshot)
        if skip_reason is not None:
            logger.info(
                "플로우 제외: reason=%s %s:%s -> %s:%s proto=%s packets=%s",
                skip_reason,
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
        skip_reason = _skip_reason_for_live_snapshot(snapshot)
        if skip_reason is not None:
            logger.info(
                "종료 시 플로우 제외: reason=%s %s:%s -> %s:%s proto=%s packets=%s",
                skip_reason,
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
