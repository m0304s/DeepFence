"""샘플 패킷 시퀀스 생성."""

from __future__ import annotations

from deepfence_common import PacketEvent, RuntimeConfig, RuntimePaths

from deepfence_sensor.feature_extractor import FeatureExtractor
from deepfence_sensor.flow_table import FlowTable


def build_sample_packets() -> list[PacketEvent]:
    """샘플 패킷 시퀀스 생성."""
    return [
        PacketEvent(
            timestamp=0.0000,
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            src_port=51515,
            dst_port=443,
            protocol="TCP",
            length=74,
            payload_bytes=0,
            header_length=20,
            window_bytes=64240,
            flags=frozenset({"SYN"}),
        ),
        PacketEvent(
            timestamp=0.0100,
            src_ip="198.51.100.20",
            dst_ip="192.0.2.10",
            src_port=443,
            dst_port=51515,
            protocol="TCP",
            length=74,
            payload_bytes=0,
            header_length=20,
            window_bytes=65535,
            flags=frozenset({"SYN", "ACK"}),
        ),
        PacketEvent(
            timestamp=0.0200,
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            src_port=51515,
            dst_port=443,
            protocol="TCP",
            length=66,
            payload_bytes=0,
            header_length=20,
            window_bytes=64240,
            flags=frozenset({"ACK"}),
        ),
        PacketEvent(
            timestamp=0.0400,
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            src_port=51515,
            dst_port=443,
            protocol="TCP",
            length=512,
            payload_bytes=446,
            header_length=20,
            window_bytes=64240,
            flags=frozenset({"PSH", "ACK"}),
        ),
        PacketEvent(
            timestamp=0.0800,
            src_ip="198.51.100.20",
            dst_ip="192.0.2.10",
            src_port=443,
            dst_port=51515,
            protocol="TCP",
            length=620,
            payload_bytes=554,
            header_length=20,
            window_bytes=65535,
            flags=frozenset({"PSH", "ACK"}),
        ),
        PacketEvent(
            timestamp=0.1200,
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            src_port=51515,
            dst_port=443,
            protocol="TCP",
            length=66,
            payload_bytes=0,
            header_length=20,
            window_bytes=64240,
            flags=frozenset({"FIN", "ACK"}),
        ),
        PacketEvent(
            timestamp=0.1300,
            src_ip="198.51.100.20",
            dst_ip="192.0.2.10",
            src_port=443,
            dst_port=51515,
            protocol="TCP",
            length=66,
            payload_bytes=0,
            header_length=20,
            window_bytes=65535,
            flags=frozenset({"FIN", "ACK"}),
        ),
        PacketEvent(
            timestamp=0.1400,
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            src_port=51515,
            dst_port=443,
            protocol="TCP",
            length=54,
            payload_bytes=0,
            header_length=20,
            window_bytes=64240,
            flags=frozenset({"ACK"}),
        ),
    ]


def load_mock_flow(paths: RuntimePaths, config: RuntimeConfig):
    """샘플 패킷 시퀀스로 플로우 1건 생성."""
    table = FlowTable()
    for packet in build_sample_packets():
        table.observe(packet)

    extractor = FeatureExtractor(paths)
    snapshot = table.export_one()
    flow = extractor.extract(snapshot)
    flow.metadata["sample_index"] = config.sample_index
    return flow
