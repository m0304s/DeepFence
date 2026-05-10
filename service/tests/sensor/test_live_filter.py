from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT / "service" / "common" / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "service" / "sensor" / "src"))

from deepfence_common import FlowKey, PacketEvent, RuntimeConfig
from deepfence_sensor.flow_table import FlowSnapshot
from deepfence_sensor.main import _skip_reason_for_live_snapshot


def _packet(
    *,
    timestamp: float,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: frozenset[str],
) -> PacketEvent:
    return PacketEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="TCP",
        length=60,
        payload_bytes=0,
        flags=flags,
    )


class LiveFilterTest(unittest.TestCase):
    def test_sensitive_port_probe_bypasses_too_few_packets(self) -> None:
        snapshot = FlowSnapshot(
            key=FlowKey(
                src_ip="192.168.0.12",
                dst_ip="192.168.0.1",
                src_port=50000,
                dst_port=22,
                protocol="TCP",
            ),
            started_at=0.0,
            ended_at=1.0,
            forward_packets=[
                _packet(
                    timestamp=0.0,
                    src_ip="192.168.0.12",
                    dst_ip="192.168.0.1",
                    src_port=50000,
                    dst_port=22,
                    flags=frozenset({"SYN"}),
                ),
                _packet(
                    timestamp=0.2,
                    src_ip="192.168.0.12",
                    dst_ip="192.168.0.1",
                    src_port=50000,
                    dst_port=22,
                    flags=frozenset({"ACK"}),
                ),
            ],
            backward_packets=[],
        )

        config = RuntimeConfig(sensitive_port_scores={"22": 20})

        self.assertIsNone(_skip_reason_for_live_snapshot(snapshot, config))

    def test_non_sensitive_short_tcp_still_skipped(self) -> None:
        snapshot = FlowSnapshot(
            key=FlowKey(
                src_ip="192.168.0.12",
                dst_ip="203.0.113.20",
                src_port=50001,
                dst_port=443,
                protocol="TCP",
            ),
            started_at=0.0,
            ended_at=1.0,
            forward_packets=[
                _packet(
                    timestamp=0.0,
                    src_ip="192.168.0.12",
                    dst_ip="203.0.113.20",
                    src_port=50001,
                    dst_port=443,
                    flags=frozenset({"SYN"}),
                ),
                _packet(
                    timestamp=0.2,
                    src_ip="192.168.0.12",
                    dst_ip="203.0.113.20",
                    src_port=50001,
                    dst_port=443,
                    flags=frozenset({"ACK"}),
                ),
            ],
            backward_packets=[],
        )

        config = RuntimeConfig(sensitive_port_scores={"22": 20})

        self.assertEqual(_skip_reason_for_live_snapshot(snapshot, config), "too-few-packets")


if __name__ == "__main__":
    unittest.main()
