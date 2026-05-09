"""패킷 이벤트 기반 플로우 집계."""

from __future__ import annotations

from dataclasses import dataclass, field

from deepfence_common import FlowKey, PacketEvent


@dataclass(slots=True)
class FlowSnapshot:
    """피처 추출 직전 플로우 스냅샷."""

    key: FlowKey
    started_at: float
    ended_at: float
    forward_packets: list[PacketEvent] = field(default_factory=list)
    backward_packets: list[PacketEvent] = field(default_factory=list)


def _canonical_id(packet: PacketEvent) -> tuple[tuple[str, int], tuple[str, int], str]:
    left = (packet.src_ip, packet.src_port)
    right = (packet.dst_ip, packet.dst_port)
    if left <= right:
        return left, right, packet.protocol
    return right, left, packet.protocol


class FlowTable:
    """패킷을 양방향 플로우로 집계."""

    def __init__(self) -> None:
        self._flows: dict[tuple[tuple[str, int], tuple[str, int], str], FlowSnapshot] = {}

    def observe(self, packet: PacketEvent) -> None:
        """패킷 1건 반영."""
        flow_id = _canonical_id(packet)
        snapshot = self._flows.get(flow_id)

        if snapshot is None:
            snapshot = FlowSnapshot(
                key=FlowKey(
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                ),
                started_at=packet.timestamp,
                ended_at=packet.timestamp,
            )
            self._flows[flow_id] = snapshot

        snapshot.ended_at = packet.timestamp
        if (
            packet.src_ip == snapshot.key.src_ip
            and packet.dst_ip == snapshot.key.dst_ip
            and packet.src_port == snapshot.key.src_port
            and packet.dst_port == snapshot.key.dst_port
        ):
            snapshot.forward_packets.append(packet)
        else:
            snapshot.backward_packets.append(packet)

    def export_one(self) -> FlowSnapshot:
        """집계된 플로우 1건 반환."""
        if not self._flows:
            raise ValueError("집계된 플로우가 없습니다.")
        return next(iter(self._flows.values()))

    def export_expired(self, current_time: float, idle_timeout_seconds: float) -> list[FlowSnapshot]:
        """유휴 타임아웃 기준으로 종료된 플로우 반환."""
        expired_ids = [
            flow_id
            for flow_id, snapshot in self._flows.items()
            if current_time - snapshot.ended_at >= idle_timeout_seconds
        ]

        snapshots: list[FlowSnapshot] = []
        for flow_id in expired_ids:
            snapshots.append(self._flows.pop(flow_id))
        return snapshots

    def export_all(self) -> list[FlowSnapshot]:
        """현재 집계된 플로우 전체 반환."""
        snapshots = list(self._flows.values())
        self._flows.clear()
        return snapshots
