"""시간축 행위 기반 탐지 신호."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from time import time

from deepfence_common import DetectionResult, RuntimeConfig


@dataclass(frozen=True, slots=True)
class BehaviorMatch:
    rule_id: str
    score: int
    reason: str


@dataclass(frozen=True, slots=True)
class _Observation:
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int


class BehaviorTracker:
    """최근 플로우들의 포트 스캔과 fan-out 패턴을 추적."""

    def __init__(self, config: RuntimeConfig):
        self._config = config
        self._observations: deque[_Observation] = deque()

    def evaluate(self, result: DetectionResult) -> tuple[BehaviorMatch, ...]:
        if not self._config.behavior_enabled:
            return ()

        timestamp = _timestamp_for(result)
        self._observations.append(
            _Observation(
                timestamp=timestamp,
                src_ip=result.flow.key.src_ip,
                dst_ip=result.flow.key.dst_ip,
                dst_port=result.flow.key.dst_port,
            )
        )
        self._expire(timestamp)

        matches: list[BehaviorMatch] = []
        port_count = self._unique_ports_for(result.flow.key.src_ip, result.flow.key.dst_ip)
        if port_count >= self._config.behavior_port_scan_min_ports:
            matches.append(
                BehaviorMatch(
                    rule_id="behavior-port-scan",
                    score=self._config.behavior_port_scan_score,
                    reason=f"dst={result.flow.key.dst_ip},ports={port_count},window={self._config.behavior_window_seconds}s",
                )
            )

        host_count = self._unique_hosts_for(result.flow.key.src_ip, result.flow.key.dst_port)
        if (
            host_count >= self._config.behavior_fanout_min_hosts
            and result.flow.key.dst_port not in self._config.behavior_fanout_exempt_ports
        ):
            matches.append(
                BehaviorMatch(
                    rule_id="behavior-fanout",
                    score=self._config.behavior_fanout_score,
                    reason=f"dst_port={result.flow.key.dst_port},hosts={host_count},window={self._config.behavior_window_seconds}s",
                )
            )

        return tuple(matches)

    def _expire(self, timestamp: float) -> None:
        boundary = timestamp - self._config.behavior_window_seconds
        while self._observations and self._observations[0].timestamp < boundary:
            self._observations.popleft()

    def _unique_ports_for(self, src_ip: str, dst_ip: str) -> int:
        return len(
            {
                observation.dst_port
                for observation in self._observations
                if observation.src_ip == src_ip and observation.dst_ip == dst_ip
            }
        )

    def _unique_hosts_for(self, src_ip: str, dst_port: int) -> int:
        return len(
            {
                observation.dst_ip
                for observation in self._observations
                if observation.src_ip == src_ip and observation.dst_port == dst_port
            }
        )


def _timestamp_for(result: DetectionResult) -> float:
    value = result.flow.metadata.get("flow_ended_at")
    if isinstance(value, (int, float)):
        return float(value)
    return time()
