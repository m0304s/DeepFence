"""시그니처 기반 탐지 신호."""

from __future__ import annotations

from dataclasses import dataclass

from deepfence_common.config import RuntimeConfig
from deepfence_common.schemas import FlowRecord


@dataclass(frozen=True, slots=True)
class SignatureMatch:
    """시그니처 규칙 1건 매칭 결과."""

    rule_id: str
    score: int
    reason: str


def _metadata_int(flow: FlowRecord, key: str) -> int:
    value = flow.metadata.get(key, 0)
    return int(value) if isinstance(value, (int, float, bool)) else 0


def evaluate_flow_signatures(
    flow: FlowRecord,
    config: RuntimeConfig,
) -> tuple[SignatureMatch, ...]:
    """플로우 메타데이터 기반 시그니처 규칙 평가."""
    if not config.signature_enabled:
        return ()

    if flow.key.protocol.upper() != "TCP":
        return ()

    score_map = config.signature_rule_scores or {}
    sensitive_ports = {int(port) for port in (config.sensitive_port_scores or {})}
    packet_count = _metadata_int(flow, "packet_count")
    forward_packets = _metadata_int(flow, "forward_packets")
    backward_packets = _metadata_int(flow, "backward_packets")
    total_payload_bytes = _metadata_int(flow, "total_payload_bytes")
    syn_flag_count = _metadata_int(flow, "syn_flag_count")
    rst_flag_count = _metadata_int(flow, "rst_flag_count")

    matches: list[SignatureMatch] = []

    if (
        packet_count > 0
        and
        flow.key.dst_port in sensitive_ports
        and packet_count <= config.signature_probe_max_packets
        and total_payload_bytes <= config.signature_probe_max_payload_bytes
    ):
        score = score_map.get("tcp-sensitive-port-probe", 0)
        if score:
            matches.append(
                SignatureMatch(
                    rule_id="tcp-sensitive-port-probe",
                    score=score,
                    reason=(
                        f"dst_port={flow.key.dst_port},"
                        f"packets={packet_count},payload<={config.signature_probe_max_payload_bytes}"
                    ),
                )
            )

    if (
        packet_count > 0
        and backward_packets == 0
        and forward_packets >= 2
        and syn_flag_count >= 1
    ):
        score = score_map.get("tcp-half-open-probe", 0)
        if score:
            matches.append(
                SignatureMatch(
                    rule_id="tcp-half-open-probe",
                    score=score,
                    reason=f"forward={forward_packets},backward={backward_packets},syn={syn_flag_count}",
                )
            )

    if (
        packet_count > 0
        and rst_flag_count >= 1
        and packet_count <= config.signature_probe_max_packets
        and total_payload_bytes <= config.signature_probe_max_payload_bytes
    ):
        score = score_map.get("tcp-rst-probe", 0)
        if score:
            matches.append(
                SignatureMatch(
                    rule_id="tcp-rst-probe",
                    score=score,
                    reason=f"rst={rst_flag_count},packets={packet_count}",
                )
            )

    return tuple(matches)
