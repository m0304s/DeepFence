"""플로우 메타데이터 기반 시그니처 룰."""

from __future__ import annotations

from deepfence_common.config import RuntimeConfig
from deepfence_common.schemas import FlowRecord
from deepfence_common.signature_types import SignatureMatch, metadata_int, score_for


def evaluate_flow_metadata_signatures(
    flow: FlowRecord,
    config: RuntimeConfig,
    score_map: dict[str, int],
) -> tuple[SignatureMatch, ...]:
    if flow.key.protocol.upper() != "TCP":
        return ()

    sensitive_ports = {int(port) for port in (config.sensitive_port_scores or {})}
    packet_count = metadata_int(flow, "packet_count")
    forward_packets = metadata_int(flow, "forward_packets")
    backward_packets = metadata_int(flow, "backward_packets")
    total_payload_bytes = metadata_int(flow, "total_payload_bytes")
    syn_flag_count = metadata_int(flow, "syn_flag_count")
    rst_flag_count = metadata_int(flow, "rst_flag_count")

    matches: list[SignatureMatch] = []

    if (
        packet_count > 0
        and flow.key.dst_port in sensitive_ports
        and packet_count <= config.signature_probe_max_packets
        and total_payload_bytes <= config.signature_probe_max_payload_bytes
    ):
        rule_id = "tcp-sensitive-port-probe"
        score = score_for(score_map, rule_id)
        if score:
            matches.append(
                SignatureMatch(
                    rule_id=rule_id,
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
        rule_id = "tcp-half-open-probe"
        score = score_for(score_map, rule_id)
        if score:
            matches.append(
                SignatureMatch(
                    rule_id=rule_id,
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
        rule_id = "tcp-rst-probe"
        score = score_for(score_map, rule_id)
        if score:
            matches.append(
                SignatureMatch(
                    rule_id=rule_id,
                    score=score,
                    reason=f"rst={rst_flag_count},packets={packet_count}",
                )
            )

    return tuple(matches)
