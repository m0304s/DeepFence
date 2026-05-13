"""위협 인텔리전스(TI) 기반 시그니처 룰."""

from __future__ import annotations

from deepfence_common.schemas import FlowRecord
from deepfence_common.signature_types import SignatureMatch, metadata_text, score_for

def evaluate_ti_signatures(
    flow: FlowRecord,
    ti_manager,
    score_map: dict[str, int],
) -> tuple[SignatureMatch, ...]:
    if ti_manager is None:
        return ()

    matches: list[SignatureMatch] = []
    
    # IP 대조
    src_ip = flow.key.src_ip
    dst_ip = flow.key.dst_ip
    
    if ti_manager.is_malicious_ip(src_ip):
        rule_id = "ti-malicious-ip"
        score = score_for(score_map, rule_id)
        if score:
            matches.append(SignatureMatch(rule_id, score, f"src_ip={src_ip}"))
            
    if ti_manager.is_malicious_ip(dst_ip):
        rule_id = "ti-malicious-ip"
        score = score_for(score_map, rule_id)
        if score:
            matches.append(SignatureMatch(rule_id, score, f"dst_ip={dst_ip}"))

    # DNS 도메인 대조
    queries = [item for item in metadata_text(flow, "dns_queries").split(",") if item]
    for query in queries:
        normalized = query.rstrip(".").lower()
        if ti_manager.is_malicious_domain(normalized):
            rule_id = "ti-malicious-domain"
            score = score_for(score_map, rule_id)
            if score:
                matches.append(SignatureMatch(rule_id, score, f"domain={normalized}"))

    return tuple(matches)
