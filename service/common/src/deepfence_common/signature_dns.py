"""DNS 질의 기반 시그니처 룰."""

from __future__ import annotations

from math import log2

from deepfence_common.config import RuntimeConfig
from deepfence_common.schemas import FlowRecord
from deepfence_common.signature_types import SignatureMatch, metadata_text, score_for


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    length = len(value)
    return -sum((count / length) * log2(count / length) for count in counts.values())


def evaluate_dns_signatures(
    flow: FlowRecord,
    config: RuntimeConfig,
    score_map: dict[str, int],
) -> tuple[SignatureMatch, ...]:
    queries = [item for item in metadata_text(flow, "dns_queries").split(",") if item]
    if not queries:
        return ()

    query_types = {item for item in metadata_text(flow, "dns_query_types").split(",") if item}
    matches: list[SignatureMatch] = []

    for query in queries:
        normalized = query.rstrip(".").lower()
        compact = normalized.replace(".", "")

        if len(normalized) >= config.signature_dns_long_query_chars:
            rule_id = "dns-long-query"
            score = score_for(score_map, rule_id)
            if score:
                matches.append(SignatureMatch(rule_id, score, f"len={len(normalized)}"))

        if "16" in query_types and len(normalized) >= config.signature_dns_txt_min_chars:
            rule_id = "dns-suspicious-txt-query"
            score = score_for(score_map, rule_id)
            if score:
                matches.append(SignatureMatch(rule_id, score, f"type=TXT,len={len(normalized)}"))

        if (
            len(compact) >= config.signature_dns_entropy_min_chars
            and _entropy(compact) >= config.signature_dns_entropy_threshold
        ):
            rule_id = "dns-high-entropy-query"
            score = score_for(score_map, rule_id)
            if score:
                matches.append(
                    SignatureMatch(rule_id, score, f"entropy={_entropy(compact):.2f},len={len(compact)}")
                )

    return tuple(matches)
