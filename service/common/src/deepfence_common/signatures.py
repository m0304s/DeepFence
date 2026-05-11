"""시그니처 기반 탐지 신호 엔진."""

from __future__ import annotations

from deepfence_common.config import RuntimeConfig
from deepfence_common.schemas import FlowRecord
from deepfence_common.signature_dns import evaluate_dns_signatures
from deepfence_common.signature_flow import evaluate_flow_metadata_signatures
from deepfence_common.signature_http import evaluate_http_signatures
from deepfence_common.signature_tls import evaluate_tls_signatures
from deepfence_common.signature_types import SignatureMatch


def evaluate_flow_signatures(
    flow: FlowRecord,
    config: RuntimeConfig,
) -> tuple[SignatureMatch, ...]:
    """Flow, HTTP, DNS, TLS metadata 시그니처를 통합 평가."""
    if not config.signature_enabled:
        return ()

    score_map = config.signature_rule_scores or {}
    return (
        *evaluate_flow_metadata_signatures(flow, config, score_map),
        *evaluate_http_signatures(flow, score_map),
        *evaluate_dns_signatures(flow, config, score_map),
        *evaluate_tls_signatures(flow, score_map),
    )
