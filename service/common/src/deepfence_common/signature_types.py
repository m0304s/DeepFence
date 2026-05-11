"""시그니처 엔진 공용 타입과 메타데이터 헬퍼."""

from __future__ import annotations

from dataclasses import dataclass

from deepfence_common.schemas import FlowRecord


@dataclass(frozen=True, slots=True)
class SignatureMatch:
    """시그니처 규칙 1건 매칭 결과."""

    rule_id: str
    score: int
    reason: str


def metadata_int(flow: FlowRecord, key: str) -> int:
    value = flow.metadata.get(key, 0)
    return int(value) if isinstance(value, (int, float, bool)) else 0


def metadata_text(flow: FlowRecord, key: str) -> str:
    value = flow.metadata.get(key, "")
    return str(value) if value is not None else ""


def score_for(score_map: dict[str, int], rule_id: str) -> int:
    return int(score_map.get(rule_id, 0))
