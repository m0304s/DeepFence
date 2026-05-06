"""Shared runtime schemas."""

from dataclasses import dataclass


@dataclass(slots=True)
class FlowKey:
    """Five-tuple flow identifier."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str


@dataclass(slots=True)
class DetectionResult:
    """Normalized detection output shared across services."""

    label: str
    confidence: float
    should_block: bool
