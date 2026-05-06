"""런타임 공용 스키마."""

from dataclasses import dataclass, field


@dataclass(slots=True)
class PacketEvent:
    """패킷 이벤트 1건."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    payload_bytes: int = 0
    header_length: int = 20
    window_bytes: int = 0
    flags: frozenset[str] = field(default_factory=frozenset)


@dataclass(slots=True)
class FlowKey:
    """5-튜플 플로우 식별자."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str


@dataclass(slots=True)
class FlowRecord:
    """센서 출력용 최소 플로우 데이터."""

    key: FlowKey
    features: dict[str, float]
    metadata: dict[str, str | int | float | bool] = field(default_factory=dict)
    pre_scaled: bool = False


@dataclass(slots=True)
class DetectionResult:
    """서비스 공용 탐지 결과."""

    label: str
    confidence: float
    should_block: bool
    flow: FlowRecord
    probabilities: dict[str, float] = field(default_factory=dict)
