"""런타임 공용 설정."""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class RuntimePaths:
    """런타임 공용 경로."""

    project_root: Path
    processed_dir: Path
    model_dir: Path


@dataclass(slots=True)
class RuntimeConfig:
    """최소 런타임 설정."""

    label_allowlist: tuple[str, ...] = ("Benign",)
    whitelist_ips: tuple[str, ...] = ()
    block_confidence_threshold: float = 0.80
    label_block_thresholds: dict[str, float] | None = None
    label_risk_scores: dict[str, int] | None = None
    sensitive_port_scores: dict[str, int] | None = None
    action_thresholds: dict[str, int] | None = None
    min_block_observations: int = 2
    repeat_observation_score: int = 15
    skip_private_peer_blocking: bool = True
    suspicious_attack_labels: tuple[str, ...] = (
        "Infiltration",
        "Brute Force",
        "SQL Injection",
        "DoS",
        "DDoS",
        "Bot",
    )
    suspicious_secondary_threshold: float = 0.25
    suspicious_gap_threshold: float = 0.20
    suspicious_score: int = 25
    default_model_name: str = "best_model_v6_catboost.cbm"
    sample_index: int = 0
    detect_only: bool = True
    capture_interface: str = "Wi-Fi"
    capture_packet_count: int = 12
    capture_timeout_seconds: int = 10
    flow_idle_timeout_seconds: int = 15
    loop_sleep_seconds: float = 1.0

    def __post_init__(self) -> None:
        """환경 변수로 런타임 설정 덮어쓰기."""
        self.label_allowlist = _get_tuple_env("LABEL_ALLOWLIST", self.label_allowlist)
        self.whitelist_ips = _get_tuple_env("WHITELIST_IPS", self.whitelist_ips)
        self.block_confidence_threshold = _get_float_env(
            "BLOCK_CONFIDENCE_THRESHOLD",
            self.block_confidence_threshold,
        )
        self.label_block_thresholds = _get_mapping_env(
            "LABEL_BLOCK_THRESHOLDS",
            self.label_block_thresholds or {},
        )
        self.label_risk_scores = _get_int_mapping_env(
            "LABEL_RISK_SCORES",
            self.label_risk_scores
            or {
                "Infiltration": 60,
                "SQL Injection": 70,
                "Brute Force": 55,
                "DoS": 50,
                "DDoS": 65,
                "Bot": 45,
            },
        )
        self.sensitive_port_scores = _get_int_mapping_env(
            "SENSITIVE_PORT_SCORES",
            self.sensitive_port_scores
            or {
                "22": 20,
                "53": 10,
                "445": 25,
                "3389": 30,
            },
        )
        self.action_thresholds = _get_int_mapping_env(
            "ACTION_THRESHOLDS",
            self.action_thresholds
            or {
                "suspicious": 25,
                "alert": 50,
                "block_candidate": 80,
                "block": 100,
            },
        )
        self.min_block_observations = _get_int_env(
            "MIN_BLOCK_OBSERVATIONS",
            self.min_block_observations,
        )
        self.repeat_observation_score = _get_int_env(
            "REPEAT_OBSERVATION_SCORE",
            self.repeat_observation_score,
        )
        self.skip_private_peer_blocking = _get_bool_env(
            "SKIP_PRIVATE_PEER_BLOCKING",
            self.skip_private_peer_blocking,
        )
        self.suspicious_attack_labels = _get_tuple_env(
            "SUSPICIOUS_ATTACK_LABELS",
            self.suspicious_attack_labels,
        )
        self.suspicious_secondary_threshold = _get_float_env(
            "SUSPICIOUS_SECONDARY_THRESHOLD",
            self.suspicious_secondary_threshold,
        )
        self.suspicious_gap_threshold = _get_float_env(
            "SUSPICIOUS_GAP_THRESHOLD",
            self.suspicious_gap_threshold,
        )
        self.suspicious_score = _get_int_env(
            "SUSPICIOUS_SCORE",
            self.suspicious_score,
        )
        self.default_model_name = os.getenv("DEFAULT_MODEL_NAME", self.default_model_name)
        self.sample_index = _get_int_env("SAMPLE_INDEX", self.sample_index)
        self.detect_only = _get_bool_env("DETECT_ONLY", self.detect_only)
        self.capture_interface = os.getenv("CAPTURE_INTERFACE", self.capture_interface)
        self.capture_packet_count = _get_int_env("CAPTURE_PACKET_COUNT", self.capture_packet_count)
        self.capture_timeout_seconds = _get_int_env(
            "CAPTURE_TIMEOUT_SECONDS",
            self.capture_timeout_seconds,
        )
        self.flow_idle_timeout_seconds = _get_int_env(
            "FLOW_IDLE_TIMEOUT_SECONDS",
            self.flow_idle_timeout_seconds,
        )
        self.loop_sleep_seconds = _get_float_env(
            "LOOP_SLEEP_SECONDS",
            self.loop_sleep_seconds,
        )


def _get_int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value is not None else default


def _get_float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    return float(value) if value is not None else default


def _get_bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_tuple_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = os.getenv(name)
    if value is None:
        return default
    items = [item.strip() for item in value.split(",")]
    return tuple(item for item in items if item)


def _get_mapping_env(name: str, default: dict[str, float]) -> dict[str, float]:
    value = os.getenv(name)
    if value is None:
        return default

    mapping: dict[str, float] = {}
    for item in value.split(","):
        item = item.strip()
        if not item or "=" not in item:
            continue
        key, raw_value = item.split("=", 1)
        mapping[key.strip()] = float(raw_value.strip())
    return mapping


def _get_int_mapping_env(name: str, default: dict[str, int]) -> dict[str, int]:
    value = os.getenv(name)
    if value is None:
        return default

    mapping: dict[str, int] = {}
    for item in value.split(","):
        item = item.strip()
        if not item or "=" not in item:
            continue
        key, raw_value = item.split("=", 1)
        mapping[key.strip()] = int(raw_value.strip())
    return mapping


def load_env_file(env_path: Path) -> None:
    """간단한 KEY=VALUE 형식의 .env 파일 로드."""
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def load_default_env(project_root: Path) -> None:
    """기본 서비스 .env 파일 로드."""
    load_env_file(project_root / "service" / "configs" / ".env")


def find_project_root(start: Path | None = None) -> Path:
    """프로젝트 루트 탐색."""
    start_path = (start or Path.cwd()).resolve()
    candidates = [start_path, *start_path.parents]
    for base in candidates:
        if (base / "training" / "artifacts").exists() and (base / "training" / "data").exists():
            return base
    raise FileNotFoundError("프로젝트 루트 탐색 실패")


def build_runtime_paths(project_root: Path) -> RuntimePaths:
    """런타임 경로 구성."""
    return RuntimePaths(
        project_root=project_root,
        processed_dir=project_root / "training" / "data" / "processed",
        model_dir=project_root / "training" / "artifacts" / "models",
    )
