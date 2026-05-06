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
    block_confidence_threshold: float = 0.80
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
        self.block_confidence_threshold = _get_float_env(
            "BLOCK_CONFIDENCE_THRESHOLD",
            self.block_confidence_threshold,
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
        if (base / "data" / "processed").exists() and (base / "training" / "artifacts").exists():
            return base
    raise FileNotFoundError("프로젝트 루트 탐색 실패")


def build_runtime_paths(project_root: Path) -> RuntimePaths:
    """런타임 경로 구성."""
    return RuntimePaths(
        project_root=project_root,
        processed_dir=project_root / "data" / "processed",
        model_dir=project_root / "training" / "artifacts" / "models",
    )
