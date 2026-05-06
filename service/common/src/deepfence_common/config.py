"""런타임 공용 설정."""

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
