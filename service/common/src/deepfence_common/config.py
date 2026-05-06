"""Common runtime configuration models."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class RuntimePaths:
    """Canonical project paths used by runtime services."""

    project_root: Path
    processed_dir: Path
    model_dir: Path


def build_runtime_paths(project_root: Path) -> RuntimePaths:
    """Create canonical path bindings for the runtime."""
    return RuntimePaths(
        project_root=project_root,
        processed_dir=project_root / "data" / "processed",
        model_dir=project_root / "training" / "artifacts" / "models",
    )
