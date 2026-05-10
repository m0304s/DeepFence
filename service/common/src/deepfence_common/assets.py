"""서비스 자산 맥락 로더."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class AssetEntry:
    """IP별 자산 맥락."""

    roles: tuple[str, ...] = ()
    trusted_server_ports: tuple[int, ...] = ()


def load_asset_catalog(project_root: Path, relative_path: str = "service/configs/assets.json") -> dict[str, AssetEntry]:
    """선택적 자산 맵 로드."""
    path = project_root / relative_path
    if not path.exists():
        return {}

    raw = json.loads(path.read_text(encoding="utf-8"))
    catalog: dict[str, AssetEntry] = {}
    for ip, item in raw.items():
        roles = tuple(str(role).strip() for role in item.get("roles", []) if str(role).strip())
        trusted_server_ports = tuple(int(port) for port in item.get("trusted_server_ports", []))
        catalog[ip] = AssetEntry(
            roles=roles,
            trusted_server_ports=trusted_server_ports,
        )
    return catalog
