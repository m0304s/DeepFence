"""실시간 패킷 기반 detect-only 파이프라인 실행."""

from __future__ import annotations

import sys
from pathlib import Path


def _extend_sys_path(project_root: Path) -> None:
    """설치 없이 서비스 패키지 import 경로 추가."""
    for relative in (
        "service/common/src",
        "service/sensor/src",
        "service/inference/src",
        "service/blocker/src",
    ):
        sys.path.insert(0, str(project_root / relative))


def main() -> None:
    """실시간 패킷 수집으로 전체 파이프라인 실행."""
    project_root = Path(__file__).resolve().parents[2]
    _extend_sys_path(project_root)

    from deepfence_blocker.main import build_policy
    from deepfence_common import RuntimeConfig, build_runtime_paths
    from deepfence_common.logging import configure_logging
    from deepfence_inference.main import build_predictor
    from deepfence_sensor.main import capture_live_flow

    logger = configure_logging("deepfence.runner")
    config = RuntimeConfig()
    paths = build_runtime_paths(project_root)

    flow = capture_live_flow(paths, config)
    predictor = build_predictor(paths, config)
    policy = build_policy(config)

    result = policy.apply(predictor.predict(flow))
    logger.info(
        "실시간 파이프라인 완료: label=%s confidence=%.4f src=%s dst=%s",
        result.label,
        result.confidence,
        result.flow.key.src_ip,
        result.flow.key.dst_ip,
    )


if __name__ == "__main__":
    main()
