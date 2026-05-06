"""실시간 패킷 기반 detect-only 파이프라인 실행."""

from __future__ import annotations

import sys
from time import sleep
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
    from deepfence_common import RuntimeConfig, build_runtime_paths, load_default_env
    from deepfence_common.logging import configure_logging
    from deepfence_inference.main import build_predictor
    from deepfence_sensor.main import build_live_runtime, collect_live_flows, flush_live_flows

    logger = configure_logging("deepfence.runner")
    load_default_env(project_root)
    config = RuntimeConfig()
    paths = build_runtime_paths(project_root)

    predictor = build_predictor(paths, config)
    policy = build_policy(config)
    table, extractor = build_live_runtime(paths)

    logger.info("상시 수집 시작: interface=%s", config.capture_interface)
    try:
        while True:
            flows = collect_live_flows(table, extractor, config)
            if not flows:
                logger.info("처리 가능한 종료 플로우 없음")
            for flow in flows:
                result = policy.apply(predictor.predict(flow))
                logger.info(
                    "실시간 파이프라인 완료: label=%s confidence=%.4f src=%s dst=%s",
                    result.label,
                    result.confidence,
                    result.flow.key.src_ip,
                    result.flow.key.dst_ip,
                )
            sleep(config.loop_sleep_seconds)
    except KeyboardInterrupt:
        logger.info("중단 신호 수신, 남은 플로우 정리 시작")
        for flow in flush_live_flows(table, extractor):
            result = policy.apply(predictor.predict(flow))
            logger.info(
                "종료 전 플로우 처리: label=%s confidence=%.4f src=%s dst=%s",
                result.label,
                result.confidence,
                result.flow.key.src_ip,
                result.flow.key.dst_ip,
            )
        logger.info("상시 수집 종료")


if __name__ == "__main__":
    main()
