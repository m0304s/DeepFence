"""실시간 패킷 기반 detect-only 파이프라인 실행."""

from __future__ import annotations

import os
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


def _require_file(path: Path, description: str) -> None:
    """필수 파일 존재 검사."""
    if not path.exists():
        raise FileNotFoundError(f"{description} 파일이 없습니다: {path}")


def _validate_runtime_inputs(paths, config) -> None:
    """실행 전 필수 아티팩트와 인터페이스 검사."""
    required_files = (
        (paths.processed_dir / "feature_names.json", "피처 이름"),
        (paths.processed_dir / "label_mapping.json", "레이블 매핑"),
        (paths.processed_dir / "scaler.pkl", "스케일러"),
        (paths.model_dir / config.default_model_name, "모델"),
    )
    for path, description in required_files:
        _require_file(path, description)

    try:
        from scapy.all import get_if_list
    except ImportError as error:
        raise RuntimeError("scapy 패키지가 필요합니다.") from error

    interfaces = set(get_if_list())
    if config.capture_interface not in interfaces:
        joined = ", ".join(sorted(interfaces))
        raise ValueError(
            f"캡처 인터페이스 '{config.capture_interface}'를 찾을 수 없습니다. "
            f"사용 가능한 인터페이스: {joined}"
        )

    if sys.platform == "darwin" and os.geteuid() != 0:
        raise PermissionError(
            "macOS 실시간 패킷 캡처는 root 권한이 필요합니다. "
            "sudo venv/bin/python service/scripts/run_live_detect.py 로 실행하세요."
        )


def _format_top_probabilities(probabilities: dict[str, float], limit: int = 3) -> str:
    """상위 예측 확률 요약."""
    ranked = sorted(probabilities.items(), key=lambda item: item[1], reverse=True)[:limit]
    return ", ".join(f"{label}={score:.4f}" for label, score in ranked)


def _log_detection_result(logger, prefix: str, result) -> None:
    """탐지 결과를 분석 친화적으로 기록."""
    metadata = result.flow.metadata
    logger.info(
        "%s: label=%s confidence=%.4f risk_score=%s action=%s should_block=%s reason=%s observations=%s matched_rules=%s suspicious=%s suspicious_reason=%s src=%s:%s dst=%s:%s proto=%s packets=%s fwd=%s bwd=%s source=%s top3=[%s]",
        prefix,
        result.label,
        result.confidence,
        result.risk_score,
        result.action,
        result.should_block,
        result.policy_reason,
        result.observation_count,
        list(result.matched_rules),
        result.suspicious,
        result.suspicious_reason or "-",
        result.flow.key.src_ip,
        result.flow.key.src_port,
        result.flow.key.dst_ip,
        result.flow.key.dst_port,
        result.flow.key.protocol,
        metadata.get("packet_count", "?"),
        metadata.get("forward_packets", "?"),
        metadata.get("backward_packets", "?"),
        metadata.get("source", "?"),
        _format_top_probabilities(result.probabilities),
    )


def _build_flow_context(flow, *, action: str = "-", risk_score: str | int = "-") -> dict[str, str]:
    key = flow.key
    flow_id = f"{key.protocol}:{key.src_ip}:{key.src_port}->{key.dst_ip}:{key.dst_port}"
    return {
        "flow_id": flow_id,
        "src": f"{key.src_ip}:{key.src_port}",
        "dst": f"{key.dst_ip}:{key.dst_port}",
        "action": str(action),
        "risk_score": str(risk_score),
    }


def main() -> None:
    """실시간 패킷 수집으로 전체 파이프라인 실행."""
    project_root = Path(__file__).resolve().parents[2]
    _extend_sys_path(project_root)

    from deepfence_blocker.main import build_policy
    from deepfence_common import RuntimeConfig, build_runtime_paths, load_default_env, log_context
    from deepfence_common.logging import configure_logging
    from deepfence_inference.main import build_predictor
    from deepfence_sensor.main import build_live_runtime, collect_live_flows, flush_live_flows

    logger = configure_logging("deepfence.runner")
    load_default_env(project_root)
    config = RuntimeConfig()
    paths = build_runtime_paths(project_root)
    _validate_runtime_inputs(paths, config)

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
                with log_context(**_build_flow_context(flow)):
                    result = policy.apply(predictor.predict(flow))
                with log_context(
                    **_build_flow_context(
                        result.flow,
                        action=result.action,
                        risk_score=result.risk_score,
                    )
                ):
                    _log_detection_result(logger, "실시간 파이프라인 완료", result)
            sleep(config.loop_sleep_seconds)
    except KeyboardInterrupt:
        logger.info("중단 신호 수신, 남은 플로우 정리 시작")
        for flow in flush_live_flows(table, extractor, config):
            with log_context(**_build_flow_context(flow)):
                result = policy.apply(predictor.predict(flow))
            with log_context(
                **_build_flow_context(
                    result.flow,
                    action=result.action,
                    risk_score=result.risk_score,
                )
            ):
                _log_detection_result(logger, "종료 전 플로우 처리", result)
        logger.info("상시 수집 종료")


if __name__ == "__main__":
    main()
