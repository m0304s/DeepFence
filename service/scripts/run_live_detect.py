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
    required_files = [
        (paths.processed_dir / "feature_names.json", "피처 이름"),
        (paths.processed_dir / "scaler.pkl", "스케일러"),
        (paths.model_dir / config.default_model_name, "모델"),
    ]
    if config.model_mode in {"netflow_v2_twostage", "netflow_v3_rescue"}:
        required_files.extend(
            [
                (paths.processed_dir / "attack_label_mapping.json", "공격 레이블 매핑"),
                (paths.processed_dir / "binary_label_mapping.json", "이진 레이블 매핑"),
                (paths.model_dir / config.attack_model_name, "공격 유형 모델"),
            ]
        )
    else:
        required_files.append((paths.processed_dir / "label_mapping.json", "레이블 매핑"))

    for path, description in required_files:
        _require_file(path, description)

    # Scapy 대신 Suricata를 사용하므로 인터페이스 확인 로직 생략 (또는 별도 구현)
    if not config.capture_interface:
        raise ValueError("캡처 인터페이스(config.capture_interface)가 설정되지 않았습니다.")

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
        "%s: label=%s confidence=%.4f risk_score=%s action=%s should_block=%s reason=%s observations=%s matched_rules=%s matched_signatures=%s matched_behaviors=%s suspicious=%s suspicious_reason=%s src=%s:%s dst=%s:%s proto=%s packets=%s fwd=%s bwd=%s source=%s src_roles=%s dst_roles=%s top3=[%s]",
        prefix,
        result.label,
        result.confidence,
        result.risk_score,
        result.action,
        result.should_block,
        result.policy_reason,
        result.observation_count,
        list(result.matched_rules),
        list(result.matched_signatures),
        list(result.matched_behaviors),
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
        metadata.get("src_asset_roles", "-"),
        metadata.get("dst_asset_roles", "-"),
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
    from deepfence_blocker.suricata_updater import SuricataUpdater
    from deepfence_common import (
        OpenSearchEventStore,
        RuntimeConfig,
        build_runtime_paths,
        load_default_env,
        log_context,
    )
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
    updater = SuricataUpdater(config)
    runner, tailer = build_live_runtime(paths, config)
    event_store = OpenSearchEventStore(config) if config.opensearch_enabled else None

    logger.info("상시 수집 시작: interface=%s", config.capture_interface)
    try:
        while True:
            updater.cleanup_expired_rules()
            flows = collect_live_flows(tailer, config)
            if not flows:
                logger.debug("처리 가능한 종료 플로우 없음")
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
                    if result.should_block:
                        updater.block_ip(result.flow.key.src_ip, result.policy_reason)
                        
                    if event_store is not None:
                        event_store.save(result)
            sleep(config.loop_sleep_seconds)
    except KeyboardInterrupt:
        logger.info("중단 신호 수신, 남은 플로우 정리 시작")
        
        # Suricata를 먼저 종료해야 메모리에 버퍼링된 플로우들이 eve.json에 강제 플러시됨
        runner.stop()
        sleep(1) # 파일 I/O 대기
        
        for flow in flush_live_flows(tailer, config):
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
                if result.should_block:
                    updater.block_ip(result.flow.key.src_ip, result.policy_reason)
                    
                if event_store is not None:
                    event_store.save(result)
        logger.info("상시 수집 종료")


if __name__ == "__main__":
    main()
