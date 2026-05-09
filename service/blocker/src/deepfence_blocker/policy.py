"""최소 detect-only 정책."""

from __future__ import annotations

from ipaddress import ip_address

from deepfence_common import DetectionResult, RuntimeConfig
from deepfence_common.logging import configure_logging


class DetectOnlyPolicy:
    """탐지 결과 평가 및 정책 적용."""

    def __init__(self, config: RuntimeConfig):
        self._config = config
        self._logger = configure_logging("deepfence.blocker")
        self._observation_counts: dict[tuple[str, str], int] = {}

    def _threshold_for_label(self, label: str) -> float:
        thresholds = self._config.label_block_thresholds or {}
        return thresholds.get(label, self._config.block_confidence_threshold)

    def _is_private_ip(self, value: str) -> bool:
        try:
            return ip_address(value).is_private
        except ValueError:
            return False

    def _evaluate_reason(self, result: DetectionResult) -> tuple[bool, str, int]:
        src_ip = result.flow.key.src_ip
        dst_ip = result.flow.key.dst_ip

        if result.label in self._config.label_allowlist:
            return False, "allowlisted-label", 0

        if src_ip in self._config.whitelist_ips or dst_ip in self._config.whitelist_ips:
            return False, "whitelisted-ip", 0

        if (
            self._config.skip_private_peer_blocking
            and self._is_private_ip(src_ip)
            and self._is_private_ip(dst_ip)
        ):
            return False, "private-peer-traffic", 0

        threshold = self._threshold_for_label(result.label)
        if result.confidence < threshold:
            return False, f"below-threshold({threshold:.2f})", 0

        key = (src_ip, result.label)
        observation_count = self._observation_counts.get(key, 0) + 1
        self._observation_counts[key] = observation_count

        if observation_count < self._config.min_block_observations:
            return False, f"awaiting-repeat({observation_count}/{self._config.min_block_observations})", observation_count

        return True, "threshold-and-repeat-met", observation_count

    def _annotate_suspicious(self, result: DetectionResult) -> None:
        if result.label not in self._config.label_allowlist:
            return
        if not result.probabilities:
            return

        ranked = sorted(result.probabilities.items(), key=lambda item: item[1], reverse=True)
        if len(ranked) < 2:
            return

        top_label, top_score = ranked[0]
        secondary_label, secondary_score = ranked[1]
        gap = top_score - secondary_score

        if top_label != result.label:
            return
        if secondary_label not in self._config.suspicious_attack_labels:
            return
        if secondary_score < self._config.suspicious_secondary_threshold:
            return
        if gap > self._config.suspicious_gap_threshold:
            return

        result.suspicious = True
        result.suspicious_reason = (
            f"close-second({secondary_label}={secondary_score:.4f},gap={gap:.4f})"
        )

    def apply(self, result: DetectionResult) -> DetectionResult:
        """탐지 결과 1건 처리."""
        action = "detect-only" if self._config.detect_only else "차단"
        should_block, reason, observation_count = self._evaluate_reason(result)
        result.should_block = should_block
        result.policy_reason = reason
        result.observation_count = observation_count
        self._annotate_suspicious(result)
        self._logger.info(
            "정책 적용: mode=%s label=%s confidence=%.4f should_block=%s reason=%s observations=%s suspicious=%s suspicious_reason=%s",
            action,
            result.label,
            result.confidence,
            result.should_block,
            result.policy_reason,
            result.observation_count,
            result.suspicious,
            result.suspicious_reason or "-",
        )
        return result
