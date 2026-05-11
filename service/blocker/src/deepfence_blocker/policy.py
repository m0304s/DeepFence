"""최소 detect-only 정책."""

from __future__ import annotations

from ipaddress import ip_address

from deepfence_common import DetectionResult, RuntimeConfig, evaluate_flow_signatures
from deepfence_common.logging import configure_logging
from deepfence_blocker.behavior import BehaviorTracker


class DetectOnlyPolicy:
    """탐지 결과 평가 및 정책 적용."""

    def __init__(self, config: RuntimeConfig):
        self._config = config
        self._logger = configure_logging("deepfence.blocker")
        self._observation_counts: dict[tuple[str, str, int, str], int] = {}
        self._behavior_tracker = BehaviorTracker(config)

    def _threshold_for_label(self, label: str) -> float:
        thresholds = self._config.label_block_thresholds or {}
        return thresholds.get(label, self._config.block_confidence_threshold)

    def _label_score_for(self, label: str, confidence: float) -> int:
        label_scores = self._config.label_risk_scores or {}
        return label_scores.get(label, max(10, int(confidence * 100)))

    def _port_score_for(self, port: int) -> int:
        port_scores = self._config.sensitive_port_scores or {}
        return port_scores.get(str(port), 0)

    def _action_for_score(self, risk_score: int) -> str:
        thresholds = self._config.action_thresholds or {}
        if risk_score >= thresholds.get("block", 100):
            return "block"
        if risk_score >= thresholds.get("block_candidate", 80):
            return "block_candidate"
        if risk_score >= thresholds.get("alert", 50):
            return "alert"
        if risk_score >= thresholds.get("suspicious", 25):
            return "suspicious"
        return "log"

    def _cap_action_before_repeat(self, action: str) -> str:
        if action in {"block_candidate", "block"}:
            return "alert"
        return action

    def _cap_action(self, action: str, max_action: str) -> str:
        order = ("log", "suspicious", "alert", "block_candidate", "block")
        if action not in order or max_action not in order:
            return action
        return order[min(order.index(action), order.index(max_action))]

    def _is_private_ip(self, value: str) -> bool:
        try:
            return ip_address(value).is_private
        except ValueError:
            return False

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

    def _signature_matches_for(self, result: DetectionResult) -> tuple[tuple[str, ...], int]:
        matches = evaluate_flow_signatures(result.flow, self._config)
        total_score = sum(match.score for match in matches)
        formatted = tuple(
            f"signature({match.rule_id}:+{match.score};{match.reason})"
            for match in matches
        )
        result.matched_signatures = formatted
        return formatted, total_score

    def _behavior_matches_for(self, result: DetectionResult) -> tuple[tuple[str, ...], int]:
        matches = self._behavior_tracker.evaluate(result)
        total_score = sum(match.score for match in matches)
        formatted = tuple(
            f"behavior({match.rule_id}:+{match.score};{match.reason})"
            for match in matches
        )
        result.matched_behaviors = formatted
        return formatted, total_score

    def _evaluate_result(self, result: DetectionResult) -> tuple[int, str, list[str], str, int]:
        src_ip = result.flow.key.src_ip
        dst_ip = result.flow.key.dst_ip
        matched_rules: list[str] = []
        risk_score = 0
        observation_count = 0
        signature_rules, signature_score = self._signature_matches_for(result)

        if src_ip in self._config.whitelist_ips or dst_ip in self._config.whitelist_ips:
            matched_rules.append("whitelisted-ip")
            return 0, "log", matched_rules, "whitelisted-ip", 0

        if result.label in self._config.label_allowlist:
            behavior_rules, behavior_score = self._behavior_matches_for(result)
            matched_rules.append("allowlisted-label")
            self._annotate_suspicious(result)
            if result.suspicious:
                risk_score += self._config.suspicious_score
                matched_rules.append(result.suspicious_reason)
            if signature_rules:
                risk_score += signature_score
                matched_rules.extend(signature_rules)
            if behavior_rules:
                risk_score += behavior_score
                matched_rules.extend(behavior_rules)
            action = self._action_for_score(risk_score)
            action = self._cap_action_before_repeat(action)
            action = self._cap_action(action, self._config.signature_allowlisted_max_action)
            return risk_score, action, matched_rules, "allowlisted-label", 0

        if (
            self._config.skip_private_peer_blocking
            and self._is_private_ip(src_ip)
            and self._is_private_ip(dst_ip)
        ):
            matched_rules.append("private-peer-traffic")
            return 0, "log", matched_rules, "private-peer-traffic", 0

        behavior_rules, behavior_score = self._behavior_matches_for(result)

        threshold = self._threshold_for_label(result.label)
        if result.confidence < threshold:
            matched_rules.append(f"below-threshold({threshold:.2f})")
            if not signature_rules and not behavior_rules:
                return 0, "log", matched_rules, matched_rules[-1], 0
            risk_score += signature_score
            risk_score += behavior_score
            matched_rules.extend(signature_rules)
            matched_rules.extend(behavior_rules)
            action = self._cap_action_before_repeat(self._action_for_score(risk_score))
            return risk_score, action, matched_rules, matched_rules[0], 0

        label_score = self._label_score_for(result.label, result.confidence)
        risk_score += label_score
        matched_rules.append(f"label-score({result.label}:+{label_score})")

        port_score = self._port_score_for(result.flow.key.dst_port)
        if port_score:
            risk_score += port_score
            matched_rules.append(f"sensitive-port({result.flow.key.dst_port}:+{port_score})")

        if result.flow.metadata.get("dst_is_trusted_service"):
            reduction = min(risk_score, self._config.trusted_service_score_reduction)
            if reduction:
                risk_score -= reduction
                matched_rules.append(f"trusted-service-dampening(-{reduction})")

        if result.flow.metadata.get("likely_response_traffic"):
            reduction = min(risk_score, self._config.response_traffic_score_reduction)
            if reduction:
                risk_score -= reduction
                matched_rules.append(f"response-traffic-dampening(-{reduction})")

        if signature_rules:
            risk_score += signature_score
            matched_rules.extend(signature_rules)

        if behavior_rules:
            risk_score += behavior_score
            matched_rules.extend(behavior_rules)

        key = (src_ip, dst_ip, result.flow.key.dst_port, result.label)
        observation_count = self._observation_counts.get(key, 0) + 1
        self._observation_counts[key] = observation_count

        if observation_count < self._config.min_block_observations:
            matched_rules.append(
                f"awaiting-repeat({observation_count}/{self._config.min_block_observations})"
            )
            action = self._cap_action_before_repeat(self._action_for_score(risk_score))
            return risk_score, action, matched_rules, matched_rules[-1], observation_count

        risk_score += self._config.repeat_observation_score
        matched_rules.append(f"repeat-score(+{self._config.repeat_observation_score})")
        matched_rules.append("threshold-and-repeat-met")
        action = self._action_for_score(risk_score)
        return risk_score, action, matched_rules, "threshold-and-repeat-met", observation_count

    def apply(self, result: DetectionResult) -> DetectionResult:
        """탐지 결과 1건 처리."""
        mode = "detect-only" if self._config.detect_only else "차단"
        risk_score, action, matched_rules, reason, observation_count = self._evaluate_result(result)
        result.risk_score = risk_score
        result.action = action
        result.matched_rules = tuple(matched_rules)
        result.should_block = action in {"block_candidate", "block"}
        result.policy_reason = reason
        result.observation_count = observation_count
        self._logger.info(
            "정책 적용: mode=%s label=%s confidence=%.4f risk_score=%s action=%s should_block=%s reason=%s observations=%s matched_rules=%s matched_signatures=%s matched_behaviors=%s suspicious=%s suspicious_reason=%s",
            mode,
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
        )
        return result
