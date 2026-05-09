from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT / "service" / "common" / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "service" / "blocker" / "src"))

from deepfence_blocker.policy import DetectOnlyPolicy
from deepfence_common import DetectionResult, FlowKey, FlowRecord, RuntimeConfig


def _build_result(
    label: str,
    confidence: float,
    src_ip: str = "198.51.100.10",
    dst_ip: str = "203.0.113.20",
) -> DetectionResult:
    flow = FlowRecord(
        key=FlowKey(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=50000,
            dst_port=443,
            protocol="TCP",
        ),
        features={},
    )
    return DetectionResult(
        label=label,
        confidence=confidence,
        should_block=False,
        flow=flow,
        probabilities={label: confidence},
    )


class DetectOnlyPolicyTest(unittest.TestCase):
    def test_allowlisted_label_is_not_blocked(self) -> None:
        policy = DetectOnlyPolicy(RuntimeConfig())

        result = policy.apply(_build_result(label="Benign", confidence=0.99))

        self.assertFalse(result.should_block)
        self.assertEqual(result.policy_reason, "allowlisted-label")
        self.assertEqual(result.observation_count, 0)

    def test_below_threshold_is_not_blocked(self) -> None:
        policy = DetectOnlyPolicy(
            RuntimeConfig(
                label_allowlist=("Benign",),
                label_block_thresholds={"Infiltration": 0.70},
                skip_private_peer_blocking=False,
            )
        )

        result = policy.apply(_build_result(label="Infiltration", confidence=0.60))

        self.assertFalse(result.should_block)
        self.assertEqual(result.policy_reason, "below-threshold(0.70)")
        self.assertEqual(result.observation_count, 0)

    def test_first_detection_awaits_repeat_before_blocking(self) -> None:
        policy = DetectOnlyPolicy(
            RuntimeConfig(
                label_allowlist=("Benign",),
                label_block_thresholds={"Infiltration": 0.55},
                min_block_observations=2,
                skip_private_peer_blocking=False,
            )
        )

        result = policy.apply(_build_result(label="Infiltration", confidence=0.60))

        self.assertFalse(result.should_block)
        self.assertEqual(result.policy_reason, "awaiting-repeat(1/2)")
        self.assertEqual(result.observation_count, 1)

    def test_second_detection_triggers_block_decision(self) -> None:
        policy = DetectOnlyPolicy(
            RuntimeConfig(
                label_allowlist=("Benign",),
                label_block_thresholds={"Infiltration": 0.55},
                min_block_observations=2,
                skip_private_peer_blocking=False,
            )
        )

        policy.apply(_build_result(label="Infiltration", confidence=0.60))
        result = policy.apply(_build_result(label="Infiltration", confidence=0.61))

        self.assertTrue(result.should_block)
        self.assertEqual(result.policy_reason, "threshold-and-repeat-met")
        self.assertEqual(result.observation_count, 2)

    def test_whitelisted_ip_bypasses_blocking(self) -> None:
        policy = DetectOnlyPolicy(
            RuntimeConfig(
                label_allowlist=("Benign",),
                whitelist_ips=("198.51.100.10",),
                label_block_thresholds={"Infiltration": 0.55},
                skip_private_peer_blocking=False,
            )
        )

        result = policy.apply(_build_result(label="Infiltration", confidence=0.90))

        self.assertFalse(result.should_block)
        self.assertEqual(result.policy_reason, "whitelisted-ip")
        self.assertEqual(result.observation_count, 0)

    def test_private_peer_traffic_is_not_blocked_when_enabled(self) -> None:
        policy = DetectOnlyPolicy(
            RuntimeConfig(
                label_allowlist=("Benign",),
                label_block_thresholds={"Infiltration": 0.55},
                skip_private_peer_blocking=True,
            )
        )

        result = policy.apply(
            _build_result(
                label="Infiltration",
                confidence=0.90,
                src_ip="192.168.0.12",
                dst_ip="192.168.0.1",
            )
        )

        self.assertFalse(result.should_block)
        self.assertEqual(result.policy_reason, "private-peer-traffic")
        self.assertEqual(result.observation_count, 0)

    def test_close_attack_second_choice_marks_result_suspicious(self) -> None:
        policy = DetectOnlyPolicy(
            RuntimeConfig(
                label_allowlist=("Benign",),
                suspicious_attack_labels=("Infiltration",),
                suspicious_secondary_threshold=0.30,
                suspicious_gap_threshold=0.15,
            )
        )

        result = _build_result(label="Benign", confidence=0.56)
        result.probabilities = {"Benign": 0.56, "Infiltration": 0.44}
        result = policy.apply(result)

        self.assertTrue(result.suspicious)
        self.assertEqual(
            result.suspicious_reason,
            "close-second(Infiltration=0.4400,gap=0.1200)",
        )

    def test_large_gap_benign_result_is_not_marked_suspicious(self) -> None:
        policy = DetectOnlyPolicy(
            RuntimeConfig(
                label_allowlist=("Benign",),
                suspicious_attack_labels=("Infiltration",),
                suspicious_secondary_threshold=0.30,
                suspicious_gap_threshold=0.15,
            )
        )

        result = _build_result(label="Benign", confidence=0.80)
        result.probabilities = {"Benign": 0.80, "Infiltration": 0.18, "DoS": 0.02}
        result = policy.apply(result)

        self.assertFalse(result.suspicious)
        self.assertEqual(result.suspicious_reason, "")


if __name__ == "__main__":
    unittest.main()
