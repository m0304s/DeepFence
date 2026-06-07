from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT / "service" / "common" / "src"))

from deepfence_common import RuntimeConfig


class RuntimeConfigTest(unittest.TestCase):
    def test_twostage_env_overrides(self) -> None:
        previous = {
            key: os.environ.get(key)
            for key in (
                "MODEL_MODE",
                "ATTACK_MODEL_NAME",
                "BINARY_ATTACK_THRESHOLD",
                "RESCUE_LABEL",
                "RESCUE_MIN_BINARY_ATTACK_PROBABILITY",
                "RESCUE_ATTACK_LABEL_THRESHOLD",
            )
        }
        try:
            os.environ["MODEL_MODE"] = "netflow_v2_twostage"
            os.environ["ATTACK_MODEL_NAME"] = "attack.cbm"
            os.environ["BINARY_ATTACK_THRESHOLD"] = "0.97"
            os.environ["RESCUE_LABEL"] = "Infiltration"
            os.environ["RESCUE_MIN_BINARY_ATTACK_PROBABILITY"] = "0.08"
            os.environ["RESCUE_ATTACK_LABEL_THRESHOLD"] = "0.90"

            config = RuntimeConfig()

            self.assertEqual(config.model_mode, "netflow_v2_twostage")
            self.assertEqual(config.attack_model_name, "attack.cbm")
            self.assertEqual(config.binary_attack_threshold, 0.97)
            self.assertEqual(config.rescue_label, "Infiltration")
            self.assertEqual(config.rescue_min_binary_attack_probability, 0.08)
            self.assertEqual(config.rescue_attack_label_threshold, 0.90)
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


if __name__ == "__main__":
    unittest.main()
