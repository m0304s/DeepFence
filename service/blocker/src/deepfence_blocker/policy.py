"""최소 detect-only 정책."""

from deepfence_common import DetectionResult, RuntimeConfig
from deepfence_common.logging import configure_logging


class DetectOnlyPolicy:
    """탐지 결과 평가 및 정책 적용."""

    def __init__(self, config: RuntimeConfig):
        self._config = config
        self._logger = configure_logging("deepfence.blocker")

    def apply(self, result: DetectionResult) -> DetectionResult:
        """탐지 결과 1건 처리."""
        action = "detect-only" if self._config.detect_only else "차단"
        self._logger.info(
            "정책 적용: mode=%s label=%s confidence=%.4f should_block=%s",
            action,
            result.label,
            result.confidence,
            result.should_block,
        )
        return result
