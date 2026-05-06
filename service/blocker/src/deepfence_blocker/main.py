"""차단기 진입점."""

from deepfence_common import RuntimeConfig
from deepfence_common.logging import configure_logging
from deepfence_blocker.policy import DetectOnlyPolicy


def build_policy(config: RuntimeConfig) -> DetectOnlyPolicy:
    """detect-only 정책 엔진 구성."""
    logger = configure_logging("deepfence.blocker")
    logger.info("차단 정책 초기화 완료")
    return DetectOnlyPolicy(config)


def main() -> None:
    """차단기 런타임 시작."""
    logger = configure_logging("deepfence.blocker")
    logger.info("차단기 런타임 시작")
