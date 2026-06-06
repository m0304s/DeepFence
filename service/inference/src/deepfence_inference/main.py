"""추론 진입점."""

from deepfence_common import RuntimeConfig, RuntimePaths
from deepfence_common.logging import configure_logging
from deepfence_inference.predictor import Predictor


def build_predictor(paths: RuntimePaths, config: RuntimeConfig) -> Predictor:
    """예측기 구성."""
    logger = configure_logging("deepfence.inference")
    logger.info("추론 아티팩트 로드: %s", paths.model_dir)
    return Predictor(paths, config)


def main() -> None:
    """추론 런타임 시작."""
    logger = configure_logging("deepfence.inference")
    logger.info("추론 런타임 시작")
