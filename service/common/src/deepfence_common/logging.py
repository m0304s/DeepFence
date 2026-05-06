"""런타임 공용 로깅 도우미."""

import logging


def configure_logging(name: str) -> logging.Logger:
    """기본 포맷 로거 반환."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    return logging.getLogger(name)
