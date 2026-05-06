"""Common logging helpers for runtime services."""

import logging


def configure_logging(name: str) -> logging.Logger:
    """Return a logger with a simple shared formatter."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    return logging.getLogger(name)
