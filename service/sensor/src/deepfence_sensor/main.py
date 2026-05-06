"""Sensor entry point placeholder."""

from deepfence_common.logging import configure_logging


def main() -> None:
    """Run packet capture and flow aggregation."""
    logger = configure_logging("deepfence.sensor")
    logger.info("sensor runtime placeholder started")
