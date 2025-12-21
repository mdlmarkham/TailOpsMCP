"""
Secure logging configuration for TailOpsMCP
"""

import logging
import os


def setup_secure_logging():
    """Setup secure logging environment."""
    # Simple secure logging setup
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    # Configure logging without sensitive information
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Set up secure loggers in dependencies
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
