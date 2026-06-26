"""Logging utilities."""
import logging
import sys
from typing import Optional


class ColoredFormatter(logging.Formatter):
    """Formatter with color support for terminals."""
    COLORS = {
        logging.DEBUG: "\033[36m",
        logging.INFO: "\033[32m",
        logging.WARNING: "\033[33m",
        logging.ERROR: "\033[31m",
        logging.CRITICAL: "\033[35m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, "")
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logger(name: str = "sast_scanner", level: int = logging.INFO, colored: bool = True) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers = []
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    fmt = "[%(asctime)s] %(levelname)s - %(message)s"
    formatter = ColoredFormatter(fmt) if colored else logging.Formatter(fmt)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger
