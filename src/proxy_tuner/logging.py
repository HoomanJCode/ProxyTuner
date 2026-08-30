"""Structured logging framework for ProxyTuner.

Provides configurable logging with file output, log levels,
and structured format.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path


class ColorFormatter(logging.Formatter):
    """Colored log formatter for terminal output."""

    COLORS = {
        logging.DEBUG: "\033[36m",    # Cyan
        logging.INFO: "\033[32m",     # Green
        logging.WARNING: "\033[33m",  # Yellow
        logging.ERROR: "\033[31m",    # Red
        logging.CRITICAL: "\033[35m", # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, "")
        reset = self.RESET
        record.colored_level = f"{color}{record.levelname:<8}{reset}"
        return super().format(record)


def setup_logging(
    level: str = "info",
    log_file: str | None = None,
    log_format: str | None = None,
) -> None:
    """Configure logging for ProxyTuner.

    Args:
        level: Log level (debug, info, warning, error).
        log_file: Optional file path for log output.
        log_format: Optional custom format string.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Root logger for the package
    root_logger = logging.getLogger("proxy_tuner")
    root_logger.setLevel(numeric_level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(numeric_level)

    if log_format is None:
        log_format = "%(asctime)s %(colored_level)s %(name)s: %(message)s"

    console_formatter = ColorFormatter(
        log_format,
        datefmt="%H:%M:%S",
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            str(file_path),
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)

        file_format = log_format.replace("%(colored_level)s", "%(levelname)-8s")
        file_formatter = logging.Formatter(
            file_format,
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    # Suppress noisy third-party loggers
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger for a module."""
    return logging.getLogger(f"proxy_tuner.{name}")
