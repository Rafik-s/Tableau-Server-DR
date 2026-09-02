"""Centralized structured logging with safe audit-context support."""

from __future__ import annotations

import logging
import re
import sys
from typing import Optional


DEFAULT_LOGGER_NAME = "TableauDR"
DEFAULT_LOG_LEVEL = logging.INFO

_SECRET_PATTERNS = (
    re.compile(
        r"(?i)(password|passwd|passphrase|client[-_ ]?secret|secret|token|"
        r"access[-_ ]?token|sas|private[-_ ]?key)\s*[:=]\s*[^\s,;]+"
    ),
    re.compile(
        r"(?i)(--password|--passphrase|--client-secret|--token)\s+\S+"
    ),
)

_SECRET_REPLACEMENT = "[REDACTED]"


def _redact_sensitive_text(value: object) -> str:
    """Remove common secret-like values before writing log records."""

    text = str(value)

    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(_SECRET_REPLACEMENT, text)

    return text


class SensitiveDataFilter(logging.Filter):
    """Redact common credentials and tokens from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Sanitize the rendered log message in-place."""

        try:
            record.msg = _redact_sensitive_text(record.getMessage())
            record.args = ()
        except Exception:
            record.msg = "[REDACTED_LOG_MESSAGE]"
            record.args = ()

        return True


class RunContextAdapter(logging.LoggerAdapter):
    """Logger adapter that adds non-sensitive DR execution context."""

    def process(self, msg: object, kwargs: dict) -> tuple[str, dict]:
        """Add run/environment/host/operation context to the log message."""

        context = self.extra or {}

        parts = []

        for key in ("run_id", "environment", "hostname", "operation"):
            value = context.get(key)

            if value is not None and str(value).strip():
                safe_value = _redact_sensitive_text(value)
                parts.append(f"{key.upper()}={safe_value}")

        prefix = f"[{' '.join(parts)}] " if parts else ""

        return f"{prefix}{_redact_sensitive_text(msg)}", kwargs


def get_logger(
    name: str = DEFAULT_LOGGER_NAME,
    run_id: Optional[str] = None,
    environment: Optional[str] = None,
    hostname: Optional[str] = None,
    operation: Optional[str] = None,
) -> logging.LoggerAdapter:
    """
    Return a centralized DR logger with optional execution context.

    The logger is configured only once per logger name to avoid duplicate
    handlers when modules request the same logger repeatedly.
    """

    if not isinstance(name, str) or not name.strip():
        raise ValueError("Logger name must be a non-empty string.")

    logger = logging.getLogger(name.strip())
    logger.setLevel(DEFAULT_LOG_LEVEL)
    logger.propagate = False

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)

        formatter = logging.Formatter(
            fmt="[%(asctime)s UTC] [%(levelname)s] %(name)s - %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )

        handler.setFormatter(formatter)
        handler.addFilter(SensitiveDataFilter())

        logger.addHandler(handler)

    context = {
        "run_id": run_id,
        "environment": environment,
        "hostname": hostname,
        "operation": operation,
    }

    return RunContextAdapter(logger, context)


def configure_logging(level: int = logging.INFO) -> None:
    """
    Configure the root logging level for application-wide logging.

    Individual Tableau DR loggers retain their own handlers and formatting.
    """

    if not isinstance(level, int):
        raise ValueError("Logging level must be an integer.")

    logging.getLogger().setLevel(level)