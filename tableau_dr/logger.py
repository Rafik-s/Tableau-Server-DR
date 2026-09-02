"""Centralized structured logging with safe audit-context support."""

from __future__ import annotations

import logging
import re
import sys
from typing import Optional


DEFAULT_LOGGER_NAME = "TableauDR"
DEFAULT_LOG_LEVEL = logging.INFO

MAX_LOG_MESSAGE_LENGTH = 8000
MAX_CONTEXT_VALUE_LENGTH = 512

_CONTROL_CHARACTER_PATTERN = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
)

_SECRET_PATTERNS = (
    re.compile(
        r"(?i)\b("
        r"password|passwd|passphrase|client[-_ ]?secret|secret|token|"
        r"access[-_ ]?token|sas[-_ ]?token|private[-_ ]?key"
        r")\b\s*[:=]\s*"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ),
    re.compile(
        r"(?i)(--password|--passphrase|--client-secret|--token|"
        r"--access-token|--sas-token|--key-file|--cert-file)"
        r"(?:=|\s+)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ),
    re.compile(
        r"(?i)\b("
        r"authorization"
        r")\s*:\s*(?:bearer\s+)?[^\s,;]+"
    ),
)

_SECRET_REPLACEMENT = "[REDACTED]"

_FILTER_MARKER = "_tableau_dr_sensitive_filter"


def _sanitize_control_characters(text: str) -> str:
    """Remove control characters that could forge log output."""
    return _CONTROL_CHARACTER_PATTERN.sub(" ", text)


def _redact_sensitive_text(value: object) -> str:
    """
    Remove common secret-like values before writing log records.

    The returned value is also normalized to prevent multiline log injection
    and bounded to avoid accidentally generating enormous log records.
    """
    try:
        text = str(value)
    except Exception:
        return "[REDACTED]"

    text = _sanitize_control_characters(text)

    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(
            lambda match: (
                f"{match.group(1)}=[REDACTED]"
                if match.lastindex
                else _SECRET_REPLACEMENT
            ),
            text,
        )

    if len(text) > MAX_LOG_MESSAGE_LENGTH:
        text = (
            text[:MAX_LOG_MESSAGE_LENGTH]
            + " [TRUNCATED]"
        )

    return text


def _sanitize_context_value(value: object) -> str:
    """Sanitize and bound a structured logging context value."""
    text = _redact_sensitive_text(value)

    if len(text) > MAX_CONTEXT_VALUE_LENGTH:
        text = (
            text[:MAX_CONTEXT_VALUE_LENGTH]
            + " [TRUNCATED]"
        )

    return text


class SensitiveDataFilter(logging.Filter):
    """Redact common credentials and tokens from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Sanitize the rendered message in-place.

        Log records are modified before formatting so secrets supplied
        through normal ``logger.info(..., args)`` calls are also protected.
        """
        try:
            rendered_message = record.getMessage()

            record.msg = _redact_sensitive_text(
                rendered_message
            )
            record.args = ()

            # Sanitize common optional fields that may be consumed by
            # custom formatters or handlers.
            for field_name in (
                "pathname",
                "filename",
                "module",
                "funcName",
                "processName",
                "threadName",
            ):
                value = getattr(record, field_name, None)

                if isinstance(value, str):
                    setattr(
                        record,
                        field_name,
                        _sanitize_control_characters(value),
                    )

        except Exception:
            record.msg = "[REDACTED_LOG_MESSAGE]"
            record.args = ()

        return True


class RunContextAdapter(logging.LoggerAdapter):
    """Logger adapter that adds non-sensitive DR execution context."""

    _CONTEXT_KEYS = (
        "run_id",
        "environment",
        "hostname",
        "operation",
    )

    def process(
        self,
        msg: object,
        kwargs: dict,
    ) -> tuple[str, dict]:
        """Add safe execution context to the log message."""

        context = self.extra or {}
        parts: list[str] = []

        for key in self._CONTEXT_KEYS:
            value = context.get(key)

            if value is None:
                continue

            safe_value = _sanitize_context_value(value)

            if safe_value.strip():
                parts.append(
                    f"{key.upper()}={safe_value}"
                )

        prefix = (
            f"[{' '.join(parts)}] "
            if parts
            else ""
        )

        safe_message = _redact_sensitive_text(msg)

        return (
            f"{prefix}{safe_message}",
            kwargs,
        )


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
    if not isinstance(name, str):
        raise TypeError(
            "Logger name must be a string."
        )

    clean_name = name.strip()

    if not clean_name:
        raise ValueError(
            "Logger name must be a non-empty string."
        )

    clean_name = _sanitize_control_characters(
        clean_name
    )

    if not clean_name:
        raise ValueError(
            "Logger name contains no valid characters."
        )

    logger = logging.getLogger(clean_name)

    logger.setLevel(DEFAULT_LOG_LEVEL)
    logger.propagate = False

    _ensure_safe_handler(logger)

    context = {
        "run_id": run_id,
        "environment": environment,
        "hostname": hostname,
        "operation": operation,
    }

    return RunContextAdapter(
        logger,
        context,
    )


def _ensure_safe_handler(logger: logging.Logger) -> None:
    """Ensure the logger has exactly the required safe handler setup."""
    for handler in logger.handlers:
        if getattr(
            handler,
            _FILTER_MARKER,
            False,
        ):
            return

    handler = logging.StreamHandler(
        sys.stdout
    )

    formatter = logging.Formatter(
        fmt=(
            "[%(asctime)s UTC] "
            "[%(levelname)s] "
            "%(name)s - %(message)s"
        ),
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    handler.setFormatter(formatter)

    sensitive_filter = SensitiveDataFilter()

    handler.addFilter(
        sensitive_filter
    )

    setattr(
        handler,
        _FILTER_MARKER,
        True,
    )

    logger.addHandler(handler)


def configure_logging(
    level: int = logging.INFO,
) -> None:
    """
    Configure the root logging level for application-wide logging.

    Individual Tableau DR loggers retain their own handlers and formatting.
    """
    if (
        isinstance(level, bool)
        or not isinstance(level, int)
    ):
        raise ValueError(
            "Logging level must be an integer."
        )

    valid_levels = {
        logging.NOTSET,
        logging.DEBUG,
        logging.INFO,
        logging.WARNING,
        logging.ERROR,
        logging.CRITICAL,
    }

    if level not in valid_levels:
        raise ValueError(
            "Logging level must be one of the standard "
            "logging levels."
        )

    logging.getLogger().setLevel(level)