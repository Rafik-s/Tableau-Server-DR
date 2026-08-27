"""Structured logging configuration with audit trail capabilities."""

from __future__ import annotations

import logging
import sys
from typing import Optional


def get_logger(name: str = "TableauDR", run_id: Optional[str] = None) -> logging.Logger:
    """Configures and returns a structured logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = f"[%(asctime)s UTC] [%(levelname)s]"
        if run_id:
            fmt += f" [RUN_ID={run_id}]"
        fmt += " %(name)s - %(message)s"
        
        formatter = logging.Formatter(fmt)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger