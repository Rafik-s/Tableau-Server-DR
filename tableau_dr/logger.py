"""Centralized structured logging initialization."""

import logging
import sys

def get_logger(name: str = "TableauDR", run_id: str | None = None) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt_prefix = f"[RUN_ID={run_id}] " if run_id else ""
        formatter = logging.Formatter(
            f"%(asctime)s - {fmt_prefix}%(levelname)s - %(name)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
    return logger