"""Storage capacity and system validation utilities."""

from __future__ import annotations

import shutil
from pathlib import Path
from tableau_dr.exceptions import ValidationError


def validate_disk_space(target_directory: str | Path, required_gb: float) -> bool:
    """Validates available disk space for local backup or recovery workspace."""
    target = Path(target_directory)
    # Target may not exist yet; evaluate parent folder
    check_path = target if target.exists() else target.parent

    try:
        usage = shutil.disk_usage(check_path)
        free_gb = usage.free / (1024 ** 3)
        if free_gb < required_gb:
            raise ValidationError(
                f"Insufficient disk space on target path '{check_path}'. "
                f"Available: {free_gb:.2f} GB | Required: {required_gb:.2f} GB"
            )
        return True
    except Exception as e:
        if isinstance(e, ValidationError):
            raise
        raise ValidationError(f"Failed to check disk usage on '{check_path}': {e}") from e