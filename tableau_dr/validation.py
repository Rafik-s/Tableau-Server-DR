"""System environment, disk capacity, and Tableau compatibility validators."""

from __future__ import annotations

import shutil
from pathlib import Path
from packaging.version import Version
from tableau_dr.exceptions import ValidationError

def validate_disk_space(path: str | Path, required_gb: float) -> None:
    """Ensures target drive partition has adequate free disk space."""
    target = Path(path)
    check_path = target if target.exists() else target.parent

    if not check_path.exists():
        raise ValidationError(f"Target disk partition path does not exist: {check_path}")

    usage = shutil.disk_usage(check_path)
    free_gb = usage.free / (1024 ** 3)

    if free_gb < required_gb:
        raise ValidationError(
            f"Insufficient disk space on partition '{check_path}'. "
            f"Required: {required_gb:.2f} GB | Available: {free_gb:.2f} GB"
        )


def validate_tableau_version(backup_version: str, dr_version: str) -> None:
    """Enforces Tableau restore rule: DR Target Version >= Backup Source Version."""
    try:
        source = Version(backup_version)
        target = Version(dr_version)
    except Exception as e:
        raise ValidationError(f"Invalid Tableau semantic version format: {e}") from e

    if target < source:
        raise ValidationError(
            f"Tableau version incompatibility block. Source backup version ({source}) "
            f"cannot be restored onto an older DR server version ({target})."
        )


def validate_identity_store(source_store: str, dr_store: str) -> None:
    """Enforces matching identity store types (e.g., activedirectory vs local)."""
    if source_store.strip().lower() != dr_store.strip().lower():
        raise ValidationError(
            f"Identity store mismatch block. Source store '{source_store}' "
            f"is incompatible with DR store '{dr_store}'."
        )