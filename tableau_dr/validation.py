"""System environment, disk capacity, and Tableau compatibility validators."""

from __future__ import annotations

import math
import shutil
from pathlib import Path

from packaging.version import InvalidVersion, Version

from tableau_dr.exceptions import ValidationError


def validate_disk_space(
    path: str | Path,
    required_gb: float,
) -> None:
    """Ensure the target filesystem has sufficient free disk space."""

    if not isinstance(required_gb, (int, float)) or isinstance(required_gb, bool):
        raise ValidationError(
            "required_gb must be a numeric value."
        )

    if not math.isfinite(float(required_gb)) or required_gb < 0:
        raise ValidationError(
            "required_gb must be a finite value greater than or equal to zero."
        )

    target = Path(path)

    try:
        check_path = target if target.exists() else target.parent
    except OSError as exc:
        raise ValidationError(
            f"Unable to resolve disk-space validation path: {target}"
        ) from exc

    if not check_path.exists():
        raise ValidationError(
            f"Target disk partition path does not exist: {check_path}"
        )

    if not check_path.is_dir():
        check_path = check_path.parent

    if not check_path.exists() or not check_path.is_dir():
        raise ValidationError(
            f"Unable to determine filesystem for path: {target}"
        )

    try:
        usage = shutil.disk_usage(check_path)
    except OSError as exc:
        raise ValidationError(
            f"Unable to determine disk usage for: {check_path}"
        ) from exc

    free_gb = usage.free / (1024**3)

    if free_gb < required_gb:
        raise ValidationError(
            f"Insufficient disk space on partition '{check_path}'. "
            f"Required: {required_gb:.2f} GB | "
            f"Available: {free_gb:.2f} GB"
        )


def validate_tableau_version(
    backup_version: str,
    dr_version: str,
) -> None:
    """
    Ensure the DR Tableau Server version is the same or newer
    than the source version contained in the backup.
    """

    if not isinstance(backup_version, str) or not backup_version.strip():
        raise ValidationError(
            "Backup Tableau version must be a non-empty string."
        )

    if not isinstance(dr_version, str) or not dr_version.strip():
        raise ValidationError(
            "DR Tableau version must be a non-empty string."
        )

    try:
        source = Version(backup_version.strip())
        target = Version(dr_version.strip())
    except InvalidVersion as exc:
        raise ValidationError(
            "Invalid Tableau semantic version format. "
            f"Source='{backup_version}', DR='{dr_version}'."
        ) from exc

    if target < source:
        raise ValidationError(
            "Tableau version compatibility check failed. "
            f"Source backup version ({source}) cannot be restored "
            f"onto an older DR server version ({target})."
        )


def validate_identity_store(
    source_store: str,
    dr_store: str,
) -> None:
    """
    Ensure source and DR environments use compatible identity stores.
    """

    if not isinstance(source_store, str) or not source_store.strip():
        raise ValidationError(
            "Source identity store must be a non-empty string."
        )

    if not isinstance(dr_store, str) or not dr_store.strip():
        raise ValidationError(
            "DR identity store must be a non-empty string."
        )

    source = source_store.strip().lower()
    target = dr_store.strip().lower()

    if source != target:
        raise ValidationError(
            "Identity store compatibility check failed. "
            f"Source store '{source_store}' is incompatible with "
            f"DR store '{dr_store}'."
        )