"""Security utilities for cryptographic checksum hashing and file validation."""

from __future__ import annotations

import hashlib
from pathlib import Path
from tableau_dr.exceptions import SecurityValidationError, ValidationError


def sha256_file(file_path: str | Path, block_size: int = 65536) -> str:
    """Computes SHA-256 digest of a file in memory-efficient chunks."""
    target = Path(file_path)
    if not target.exists():
        raise FileNotFoundError(f"Cannot compute hash for missing file: {target}")

    hasher = hashlib.sha256()
    with open(target, "rb") as f:
        for chunk in iter(lambda: f.read(block_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def validate_file(
    file_path: str | Path,
    must_exist: bool = True,
    min_size_mb: float = 0.0,
) -> bool:
    """Validates physical file attributes."""
    target = Path(file_path)
    if must_exist and not target.exists():
        raise ValidationError(f"File validation failed. Path does not exist: {target}")

    if min_size_mb > 0.0:
        size_bytes = target.stat().st_size
        size_mb = size_bytes / (1024 * 1024)
        if size_mb < min_size_mb:
            raise SecurityValidationError(
                f"File '{target.name}' size ({size_mb:.2f} MB) is below minimum threshold ({min_size_mb:.2f} MB)."
            )

    return True