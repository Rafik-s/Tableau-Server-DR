"""File verification and cryptographic hashing utilities."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from tableau_dr.exceptions import SecurityValidationError

def validate_file(
    path: str | Path,
    *,
    must_exist: bool = True,
    max_size_mb: int | None = None,
    min_size_mb: int | None = None,
) -> Path:
    """Validates existence, read permissions, and size constraints for a target file."""
    file_path = Path(path)

    if must_exist:
        if not file_path.exists():
            raise SecurityValidationError(f"Required file does not exist: {file_path}")
        if not file_path.is_file():
            raise SecurityValidationError(f"Path is not a regular file: {file_path}")
        if not os.access(file_path, os.R_OK):
            raise SecurityValidationError(f"File exists but is not readable: {file_path}")

        size_mb = file_path.stat().st_size / (1024 * 1024)

        if max_size_mb is not None and size_mb > max_size_mb:
            raise SecurityValidationError(
                f"File {file_path.name} ({size_mb:.2f} MB) exceeds max size threshold of {max_size_mb} MB"
            )

        if min_size_mb is not None and size_mb < min_size_mb:
            raise SecurityValidationError(
                f"File {file_path.name} ({size_mb:.2f} MB) is below min size threshold of {min_size_mb} MB"
            )

    return file_path


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    """Calculates SHA-256 digest using chunked byte streaming to optimize RAM usage."""
    file_path = validate_file(path, must_exist=True)
    digest = hashlib.sha256()

    with open(file_path, "rb") as file:
        while chunk := file.read(chunk_size):
            digest.update(chunk)

    return digest.hexdigest()


def validate_sha256(path: str | Path, expected_hash: str) -> bool:
    """Compares actual SHA-256 digest against expected value using constant-time comparison."""
    actual_hash = sha256_file(path)
    if not hmac.compare_digest(actual_hash.lower(), expected_hash.lower()):
        raise SecurityValidationError(
            f"SHA-256 integrity verification failed for {path}.\n"
            f"Expected: {expected_hash.lower()}\n"
            f"Actual:   {actual_hash.lower()}"
        )
    return True