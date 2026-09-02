"""Security utilities for cryptographic hashing and file validation."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

from tableau_dr.exceptions import SecurityValidationError, ValidationError


DEFAULT_BLOCK_SIZE = 64 * 1024
SHA256_HEX_LENGTH = 64


def sha256_file(
    file_path: str | Path,
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> str:
    """Compute the SHA-256 digest of a file using memory-efficient chunks."""

    target = Path(file_path)

    if block_size <= 0:
        raise ValueError("block_size must be greater than zero.")

    if not target.exists():
        raise FileNotFoundError(
            f"Cannot compute hash for missing file: {target}"
        )

    if not target.is_file():
        raise SecurityValidationError(
            f"Cannot compute hash. Path is not a regular file: {target}"
        )

    hasher = hashlib.sha256()

    try:
        with target.open("rb") as file:
            for chunk in iter(lambda: file.read(block_size), b""):
                hasher.update(chunk)
    except OSError as exc:
        raise SecurityValidationError(
            f"Unable to read file for SHA-256 validation: {target}"
        ) from exc

    return hasher.hexdigest()


def verify_sha256(
    file_path: str | Path,
    expected_sha256: str,
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> bool:
    """Verify a file's SHA-256 digest using constant-time comparison."""

    if not isinstance(expected_sha256, str):
        raise SecurityValidationError(
            "Expected SHA-256 digest must be a string."
        )

    expected = expected_sha256.strip().lower()

    if (
        len(expected) != SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in expected)
    ):
        raise SecurityValidationError(
            "Invalid SHA-256 digest format."
        )

    actual = sha256_file(
        file_path=file_path,
        block_size=block_size,
    )

    if not hmac.compare_digest(actual, expected):
        raise SecurityValidationError(
            f"SHA-256 validation failed for file: {Path(file_path).name}"
        )

    return True


def validate_file(
    file_path: str | Path,
    must_exist: bool = True,
    min_size_mb: float = 0.0,
) -> bool:
    """Validate file existence, type, readability, and minimum size."""

    target = Path(file_path)

    if must_exist and not target.exists():
        raise ValidationError(
            f"File validation failed. Path does not exist: {target}"
        )

    if not target.exists():
        return True

    if not target.is_file():
        raise ValidationError(
            f"File validation failed. Path is not a regular file: {target}"
        )

    if min_size_mb < 0:
        raise ValueError(
            "min_size_mb cannot be negative."
        )

    if min_size_mb > 0.0:
        try:
            size_bytes = target.stat().st_size
        except OSError as exc:
            raise ValidationError(
                f"Unable to determine file size: {target}"
            ) from exc

        minimum_size_bytes = min_size_mb * 1024 * 1024

        if size_bytes < minimum_size_bytes:
            actual_size_mb = size_bytes / (1024 * 1024)

            raise SecurityValidationError(
                f"File '{target.name}' size "
                f"({actual_size_mb:.2f} MB) is below minimum "
                f"threshold ({min_size_mb:.2f} MB)."
            )

    return True