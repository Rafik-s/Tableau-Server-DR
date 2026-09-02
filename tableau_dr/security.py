"""
Security utilities for cryptographic hashing and file validation.

This module provides reusable security primitives for the Tableau DR
backup and recovery workflows.

The functions intentionally fail closed when files, sizes, or cryptographic
digests cannot be validated.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from pathlib import Path

from tableau_dr.exceptions import (
    SecurityValidationError,
    ValidationError,
)


DEFAULT_BLOCK_SIZE = 64 * 1024
SHA256_HEX_LENGTH = 64
MIN_BLOCK_SIZE = 1024
MAX_BLOCK_SIZE = 16 * 1024 * 1024
MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024 * 1024 * 1024  # 1 TiB


def _validate_block_size(
    block_size: int,
) -> int:
    """Validate a file hashing block size."""

    if (
        isinstance(block_size, bool)
        or not isinstance(block_size, int)
    ):
        raise ValueError(
            "block_size must be an integer."
        )

    if not (
        MIN_BLOCK_SIZE
        <= block_size
        <= MAX_BLOCK_SIZE
    ):
        raise ValueError(
            "block_size must be between "
            f"{MIN_BLOCK_SIZE} and {MAX_BLOCK_SIZE} bytes."
        )

    return block_size


def _validate_sha256_digest(
    expected_sha256: str,
) -> str:
    """Validate and normalize a SHA-256 hexadecimal digest."""

    if not isinstance(
        expected_sha256,
        str,
    ):
        raise SecurityValidationError(
            "Expected SHA-256 digest must be a string."
        )

    expected = (
        expected_sha256
        .strip()
        .lower()
    )

    if (
        len(expected) != SHA256_HEX_LENGTH
        or any(
            character not in "0123456789abcdef"
            for character in expected
        )
    ):
        raise SecurityValidationError(
            "Invalid SHA-256 digest format."
        )

    return expected


def sha256_file(
    file_path: str | Path,
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> str:
    """
    Compute the SHA-256 digest of a file.

    The file is processed in bounded chunks so large Tableau backup
    artifacts do not need to be loaded into memory.
    """

    validated_block_size = _validate_block_size(
        block_size
    )

    target = Path(
        file_path
    )

    if not target.exists():
        raise FileNotFoundError(
            "Cannot compute hash for missing file."
        )

    if not target.is_file():
        raise SecurityValidationError(
            "Cannot compute hash because the path is not "
            "a regular file."
        )

    try:
        size_bytes = target.stat().st_size

    except OSError as exc:
        raise SecurityValidationError(
            "Unable to determine file size for SHA-256 validation."
        ) from exc

    if size_bytes < 0:
        raise SecurityValidationError(
            "File reported an invalid size."
        )

    if size_bytes > MAX_FILE_SIZE_BYTES:
        raise SecurityValidationError(
            "File exceeds the maximum supported hashing size."
        )

    hasher = hashlib.sha256()

    try:
        with target.open(
            "rb"
        ) as file:
            for chunk in iter(
                lambda: file.read(
                    validated_block_size
                ),
                b"",
            ):
                hasher.update(
                    chunk
                )

    except OSError as exc:
        raise SecurityValidationError(
            "Unable to read file for SHA-256 validation."
        ) from exc

    return hasher.hexdigest()


def verify_sha256(
    file_path: str | Path,
    expected_sha256: str,
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> bool:
    """
    Verify a file's SHA-256 digest using constant-time comparison.

    Returns True only when the calculated digest exactly matches the
    supplied expected digest.
    """

    expected = _validate_sha256_digest(
        expected_sha256
    )

    actual = sha256_file(
        file_path=file_path,
        block_size=block_size,
    )

    if not hmac.compare_digest(
        actual,
        expected,
    ):
        raise SecurityValidationError(
            "SHA-256 validation failed for file: "
            f"{Path(file_path).name}"
        )

    return True


def validate_file(
    file_path: str | Path,
    must_exist: bool = True,
    min_size_mb: float = 0.0,
) -> bool:
    """
    Validate file existence, type, and minimum size.

    Parameters:
        file_path:
            File to validate.

        must_exist:
            If True, a missing file is an error. If False, a missing file
            is accepted.

        min_size_mb:
            Minimum permitted file size in MiB.
    """

    if isinstance(
        must_exist,
        bool,
    ) is False:
        raise ValueError(
            "must_exist must be boolean."
        )

    if (
        isinstance(min_size_mb, bool)
        or not isinstance(
            min_size_mb,
            (int, float),
        )
        or not math.isfinite(
            float(min_size_mb)
        )
    ):
        raise ValueError(
            "min_size_mb must be a finite numeric value."
        )

    if min_size_mb < 0:
        raise ValueError(
            "min_size_mb cannot be negative."
        )

    target = Path(
        file_path
    )

    if not target.exists():
        if must_exist:
            raise ValidationError(
                "File validation failed. "
                "Path does not exist."
            )

        return True

    if not target.is_file():
        raise ValidationError(
            "File validation failed. "
            "Path is not a regular file."
        )

    try:
        size_bytes = target.stat().st_size

    except OSError as exc:
        raise ValidationError(
            "Unable to determine file size."
        ) from exc

    if size_bytes < 0:
        raise ValidationError(
            "File reported an invalid size."
        )

    minimum_size_bytes = (
        float(min_size_mb)
        * 1024
        * 1024
    )

    if size_bytes < minimum_size_bytes:
        actual_size_mb = (
            size_bytes
            / (1024 * 1024)
        )

        raise SecurityValidationError(
            f"File '{target.name}' size "
            f"({actual_size_mb:.2f} MB) is below minimum "
            f"threshold ({float(min_size_mb):.2f} MB)."
        )

    if size_bytes > MAX_FILE_SIZE_BYTES:
        raise SecurityValidationError(
            "File exceeds the maximum supported size."
        )

    return True