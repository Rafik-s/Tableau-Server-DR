"""Secure Azure Blob Storage integration for Tableau DR artifacts."""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import re
from pathlib import Path

from azure.core.exceptions import AzureError
from azure.core.pipeline.policies import ExponentialRetry
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

from tableau_dr.exceptions import IntegrityError, SecurityValidationError


logger = logging.getLogger(__name__)

SHA256_LENGTH = 64
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 0.8
HASH_BLOCK_SIZE = 64 * 1024

_SECRET_PATTERN = re.compile(
    r"(?i)(password|passwd|passphrase|secret|token|access[-_ ]?token|"
    r"client[-_ ]?secret|sas[-_ ]?token)\s*[:=]\s*[^\s,;]+"
)


class AzureManager:
    """Manage Azure Blob persistence with integrity verification."""

    def __init__(
        self,
        account_name: str,
        container_name: str,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
    ) -> None:
        """Initialize an Azure Blob client using managed/default credentials."""

        self.account_name = self._validate_name(
            account_name,
            "Azure storage account name",
        )
        self.container_name = self._validate_name(
            container_name,
            "Azure container name",
        )

        self._validate_retry_configuration(
            max_retries=max_retries,
            backoff_factor=backoff_factor,
        )

        self.account_url = (
            f"https://{self.account_name}.blob.core.windows.net"
        )

        try:
            self.credential = DefaultAzureCredential()

            retry_policy = ExponentialRetry(
                initial_backoff=max(1, int(backoff_factor)),
                max_attempts=max_retries,
                random_jitter_range=1,
            )

            self.service_client = BlobServiceClient(
                account_url=self.account_url,
                credential=self.credential,
                retry_policy=retry_policy,
            )

            self.container_client = (
                self.service_client.get_container_client(
                    self.container_name
                )
            )

        except AzureError as exc:
            logger.error(
                "Azure Blob client initialization failed for configured "
                "storage account."
            )
            raise SecurityValidationError(
                "Azure Blob Storage initialization failed."
            ) from exc

    @staticmethod
    def _validate_name(value: str, description: str) -> str:
        """Validate a required Azure resource name."""

        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{description} must be a non-empty string.")

        return value.strip()

    @staticmethod
    def _validate_retry_configuration(
        max_retries: int,
        backoff_factor: float,
    ) -> None:
        """Validate retry settings."""

        if (
            isinstance(max_retries, bool)
            or not isinstance(max_retries, int)
            or max_retries < 1
        ):
            raise ValueError(
                "max_retries must be an integer greater than zero."
            )

        if (
            isinstance(backoff_factor, bool)
            or not isinstance(backoff_factor, (int, float))
            or not math.isfinite(float(backoff_factor))
            or backoff_factor <= 0
        ):
            raise ValueError(
                "backoff_factor must be a finite number greater than zero."
            )

    @staticmethod
    def _validate_blob_path(blob_path: str) -> str:
        """Validate and normalize an Azure Blob object path."""

        if not isinstance(blob_path, str) or not blob_path.strip():
            raise ValueError("blob_path must be a non-empty string.")

        normalized = blob_path.strip().replace("\\", "/")

        if normalized.startswith("/"):
            raise SecurityValidationError(
                "Blob path must not begin with '/'."
            )

        if "\x00" in normalized:
            raise SecurityValidationError(
                "Blob path contains an invalid null character."
            )

        if any(part == ".." for part in normalized.split("/")):
            raise SecurityValidationError(
                "Blob path contains an invalid traversal component."
            )

        return normalized

    @staticmethod
    def _validate_sha256(checksum: str) -> str:
        """Validate and normalize a SHA-256 hexadecimal digest."""

        if not isinstance(checksum, str):
            raise SecurityValidationError(
                "SHA-256 checksum must be a string."
            )

        normalized = checksum.strip().lower()

        if (
            len(normalized) != SHA256_LENGTH
            or any(
                character not in "0123456789abcdef"
                for character in normalized
            )
        ):
            raise SecurityValidationError(
                "Invalid SHA-256 checksum format."
            )

        return normalized

    @staticmethod
    def _sanitize_error(value: object) -> str:
        """Remove common secret-like values from Azure error text."""

        text = str(value)

        return _SECRET_PATTERN.sub(
            lambda match: f"{match.group(1)}=[REDACTED]",
            text,
        )

    @staticmethod
    def _hash_stream(stream) -> str:
        """Calculate SHA-256 from an Azure download stream."""

        digest = hashlib.sha256()

        for chunk in stream.chunks():
            digest.update(chunk)

        return digest.hexdigest()

    def upload_file(
        self,
        local_path: str | Path,
        blob_path: str,
        sha256_checksum: str,
    ) -> str:
        """
        Upload a local artifact and store its SHA-256 as Blob metadata.

        Existing blobs are intentionally overwritten because the caller
        controls the unique run-specific blob path.
        """

        file_path = Path(local_path)
        normalized_blob_path = self._validate_blob_path(blob_path)
        expected_sha256 = self._validate_sha256(sha256_checksum)

        if not file_path.exists():
            raise FileNotFoundError(
                f"Local artifact does not exist: {file_path}"
            )

        if not file_path.is_file():
            raise SecurityValidationError(
                f"Local artifact is not a regular file: {file_path}"
            )

        try:
            file_size = file_path.stat().st_size
        except OSError as exc:
            raise SecurityValidationError(
                f"Unable to determine artifact size: {file_path.name}"
            ) from exc

        if file_size <= 0:
            raise SecurityValidationError(
                f"Refusing to upload empty artifact: {file_path.name}"
            )

        blob_client = self.container_client.get_blob_client(
            normalized_blob_path
        )

        metadata = {
            "sha256": expected_sha256,
            "size_bytes": str(file_size),
        }

        logger.info(
            "Uploading artifact '%s' to Azure Blob Storage.",
            file_path.name,
        )

        try:
            with file_path.open("rb") as data:
                blob_client.upload_blob(
                    data,
                    overwrite=True,
                    metadata=metadata,
                )

        except AzureError as exc:
            logger.error(
                "Azure Blob upload failed for artifact '%s'.",
                file_path.name,
            )
            raise IntegrityError(
                "Azure Blob upload failed."
            ) from exc

        logger.info(
            "Azure Blob upload completed for '%s'.",
            file_path.name,
        )

        return normalized_blob_path

    def verify_remote_blob(
        self,
        blob_path: str,
        expected_size_bytes: int,
        expected_sha256: str,
        verify_content_stream: bool = False,
    ) -> bool:
        """
        Verify remote Blob size and SHA-256 metadata.

        Optional full content streaming verification provides end-to-end
        validation of the actual object contents.
        """

        normalized_blob_path = self._validate_blob_path(blob_path)
        expected_sha256 = self._validate_sha256(expected_sha256)

        if (
            isinstance(expected_size_bytes, bool)
            or not isinstance(expected_size_bytes, int)
            or expected_size_bytes < 0
        ):
            raise ValueError(
                "expected_size_bytes must be a non-negative integer."
            )

        blob_client = self.container_client.get_blob_client(
            normalized_blob_path
        )

        try:
            properties = blob_client.get_blob_properties()

            actual_size = properties.size

            if actual_size != expected_size_bytes:
                raise IntegrityError(
                    f"Remote Blob size mismatch for "
                    f"'{normalized_blob_path}'. "
                    f"Expected: {expected_size_bytes} | "
                    f"Actual: {actual_size}"
                )

            remote_metadata = properties.metadata or {}

            remote_sha256 = remote_metadata.get("sha256", "").strip().lower()

            if not remote_sha256:
                raise SecurityValidationError(
                    f"Remote Blob '{normalized_blob_path}' is missing "
                    "SHA-256 metadata."
                )

            try:
                remote_sha256 = self._validate_sha256(remote_sha256)
            except SecurityValidationError as exc:
                raise SecurityValidationError(
                    f"Remote Blob '{normalized_blob_path}' contains "
                    "invalid SHA-256 metadata."
                ) from exc

            if not hmac.compare_digest(
                remote_sha256,
                expected_sha256,
            ):
                raise IntegrityError(
                    f"Remote Blob SHA-256 metadata mismatch for "
                    f"'{normalized_blob_path}'."
                )

            metadata_size = remote_metadata.get("size_bytes")

            if metadata_size is not None:
                try:
                    if int(metadata_size) != expected_size_bytes:
                        raise IntegrityError(
                            f"Remote Blob metadata size mismatch for "
                            f"'{normalized_blob_path}'."
                        )
                except ValueError as exc:
                    raise SecurityValidationError(
                        f"Remote Blob '{normalized_blob_path}' contains "
                        "invalid size metadata."
                    ) from exc

            if verify_content_stream:
                logger.info(
                    "Performing full content SHA-256 verification for "
                    "'%s'.",
                    normalized_blob_path,
                )

                download_stream = blob_client.download_blob()

                actual_content_sha256 = self._hash_stream(
                    download_stream
                )

                if not hmac.compare_digest(
                    actual_content_sha256,
                    expected_sha256,
                ):
                    raise IntegrityError(
                        f"Remote Blob content SHA-256 mismatch for "
                        f"'{normalized_blob_path}'."
                    )

            logger.info(
                "Remote Blob integrity verification passed for '%s'.",
                normalized_blob_path,
            )

            return True

        except (IntegrityError, SecurityValidationError):
            raise

        except AzureError as exc:
            logger.error(
                "Azure API verification failed for remote Blob."
            )
            raise IntegrityError(
                "Azure Blob remote verification failed."
            ) from exc

    def blob_exists(self, blob_path: str) -> bool:
        """Return whether a Blob exists without exposing Azure error details."""

        normalized_blob_path = self._validate_blob_path(blob_path)

        blob_client = self.container_client.get_blob_client(
            normalized_blob_path
        )

        try:
            blob_client.get_blob_properties()
            return True

        except AzureError as exc:
            error_text = self._sanitize_error(exc)

            if "404" in error_text or "not found" in error_text.lower():
                return False

            raise IntegrityError(
                "Unable to determine remote Blob existence."
            ) from exc