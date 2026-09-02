"""Secure Azure Blob Storage integration for Tableau DR artifacts."""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import re
from pathlib import Path
from typing import Any, Iterable

from azure.core.exceptions import AzureError, ResourceNotFoundError
from azure.core.pipeline.policies import ExponentialRetry
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

from tableau_dr.exceptions import IntegrityError, SecurityValidationError


logger = logging.getLogger(__name__)

SHA256_LENGTH = 64
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 0.8
HASH_BLOCK_SIZE = 64 * 1024

MAX_BLOB_PATH_LENGTH = 1024

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
        """
        Initialize an Azure Blob client using managed/default credentials.

        No storage keys, SAS tokens, or connection strings are accepted.
        Authentication is delegated to DefaultAzureCredential.
        """

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
            self.credential = DefaultAzureCredential(
                exclude_interactive_browser_credential=True,
            )

            retry_policy = ExponentialRetry(
                initial_backoff=float(backoff_factor),
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
                "Azure Blob client initialization failed."
            )

            raise SecurityValidationError(
                "Azure Blob Storage initialization failed."
            ) from exc

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_name(
        value: str,
        description: str,
    ) -> str:
        """Validate a required Azure resource name."""

        if not isinstance(value, str):
            raise ValueError(
                f"{description} must be a string."
            )

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                f"{description} must be a non-empty string."
            )

        if len(normalized) > 255:
            raise ValueError(
                f"{description} is too long."
            )

        return normalized

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

    @classmethod
    def validate_blob_path(
        cls,
        blob_path: str,
    ) -> str:
        """
        Validate and normalize an Azure Blob object path.

        Prevents:
        - absolute paths
        - traversal components
        - null bytes
        - empty path components
        - excessively long paths
        """

        if not isinstance(blob_path, str):
            raise SecurityValidationError(
                "Blob path must be a string."
            )

        normalized = blob_path.strip().replace(
            "\\",
            "/",
        )

        if not normalized:
            raise SecurityValidationError(
                "Blob path must not be empty."
            )

        if len(normalized) > MAX_BLOB_PATH_LENGTH:
            raise SecurityValidationError(
                "Blob path is too long."
            )

        if "\x00" in normalized:
            raise SecurityValidationError(
                "Blob path contains an invalid null character."
            )

        if normalized.startswith("/"):
            raise SecurityValidationError(
                "Blob path must not begin with '/'."
            )

        if ":" in normalized:
            raise SecurityValidationError(
                "Drive-qualified blob paths are not permitted."
            )

        parts = normalized.split("/")

        if any(
            part in {"", ".", ".."}
            for part in parts
        ):
            raise SecurityValidationError(
                "Blob path contains an invalid path component."
            )

        return normalized

    @classmethod
    def _validate_blob_path(
        cls,
        blob_path: str,
    ) -> str:
        """
        Backward-compatible private wrapper.

        Internal callers may continue using the private method,
        while new callers should use validate_blob_path().
        """

        return cls.validate_blob_path(blob_path)

    @classmethod
    def validate_sha256(
        cls,
        checksum: str,
    ) -> str:
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

    @classmethod
    def _validate_sha256(
        cls,
        checksum: str,
    ) -> str:
        """Backward-compatible private wrapper."""

        return cls.validate_sha256(checksum)

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    @staticmethod
    def _sanitize_error(
        value: object,
    ) -> str:
        """Remove common secret-like values from Azure error text."""

        text = str(value)

        return _SECRET_PATTERN.sub(
            lambda match: (
                f"{match.group(1)}=[REDACTED]"
            ),
            text,
        )

    # ------------------------------------------------------------------
    # Blob access helpers
    # ------------------------------------------------------------------

    def _get_blob_client(
        self,
        blob_path: str,
    ):
        """Return a validated BlobClient."""

        normalized_blob_path = (
            self.validate_blob_path(
                blob_path
            )
        )

        return self.container_client.get_blob_client(
            normalized_blob_path
        )

    def get_blob_properties(
        self,
        blob_path: str,
    ):
        """
        Retrieve remote Blob properties.

        Azure errors are intentionally wrapped to avoid exposing
        infrastructure details to higher layers.
        """

        blob_client = self._get_blob_client(
            blob_path
        )

        try:
            return blob_client.get_blob_properties()

        except ResourceNotFoundError as exc:
            raise IntegrityError(
                "Remote recovery artifact was not found."
            ) from exc

        except AzureError as exc:
            logger.error(
                "Azure API failed while retrieving Blob properties."
            )

            raise IntegrityError(
                "Unable to retrieve remote Blob properties."
            ) from exc

    def download_blob_stream(
        self,
        blob_path: str,
    ):
        """
        Return an Azure download stream.

        The caller is responsible for enforcing any application-specific
        maximum streaming size.
        """

        blob_client = self._get_blob_client(
            blob_path
        )

        try:
            return blob_client.download_blob()

        except ResourceNotFoundError as exc:
            raise IntegrityError(
                "Remote recovery artifact was not found."
            ) from exc

        except AzureError as exc:
            logger.error(
                "Azure API failed while starting Blob download."
            )

            raise IntegrityError(
                "Unable to download remote Blob."
            ) from exc

    def list_blobs(
        self,
        prefix: str | None = None,
    ) -> Iterable[Any]:
        """
        List Blob objects from the configured container.

        The optional prefix is validated before being sent to Azure.
        """

        normalized_prefix: str | None = None

        if prefix is not None:
            normalized_prefix = (
                self.validate_blob_path(prefix)
            )

        try:
            return self.container_client.list_blobs(
                name_starts_with=normalized_prefix,
            )

        except AzureError as exc:
            logger.error(
                "Azure Blob listing failed."
            )

            raise IntegrityError(
                "Unable to list recovery Blobs."
            ) from exc

    # ------------------------------------------------------------------
    # Upload
    # ------------------------------------------------------------------

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

        file_path = Path(
            local_path
        )

        normalized_blob_path = (
            self.validate_blob_path(
                blob_path
            )
        )

        expected_sha256 = (
            self.validate_sha256(
                sha256_checksum
            )
        )

        if not file_path.exists():
            raise FileNotFoundError(
                f"Local artifact does not exist: {file_path}"
            )

        if not file_path.is_file():
            raise SecurityValidationError(
                "Local artifact is not a regular file."
            )

        try:
            file_size = file_path.stat().st_size

        except OSError as exc:
            raise SecurityValidationError(
                "Unable to determine artifact size."
            ) from exc

        if file_size <= 0:
            raise SecurityValidationError(
                "Refusing to upload empty artifact."
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
            with file_path.open(
                "rb"
            ) as data:
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

    # ------------------------------------------------------------------
    # Remote verification
    # ------------------------------------------------------------------

    def verify_remote_blob(
        self,
        blob_path: str,
        expected_size_bytes: int,
        expected_sha256: str,
        verify_content_stream: bool = False,
    ) -> bool:
        """
        Verify remote Blob size and SHA-256 metadata.

        Optional full content streaming verification calculates the SHA-256
        of the actual remote object.
        """

        normalized_blob_path = (
            self.validate_blob_path(
                blob_path
            )
        )

        expected_sha256 = (
            self.validate_sha256(
                expected_sha256
            )
        )

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
            properties = (
                blob_client.get_blob_properties()
            )

            actual_size = properties.size

            if actual_size != expected_size_bytes:
                raise IntegrityError(
                    "Remote Blob size does not match expected size."
                )

            remote_metadata = (
                properties.metadata or {}
            )

            remote_sha256 = (
                remote_metadata
                .get("sha256", "")
                .strip()
                .lower()
            )

            if not remote_sha256:
                raise SecurityValidationError(
                    "Remote Blob is missing SHA-256 metadata."
                )

            try:
                remote_sha256 = (
                    self.validate_sha256(
                        remote_sha256
                    )
                )

            except SecurityValidationError as exc:
                raise SecurityValidationError(
                    "Remote Blob contains invalid SHA-256 metadata."
                ) from exc

            if not hmac.compare_digest(
                remote_sha256,
                expected_sha256,
            ):
                raise IntegrityError(
                    "Remote Blob SHA-256 metadata mismatch."
                )

            metadata_size = (
                remote_metadata.get(
                    "size_bytes"
                )
            )

            if metadata_size is not None:
                try:
                    parsed_metadata_size = int(
                        metadata_size
                    )

                except (TypeError, ValueError) as exc:
                    raise SecurityValidationError(
                        "Remote Blob contains invalid size metadata."
                    ) from exc

                if parsed_metadata_size != expected_size_bytes:
                    raise IntegrityError(
                        "Remote Blob metadata size mismatch."
                    )

            if verify_content_stream:
                logger.info(
                    "Performing full content SHA-256 verification."
                )

                download_stream = (
                    blob_client.download_blob()
                )

                actual_content_sha256 = (
                    self._hash_stream(
                        download_stream
                    )
                )

                if not hmac.compare_digest(
                    actual_content_sha256,
                    expected_sha256,
                ):
                    raise IntegrityError(
                        "Remote Blob content SHA-256 mismatch."
                    )

            logger.info(
                "Remote Blob integrity verification passed."
            )

            return True

        except (
            IntegrityError,
            SecurityValidationError,
        ):
            raise

        except ResourceNotFoundError as exc:
            raise IntegrityError(
                "Remote Blob was not found."
            ) from exc

        except AzureError as exc:
            logger.error(
                "Azure API verification failed for remote Blob."
            )

            raise IntegrityError(
                "Azure Blob remote verification failed."
            ) from exc

    # ------------------------------------------------------------------
    # Existence
    # ------------------------------------------------------------------

    def blob_exists(
        self,
        blob_path: str,
    ) -> bool:
        """Return whether a Blob exists."""

        normalized_blob_path = (
            self.validate_blob_path(
                blob_path
            )
        )

        blob_client = (
            self.container_client.get_blob_client(
                normalized_blob_path
            )
        )

        try:
            blob_client.get_blob_properties()

            return True

        except ResourceNotFoundError:
            return False

        except AzureError as exc:
            error_text = (
                self._sanitize_error(
                    exc
                )
            )

            logger.error(
                "Azure Blob existence check failed: %s",
                error_text[:500],
            )

            raise IntegrityError(
                "Unable to determine remote Blob existence."
            ) from exc

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_stream(
        stream,
    ) -> str:
        """Calculate SHA-256 from an Azure download stream."""

        digest = hashlib.sha256()

        for chunk in stream.chunks(
            chunk_size=HASH_BLOCK_SIZE
        ):
            if chunk:
                digest.update(
                    chunk
                )

        return digest.hexdigest()