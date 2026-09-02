"""
Secure Azure Blob Storage integration for Tableau DR artifacts.

Authentication uses DefaultAzureCredential only. Storage account keys,
connection strings, and SAS tokens are intentionally not supported.

All uploaded recovery artifacts carry SHA-256 and size metadata and can
optionally be verified by streaming the complete remote object.
"""

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

from tableau_dr.exceptions import (
    IntegrityError,
    SecurityValidationError,
)


logger = logging.getLogger(__name__)


SHA256_LENGTH = 64
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 0.8
HASH_BLOCK_SIZE = 64 * 1024

MAX_BLOB_PATH_LENGTH = 1024
MAX_BLOB_SIZE_BYTES = 1 * 1024 * 1024 * 1024 * 1024  # 1 TiB


_SECRET_PATTERN = re.compile(
    r"(?i)(password|passwd|passphrase|secret|token|"
    r"access[-_ ]?token|client[-_ ]?secret|sas[-_ ]?token)"
    r"\s*[:=]\s*[^\s,;]+"
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
        Initialize Azure Blob Storage using managed/default identity.

        No storage account keys, SAS tokens, or connection strings are
        accepted by this class.
        """

        self.account_name = (
            self._validate_storage_account_name(
                account_name
            )
        )

        self.container_name = (
            self._validate_container_name(
                container_name
            )
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
                initial_backoff=float(
                    backoff_factor
                ),
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
    # Azure resource validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_storage_account_name(
        value: str,
    ) -> str:
        """Validate an Azure Storage Account name."""

        if not isinstance(
            value,
            str,
        ):
            raise SecurityValidationError(
                "Azure storage account name must be a string."
            )

        normalized = value.strip()

        if not (
            3 <= len(normalized) <= 24
        ):
            raise SecurityValidationError(
                "Azure storage account name length is invalid."
            )

        if normalized != normalized.lower():
            raise SecurityValidationError(
                "Azure storage account name must use lowercase characters."
            )

        if not normalized.isalnum():
            raise SecurityValidationError(
                "Azure storage account name must contain only "
                "letters and numbers."
            )

        return normalized

    @staticmethod
    def _validate_container_name(
        value: str,
    ) -> str:
        """Validate an Azure Blob container name."""

        if not isinstance(
            value,
            str,
        ):
            raise SecurityValidationError(
                "Azure container name must be a string."
            )

        normalized = value.strip()

        if not (
            3 <= len(normalized) <= 63
        ):
            raise SecurityValidationError(
                "Azure container name length is invalid."
            )

        if (
            normalized.startswith("-")
            or normalized.endswith("-")
            or "--" in normalized
        ):
            raise SecurityValidationError(
                "Azure container name has invalid hyphen placement."
            )

        if not all(
            character.islower()
            or character.isdigit()
            or character == "-"
            for character in normalized
        ):
            raise SecurityValidationError(
                "Azure container name contains invalid characters."
            )

        return normalized

    @staticmethod
    def _validate_retry_configuration(
        max_retries: int,
        backoff_factor: float,
    ) -> None:
        """Validate Azure retry configuration."""

        if (
            isinstance(max_retries, bool)
            or not isinstance(max_retries, int)
            or max_retries < 1
        ):
            raise SecurityValidationError(
                "max_retries must be an integer greater than zero."
            )

        if (
            isinstance(backoff_factor, bool)
            or not isinstance(
                backoff_factor,
                (int, float),
            )
            or not math.isfinite(
                float(backoff_factor)
            )
            or backoff_factor <= 0
        ):
            raise SecurityValidationError(
                "backoff_factor must be a finite number greater than zero."
            )

    # ------------------------------------------------------------------
    # Blob path validation
    # ------------------------------------------------------------------

    @classmethod
    def validate_blob_path(
        cls,
        blob_path: str,
    ) -> str:
        """
        Validate and normalize a complete Azure Blob object path.

        Prevents:
            - absolute paths
            - traversal components
            - null bytes
            - empty path components
            - drive-qualified paths
            - excessively long paths
        """

        if not isinstance(
            blob_path,
            str,
        ):
            raise SecurityValidationError(
                "Blob path must be a string."
            )

        normalized = (
            blob_path
            .strip()
            .replace(
                "\\",
                "/",
            )
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
            part in {
                "",
                ".",
                "..",
            }
            for part in parts
        ):
            raise SecurityValidationError(
                "Blob path contains an invalid path component."
            )

        if any(
            ord(character) < 32
            or ord(character) == 127
            for character in normalized
        ):
            raise SecurityValidationError(
                "Blob path contains invalid control characters."
            )

        return normalized

    @classmethod
    def _validate_blob_path(
        cls,
        blob_path: str,
    ) -> str:
        """Backward-compatible private blob-path validator."""

        return cls.validate_blob_path(
            blob_path
        )

    @classmethod
    def _validate_blob_prefix(
        cls,
        prefix: str,
    ) -> str:
        """
        Validate a Blob listing prefix.

        Unlike a complete Blob path, a prefix may intentionally end with
        '/' because Azure uses it as a name filter.
        """

        if not isinstance(
            prefix,
            str,
        ):
            raise SecurityValidationError(
                "Blob prefix must be a string."
            )

        normalized = (
            prefix
            .strip()
            .replace(
                "\\",
                "/",
            )
        )

        if not normalized:
            raise SecurityValidationError(
                "Blob prefix must not be empty."
            )

        if len(normalized) > MAX_BLOB_PATH_LENGTH:
            raise SecurityValidationError(
                "Blob prefix is too long."
            )

        if normalized.startswith("/"):
            raise SecurityValidationError(
                "Blob prefix must not begin with '/'."
            )

        if ":" in normalized:
            raise SecurityValidationError(
                "Drive-qualified Blob prefixes are not permitted."
            )

        if "\x00" in normalized:
            raise SecurityValidationError(
                "Blob prefix contains an invalid null character."
            )

        if any(
            ord(character) < 32
            or ord(character) == 127
            for character in normalized
        ):
            raise SecurityValidationError(
                "Blob prefix contains invalid control characters."
            )

        # Prefixes may end with '/', but internal empty components and
        # traversal components remain forbidden.
        parts = normalized.split("/")

        for index, part in enumerate(parts):
            if index == len(parts) - 1 and part == "":
                continue

            if part in {
                "",
                ".",
                "..",
            }:
                raise SecurityValidationError(
                    "Blob prefix contains an invalid path component."
                )

        return normalized

    # ------------------------------------------------------------------
    # SHA-256 validation
    # ------------------------------------------------------------------

    @classmethod
    def validate_sha256(
        cls,
        checksum: str,
    ) -> str:
        """Validate and normalize a SHA-256 hexadecimal digest."""

        if not isinstance(
            checksum,
            str,
        ):
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
        """Backward-compatible private SHA-256 validator."""

        return cls.validate_sha256(
            checksum
        )

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    @staticmethod
    def _sanitize_error(
        value: object,
    ) -> str:
        """Remove common secret-like values from error text."""

        text = str(value)

        return _SECRET_PATTERN.sub(
            lambda match: (
                f"{match.group(1)}=[REDACTED]"
            ),
            text,
        )

    # ------------------------------------------------------------------
    # Blob client helpers
    # ------------------------------------------------------------------

    def _get_blob_client(
        self,
        blob_path: str,
    ):
        """Return a BlobClient for a validated object path."""

        normalized_blob_path = (
            self.validate_blob_path(
                blob_path
            )
        )

        return self.container_client.get_blob_client(
            normalized_blob_path
        )

    # ------------------------------------------------------------------
    # Remote metadata
    # ------------------------------------------------------------------

    def get_blob_properties(
        self,
        blob_path: str,
    ):
        """Retrieve remote Blob properties safely."""

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

    # ------------------------------------------------------------------
    # Remote streaming
    # ------------------------------------------------------------------

    def download_blob_stream(
        self,
        blob_path: str,
    ):
        """
        Return an Azure download stream.

        Application-level callers are responsible for enforcing their
        own streaming size limits.
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

    # ------------------------------------------------------------------
    # Blob listing
    # ------------------------------------------------------------------

    def list_blobs(
        self,
        prefix: str | None = None,
    ) -> Iterable[Any]:
        """List Blobs using an optionally validated prefix."""

        normalized_prefix: str | None = None

        if prefix is not None:
            normalized_prefix = (
                self._validate_blob_prefix(
                    prefix
                )
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
        Upload a local artifact and store SHA-256 and size metadata.

        Existing objects may be overwritten because the backup manager
        generates run-specific Blob paths.
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
                "Local artifact does not exist."
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

        if file_size > MAX_BLOB_SIZE_BYTES:
            raise SecurityValidationError(
                "Local artifact exceeds the maximum supported size."
            )

        blob_client = (
            self.container_client.get_blob_client(
                normalized_blob_path
            )
        )

        metadata = {
            "sha256": expected_sha256,
            "size_bytes": str(
                file_size
            ),
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

        When verify_content_stream is True, the complete remote Blob is
        streamed and independently hashed.
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
            isinstance(
                expected_size_bytes,
                bool,
            )
            or not isinstance(
                expected_size_bytes,
                int,
            )
            or expected_size_bytes < 0
        ):
            raise SecurityValidationError(
                "expected_size_bytes must be a non-negative integer."
            )

        if expected_size_bytes > MAX_BLOB_SIZE_BYTES:
            raise SecurityValidationError(
                "expected_size_bytes exceeds the maximum supported size."
            )

        blob_client = (
            self.container_client.get_blob_client(
                normalized_blob_path
            )
        )

        try:
            properties = (
                blob_client.get_blob_properties()
            )

            actual_size = properties.size

            if (
                not isinstance(
                    actual_size,
                    int,
                )
                or actual_size < 0
            ):
                raise IntegrityError(
                    "Remote Blob reported an invalid size."
                )

            if actual_size > MAX_BLOB_SIZE_BYTES:
                raise IntegrityError(
                    "Remote Blob exceeds the maximum supported size."
                )

            if actual_size != expected_size_bytes:
                raise IntegrityError(
                    "Remote Blob size does not match expected size."
                )

            remote_metadata = (
                properties.metadata or {}
            )

            remote_sha256 = (
                remote_metadata
                .get(
                    "sha256",
                    "",
                )
            )

            if not isinstance(
                remote_sha256,
                str,
            ):
                raise SecurityValidationError(
                    "Remote Blob SHA-256 metadata is invalid."
                )

            remote_sha256 = (
                remote_sha256
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

            if metadata_size is None:
                raise SecurityValidationError(
                    "Remote Blob is missing size metadata."
                )

            try:
                parsed_metadata_size = int(
                    metadata_size
                )

            except (
                TypeError,
                ValueError,
            ) as exc:
                raise SecurityValidationError(
                    "Remote Blob contains invalid size metadata."
                ) from exc

            if (
                parsed_metadata_size
                != expected_size_bytes
            ):
                raise IntegrityError(
                    "Remote Blob metadata size mismatch."
                )

            if verify_content_stream:
                logger.info(
                    "Performing full remote content SHA-256 verification."
                )

                download_stream = (
                    blob_client.download_blob()
                )

                actual_content_sha256 = (
                    self._hash_stream(
                        download_stream,
                        expected_size_bytes,
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
        expected_size_bytes: int | None = None,
    ) -> str:
        """
        Calculate SHA-256 from an Azure download stream.

        If an expected size is supplied, the stream is fail-closed if
        more data than expected is returned.
        """

        digest = hashlib.sha256()
        total_bytes = 0

        for chunk in stream.chunks(
            chunk_size=HASH_BLOCK_SIZE
        ):
            if not chunk:
                continue

            total_bytes += len(chunk)

            if (
                expected_size_bytes is not None
                and total_bytes > expected_size_bytes
            ):
                raise IntegrityError(
                    "Remote Blob stream exceeded expected size."
                )

            digest.update(chunk)

        if (
            expected_size_bytes is not None
            and total_bytes != expected_size_bytes
        ):
            raise IntegrityError(
                "Remote Blob stream size does not match expected size."
            )

        return digest.hexdigest()