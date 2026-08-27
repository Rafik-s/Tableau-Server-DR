"""Azure Blob Storage integration using DefaultAzureCredential and explicit retry backoff."""

from __future__ import annotations

import hmac
import logging
from pathlib import Path

from azure.core.exceptions import AzureError
from azure.core.pipeline.policies import ExponentialRetry
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

from tableau_dr.exceptions import SecurityValidationError, ValidationError

logger = logging.getLogger(__name__)


class AzureManager:
    """Manages cloud backup persistence with SHA-256 integrity verification."""

    def __init__(
        self,
        account_name: str,
        container_name: str,
        max_retries: int = 3,
        backoff_factor: float = 0.8,
    ):
        self.account_name = account_name
        self.container_name = container_name
        self.account_url = f"https://{account_name}.blob.core.windows.net"

        try:
            self.credential = DefaultAzureCredential()
            retry_policy = ExponentialRetry(
                initial_backoff=int(backoff_factor * 2),
                max_attempts=max_retries,
                random_jitter_range=1,
            )
            self.service_client = BlobServiceClient(
                account_url=self.account_url,
                credential=self.credential,
                retry_policy=retry_policy,
            )
            self.container_client = self.service_client.get_container_client(container_name)
        except Exception as e:
            logger.error(f"Failed to initialize Azure Blob Client: {e}")
            raise ValidationError(f"Azure authentication initialization failed: {e}") from e

    def upload_file(self, local_path: str | Path, blob_path: str, sha256_checksum: str) -> str:
        file_path = Path(local_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Local file does not exist: {file_path}")

        blob_client = self.container_client.get_blob_client(blob_path)
        metadata = {"sha256": sha256_checksum.lower()}

        logger.info(f"Uploading '{file_path.name}' to remote container...")
        try:
            with open(file_path, "rb") as data:
                blob_client.upload_blob(data, overwrite=True, metadata=metadata)
            return blob_path
        except AzureError as e:
            logger.error(f"Azure Blob upload failed for '{blob_path}': {e}")
            raise ValidationError(f"Azure Blob upload failure for {blob_path}: {e}") from e

    def verify_remote_blob(
        self,
        blob_path: str,
        expected_size_bytes: int,
        expected_sha256: str,
        verify_content_stream: bool = False,
    ) -> bool:
        try:
            blob_client = self.container_client.get_blob_client(blob_path)
            properties = blob_client.get_blob_properties()

            if properties.size != expected_size_bytes:
                raise SecurityValidationError(
                    f"Remote blob size mismatch for '{blob_path}'. "
                    f"Expected: {expected_size_bytes} | Actual: {properties.size}"
                )

            remote_metadata = properties.metadata or {}
            remote_sha256 = remote_metadata.get("sha256", "").lower()

            if not remote_sha256:
                raise SecurityValidationError(f"Remote blob '{blob_path}' is missing SHA-256 metadata.")

            if not hmac.compare_digest(remote_sha256, expected_sha256.lower()):
                raise SecurityValidationError(
                    f"Remote metadata SHA-256 mismatch for '{blob_path}'. "
                    f"Expected: {expected_sha256.lower()} | Actual: {remote_sha256}"
                )

            if verify_content_stream:
                logger.info(f"Executing full stream checksum validation for '{blob_path}'...")
                download_stream = blob_client.download_blob()
                import hashlib
                digest = hashlib.sha256()
                for chunk in download_stream.chunks():
                    digest.update(chunk)
                stream_sha256 = digest.hexdigest()

                if not hmac.compare_digest(stream_sha256.lower(), expected_sha256.lower()):
                    raise SecurityValidationError(
                        f"Stream content SHA-256 re-hash mismatch for '{blob_path}'!"
                    )

            logger.info(f"[PASS] Remote Blob Verified: '{blob_path}'")
            return True

        except AzureError as e:
            logger.error(f"Azure API call failed during blob verification: {e}")
            raise ValidationError(f"Remote verification API failure: {e}") from e