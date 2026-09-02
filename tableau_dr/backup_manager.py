"""
Enterprise Tableau Server Disaster Recovery backup orchestrator.

Backup workflow:

    BACKUP_STARTED
        -> PREFLIGHT_PASSED
        -> SETTINGS_EXPORTED
        -> BACKUP_CREATED
        -> ARTIFACTS_VALIDATED
        -> MANIFEST_CREATED
        -> AZURE_UPLOADED
        -> REMOTE_VERIFIED
        -> LOCAL_CLEANUP
        -> BACKUP_COMPLETED

Security principles:
- Never upload an artifact that has not passed local validation.
- Calculate SHA-256 before remote persistence.
- Store SHA-256 and size metadata with every Azure Blob artifact.
- Verify every uploaded Blob before declaring backup success.
- Never delete local staging before remote verification succeeds.
- Preserve failed staging data for incident investigation.
- Never log secrets or raw subprocess output.
- Use isolated run-specific workspaces.
- Keep backup and recovery run IDs independent.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import logging
import re
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from azure.core.exceptions import AzureError

from .azure_manager import AzureManager
from .config import Config
from .exceptions import TableauDRError, ValidationError
from .security import sha256_file, validate_file
from .tab_server_connector import TSMConnector
from .validation import validate_disk_space


LOGGER = logging.getLogger(__name__)


class BackupError(TableauDRError):
    """Controlled backup pipeline failure."""


@dataclass
class BackupResult:
    """Structured result returned by the backup workflow."""

    run_id: str
    status: str
    started_at_utc: str
    completed_at_utc: str
    duration_seconds: float
    manifest_path: str
    artifacts: Dict[str, Dict[str, Any]]
    remote_verified: bool
    cleanup_status: str

    def to_dict(self) -> Dict[str, Any]:
        """Return the result as a serializable dictionary."""

        return asdict(self)


class BackupManager:
    """Enterprise fail-closed Tableau Server backup orchestrator."""

    MANIFEST_VERSION = "2.0"
    MANIFEST_STATUS = "ARTIFACTS_READY"

    MAX_MANIFEST_SIZE_BYTES = 10 * 1024 * 1024
    MAX_ARTIFACT_SIZE_BYTES = 1024 * 1024 * 1024 * 1024

    SHA256_PATTERN = re.compile(
        r"^[a-fA-F0-9]{64}$"
    )

    RUN_ID_PATTERN = re.compile(
        r"^[A-Za-z0-9_.-]+$"
    )

    SAFE_ARTIFACT_NAMES = {
        "backup.tsbak",
        "settings.json",
    }

    def __init__(
        self,
        config: Config,
        run_id: str,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """Initialize the backup pipeline."""

        self.config = config
        self.run_id = self._validate_run_id(run_id)
        self.logger = logger or LOGGER

        self.tsm = TSMConnector(
            config=config,
            logger=self.logger,
        )

        self.azure = AzureManager(
            account_name=config.azure[
                "storage_account_name"
            ],
            container_name=config.azure[
                "storage_container"
            ],
            max_retries=config.azure[
                "max_retries"
            ],
            backoff_factor=config.azure[
                "retry_backoff_factor"
            ],
        )

        self.started_at = dt.datetime.now(
            dt.timezone.utc
        )

        self.timestamp = self.started_at.strftime(
            "%Y%m%dT%H%M%SZ"
        )

        self.run_dir_name = (
            f"{self.timestamp}_{self.run_id}"
        )

        self.backup_root = Path(
            config.paths["backup_dir"]
        ).resolve()

        self.run_work_dir = (
            self.backup_root
            / self.run_dir_name
        )

        self.remote_blob_prefix = (
            f"backups/{self.run_dir_name}"
        )

        self._validate_configuration()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute_backup_pipeline(
        self,
    ) -> BackupResult:
        """
        Execute the complete backup pipeline.

        Local cleanup is performed only after every remote artifact,
        including the manifest, has passed integrity verification.
        """

        pipeline_start = time.monotonic()

        artifacts: Dict[
            str,
            Dict[str, Any],
        ] = {}

        manifest_path: Optional[Path] = None
        manifest_blob_path: Optional[str] = None

        remote_verified = False
        cleanup_status = "SKIPPED"

        try:
            self._run_preflight()

            self._prepare_work_directory()

            self.logger.info(
                "Starting Tableau DR backup pipeline."
            )

            # ----------------------------------------------------------
            # Stage 1 - Export Tableau settings
            # ----------------------------------------------------------

            settings_path = (
                self._export_settings()
            )

            settings_metadata = (
                self._build_artifact_metadata(
                    logical_name="settings.json",
                    local_path=settings_path,
                )
            )

            artifacts[
                "settings.json"
            ] = settings_metadata

            # ----------------------------------------------------------
            # Stage 2 - Create Tableau repository backup
            # ----------------------------------------------------------

            backup_created_at = (
                dt.datetime.now(
                    dt.timezone.utc
                )
            )

            backup_path = (
                self._create_repository_backup()
            )

            backup_metadata = (
                self._build_artifact_metadata(
                    logical_name="backup.tsbak",
                    local_path=backup_path,
                )
            )

            artifacts[
                "backup.tsbak"
            ] = backup_metadata

            # ----------------------------------------------------------
            # Stage 3 - Generate manifest
            # ----------------------------------------------------------

            manifest_path = (
                self._create_manifest(
                    artifacts=artifacts,
                    backup_created_at=backup_created_at,
                    pipeline_start=pipeline_start,
                )
            )

            manifest_sha256 = (
                self._validate_and_hash_manifest(
                    manifest_path
                )
            )

            manifest_blob_path = (
                f"{self.remote_blob_prefix}/"
                f"manifest_{self.timestamp}.json"
            )

            # ----------------------------------------------------------
            # Stage 4 - Upload artifacts
            # ----------------------------------------------------------

            self._upload_artifacts(
                artifacts
            )

            self.azure.upload_file(
                local_path=manifest_path,
                blob_path=manifest_blob_path,
                sha256_checksum=manifest_sha256,
            )

            # ----------------------------------------------------------
            # Stage 5 - Verify remote artifacts
            # ----------------------------------------------------------

            self._verify_remote_artifacts(
                artifacts
            )

            self.azure.verify_remote_blob(
                blob_path=manifest_blob_path,
                expected_size_bytes=manifest_path.stat().st_size,
                expected_sha256=manifest_sha256,
                verify_content_stream=self._remote_content_verification_enabled(),
            )

            remote_verified = True

            # ----------------------------------------------------------
            # Stage 6 - Cleanup
            # ----------------------------------------------------------

            cleanup_status = (
                self._execute_local_cleanup()
            )

            completed_at = (
                dt.datetime.now(
                    dt.timezone.utc
                )
            )

            duration = (
                time.monotonic()
                - pipeline_start
            )

            self.logger.info(
                "Tableau DR backup completed successfully."
            )

            return BackupResult(
                run_id=self.run_id,
                status="SUCCESS",
                started_at_utc=(
                    self.started_at.isoformat()
                ),
                completed_at_utc=(
                    completed_at.isoformat()
                ),
                duration_seconds=round(
                    duration,
                    3,
                ),
                manifest_path=manifest_blob_path,
                artifacts=(
                    self._public_artifact_metadata(
                        artifacts
                    )
                ),
                remote_verified=remote_verified,
                cleanup_status=cleanup_status,
            )

        except Exception as exc:
            self._preserve_failed_workspace()

            self.logger.error(
                "Tableau DR backup pipeline failed; "
                "local staging workspace preserved."
            )

            if isinstance(
                exc,
                TableauDRError,
            ):
                raise

            raise BackupError(
                "Backup execution failed."
            ) from exc

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_run_id(
        run_id: str,
    ) -> str:
        """Validate the backup execution identifier."""

        if not isinstance(
            run_id,
            str,
        ):
            raise ValueError(
                "run_id must be a string."
            )

        value = run_id.strip()

        if not value:
            raise ValueError(
                "run_id cannot be empty."
            )

        if len(value) > 128:
            raise ValueError(
                "run_id is too long."
            )

        if not BackupManager.RUN_ID_PATTERN.fullmatch(
            value
        ):
            raise ValueError(
                "run_id contains invalid characters."
            )

        return value

    def _validate_configuration(
        self,
    ) -> None:
        """Validate backup-specific configuration assumptions."""

        backup_dir = str(
            self.config.paths[
                "backup_dir"
            ]
        ).strip()

        if not backup_dir:
            raise BackupError(
                "Backup directory is not configured."
            )

        production = (
            self.config.servers[
                "production"
            ]
        )

        if not str(
            production["hostname"]
        ).strip():
            raise BackupError(
                "Production hostname is not configured."
            )

        if not str(
            self.config.environment[
                "version"
            ]
        ).strip():
            raise BackupError(
                "Tableau version is not configured."
            )

        minimum_size = float(
            self.config.backup[
                "minimum_backup_size_mb"
            ]
        )

        if minimum_size <= 0:
            raise BackupError(
                "minimum_backup_size_mb must be greater than zero."
            )

        minimum_free = float(
            self.config.backup[
                "minimum_free_space_gb"
            ]
        )

        if minimum_free <= 0:
            raise BackupError(
                "minimum_free_space_gb must be greater than zero."
            )

    # ------------------------------------------------------------------
    # Stage 0 - Preflight
    # ------------------------------------------------------------------

    def _run_preflight(
        self,
    ) -> None:
        """Validate disk capacity and Tableau Server availability."""

        required_free_gb = float(
            self.config.backup[
                "minimum_free_space_gb"
            ]
        )

        validate_disk_space(
            self.config.paths[
                "backup_dir"
            ],
            required_gb=required_free_gb,
        )

        status_result = (
            self.tsm.status()
        )

        if not status_result.success:
            raise ValidationError(
                "Unable to verify Tableau Server "
                "status before backup."
            )

    # ------------------------------------------------------------------
    # Stage 1 - Work directory
    # ------------------------------------------------------------------

    def _prepare_work_directory(
        self,
    ) -> None:
        """Create an isolated run-specific staging directory."""

        self.backup_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        if self.run_work_dir.exists():
            raise BackupError(
                "Backup staging directory already exists."
            )

        self.run_work_dir.mkdir(
            parents=True,
            exist_ok=False,
        )

    # ------------------------------------------------------------------
    # Stage 2 - Settings export
    # ------------------------------------------------------------------

    def _export_settings(
        self,
    ) -> Path:
        """Export Tableau Server settings into the isolated workspace."""

        settings_path = (
            self.run_work_dir
            / "settings.json"
        )

        if settings_path.exists():
            raise BackupError(
                "Settings target already exists."
            )

        result = self.tsm.export_settings(
            str(settings_path)
        )

        if not result.success:
            raise BackupError(
                "Tableau settings export failed."
            )

        try:
            validate_file(
                settings_path,
                must_exist=True,
            )
        except Exception as exc:
            raise BackupError(
                "Exported Tableau settings failed validation."
            ) from exc

        if settings_path.stat().st_size <= 0:
            raise BackupError(
                "Exported Tableau settings file is empty."
            )

        return settings_path

    # ------------------------------------------------------------------
    # Stage 3 - Repository backup
    # ------------------------------------------------------------------

    def _create_repository_backup(
        self,
    ) -> Path:
        """Create the Tableau repository/File Store backup."""

        target_path = (
            self.run_work_dir
            / "backup.tsbak"
        )

        # Tableau's TSM backup command is passed a base path.
        # With append_date=False, the resulting artifact is expected
        # to be backup.tsbak.
        command_path = (
            self.run_work_dir
            / "backup"
        )

        if target_path.exists():
            raise BackupError(
                "Backup target already exists."
            )

        result = self.tsm.create_backup(
            str(command_path),
            append_date=False,
        )

        if not result.success:
            raise BackupError(
                "Tableau repository backup failed."
            )

        minimum_backup_mb = float(
            self.config.backup[
                "minimum_backup_size_mb"
            ]
        )

        try:
            validate_file(
                target_path,
                must_exist=True,
                min_size_mb=minimum_backup_mb,
            )
        except Exception as exc:
            raise BackupError(
                "Created Tableau backup failed local validation."
            ) from exc

        if (
            target_path.stat().st_size
            > self.MAX_ARTIFACT_SIZE_BYTES
        ):
            raise BackupError(
                "Created Tableau backup exceeds maximum "
                "allowed artifact size."
            )

        return target_path

    # ------------------------------------------------------------------
    # Artifact metadata
    # ------------------------------------------------------------------

    def _build_artifact_metadata(
        self,
        *,
        logical_name: str,
        local_path: Path,
    ) -> Dict[str, Any]:
        """Validate an artifact and build trusted manifest metadata."""

        if logical_name not in (
            self.SAFE_ARTIFACT_NAMES
        ):
            raise BackupError(
                "Unsupported backup artifact name."
            )

        local_path = local_path.resolve()

        try:
            local_path.relative_to(
                self.run_work_dir.resolve()
            )
        except ValueError as exc:
            raise BackupError(
                "Backup artifact escapes isolated workspace."
            ) from exc

        if local_path.name != logical_name:
            raise BackupError(
                f"Unexpected artifact filename for {logical_name}."
            )

        if not local_path.is_file():
            raise BackupError(
                f"Backup artifact is not a regular file: "
                f"{logical_name}"
            )

        try:
            size_bytes = (
                local_path.stat().st_size
            )
        except OSError as exc:
            raise BackupError(
                f"Unable to determine artifact size: "
                f"{logical_name}"
            ) from exc

        if size_bytes <= 0:
            raise BackupError(
                f"Artifact is empty: {logical_name}"
            )

        if (
            size_bytes
            > self.MAX_ARTIFACT_SIZE_BYTES
        ):
            raise BackupError(
                f"Artifact exceeds maximum size: "
                f"{logical_name}"
            )

        try:
            checksum = sha256_file(
                local_path
            )
        except Exception as exc:
            raise BackupError(
                f"Unable to calculate SHA-256 for "
                f"{logical_name}"
            ) from exc

        checksum = self._validate_sha256(
            checksum
        )

        blob_path = (
            f"{self.remote_blob_prefix}/"
            f"{logical_name}"
        )

        return {
            "filename": logical_name,
            "size_bytes": size_bytes,
            "sha256": checksum,
            "blob_path": blob_path,
            "local_path": str(local_path),
        }

    # ------------------------------------------------------------------
    # Stage 4 - Manifest
    # ------------------------------------------------------------------

    def _create_manifest(
        self,
        *,
        artifacts: Dict[str, Dict[str, Any]],
        backup_created_at: dt.datetime,
        pipeline_start: float,
    ) -> Path:
        """Create the immutable backup manifest."""

        if not artifacts:
            raise BackupError(
                "Cannot create a manifest without artifacts."
            )

        completed_at = (
            dt.datetime.now(
                dt.timezone.utc
            )
        )

        manifest = {
            "manifest_version": self.MANIFEST_VERSION,
            "run_id": self.run_id,
            "status": self.MANIFEST_STATUS,
            "source": {
                "environment": "production",
                "hostname": (
                    self.config.servers[
                        "production"
                    ]["hostname"]
                ),
                "version": (
                    self.config.environment[
                        "version"
                    ]
                ),
                "identity_store": (
                    self.config.servers[
                        "production"
                    ]["identity_store"]
                ),
            },
            "timing": {
                "started_at_utc": (
                    self.started_at.isoformat()
                ),
                "backup_created_at_utc": (
                    backup_created_at.isoformat()
                ),
                "completed_at_utc": (
                    completed_at.isoformat()
                ),
                "duration_seconds": round(
                    time.monotonic()
                    - pipeline_start,
                    3,
                ),
            },
            "artifacts": {
                "backup.tsbak": (
                    self._manifest_artifact(
                        artifacts[
                            "backup.tsbak"
                        ]
                    )
                ),
                "settings.json": (
                    self._manifest_artifact(
                        artifacts[
                            "settings.json"
                        ]
                    )
                ),
            },
            "remote_storage": {
                "account": (
                    self.config.azure[
                        "storage_account_name"
                    ]
                ),
                "container": (
                    self.config.azure[
                        "storage_container"
                    ]
                ),
                "prefix": (
                    self.remote_blob_prefix
                ),
            },
        }

        manifest_path = (
            self.run_work_dir
            / f"manifest_{self.timestamp}.json"
        )

        if manifest_path.exists():
            raise BackupError(
                "Manifest file already exists."
            )

        try:
            serialized = json.dumps(
                manifest,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )

            encoded = serialized.encode(
                "utf-8"
            )

            if len(encoded) > (
                self.MAX_MANIFEST_SIZE_BYTES
            ):
                raise BackupError(
                    "Generated manifest exceeds maximum size."
                )

            manifest_path.write_bytes(
                encoded
            )

        except OSError as exc:
            raise BackupError(
                "Unable to write backup manifest."
            ) from exc

        self._validate_manifest_structure(
            manifest
        )

        return manifest_path

    @staticmethod
    def _manifest_artifact(
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Return only metadata that belongs in the remote manifest.

        The local filesystem path intentionally remains outside the
        persisted manifest.
        """

        return {
            "filename": metadata[
                "filename"
            ],
            "size_bytes": metadata[
                "size_bytes"
            ],
            "sha256": metadata[
                "sha256"
            ],
            "blob_path": metadata[
                "blob_path"
            ],
        }

    def _validate_manifest_structure(
        self,
        manifest: Dict[str, Any],
    ) -> None:
        """Perform final local validation of generated manifest data."""

        if manifest.get(
            "manifest_version"
        ) != self.MANIFEST_VERSION:
            raise BackupError(
                "Generated manifest version is invalid."
            )

        if manifest.get(
            "status"
        ) != self.MANIFEST_STATUS:
            raise BackupError(
                "Generated manifest status is invalid."
            )

        run_id = manifest.get(
            "run_id"
        )

        if not isinstance(
            run_id,
            str,
        ) or not self.RUN_ID_PATTERN.fullmatch(
            run_id
        ):
            raise BackupError(
                "Generated manifest run_id is invalid."
            )

        source = manifest.get(
            "source"
        )

        if not isinstance(
            source,
            dict,
        ):
            raise BackupError(
                "Generated manifest source section is invalid."
            )

        required_source_fields = {
            "environment",
            "hostname",
            "version",
            "identity_store",
        }

        if not required_source_fields.issubset(
            source
        ):
            raise BackupError(
                "Generated manifest source section is incomplete."
            )

        artifacts = manifest.get(
            "artifacts"
        )

        if not isinstance(
            artifacts,
            dict,
        ):
            raise BackupError(
                "Generated manifest artifacts section is invalid."
            )

        if set(artifacts) != (
            self.SAFE_ARTIFACT_NAMES
        ):
            raise BackupError(
                "Generated manifest contains an unexpected artifact set."
            )

        for logical_name, metadata in artifacts.items():
            if not isinstance(
                metadata,
                dict,
            ):
                raise BackupError(
                    f"Invalid generated metadata: {logical_name}"
                )

            if metadata.get(
                "filename"
            ) != logical_name:
                raise BackupError(
                    f"Generated artifact filename mismatch: "
                    f"{logical_name}"
                )

            self._validate_sha256(
                metadata.get(
                    "sha256"
                )
            )

            size_bytes = metadata.get(
                "size_bytes"
            )

            if (
                isinstance(
                    size_bytes,
                    bool,
                )
                or not isinstance(
                    size_bytes,
                    int,
                )
                or size_bytes <= 0
                or size_bytes > (
                    self.MAX_ARTIFACT_SIZE_BYTES
                )
            ):
                raise BackupError(
                    f"Invalid generated artifact size: "
                    f"{logical_name}"
                )

            blob_path = metadata.get(
                "blob_path"
            )

            if not isinstance(
                blob_path,
                str,
            ):
                raise BackupError(
                    f"Invalid generated blob path: "
                    f"{logical_name}"
                )

            expected_path = (
                f"{self.remote_blob_prefix}/"
                f"{logical_name}"
            )

            if blob_path != expected_path:
                raise BackupError(
                    f"Generated blob path mismatch: "
                    f"{logical_name}"
                )

    def _validate_and_hash_manifest(
        self,
        manifest_path: Path,
    ) -> str:
        """Validate manifest file size and calculate SHA-256."""

        try:
            validate_file(
                manifest_path,
                must_exist=True,
            )
        except Exception as exc:
            raise BackupError(
                "Generated manifest failed file validation."
            ) from exc

        try:
            size_bytes = (
                manifest_path.stat().st_size
            )
        except OSError as exc:
            raise BackupError(
                "Unable to determine manifest size."
            ) from exc

        if size_bytes > (
            self.MAX_MANIFEST_SIZE_BYTES
        ):
            raise BackupError(
                "Manifest exceeds maximum size."
            )

        try:
            checksum = sha256_file(
                manifest_path
            )
        except Exception as exc:
            raise BackupError(
                "Unable to calculate manifest SHA-256."
            ) from exc

        return self._validate_sha256(
            checksum
        )

    # ------------------------------------------------------------------
    # Stage 5 - Azure upload
    # ------------------------------------------------------------------

    def _upload_artifacts(
        self,
        artifacts: Dict[str, Dict[str, Any]],
    ) -> None:
        """Upload all backup artifacts to Azure Blob Storage."""

        for logical_name in (
            "backup.tsbak",
            "settings.json",
        ):
            metadata = artifacts.get(
                logical_name
            )

            if not isinstance(
                metadata,
                dict,
            ):
                raise BackupError(
                    f"Missing artifact metadata: "
                    f"{logical_name}"
                )

            self.azure.upload_file(
                local_path=metadata[
                    "local_path"
                ],
                blob_path=metadata[
                    "blob_path"
                ],
                sha256_checksum=metadata[
                    "sha256"
                ],
            )

    # ------------------------------------------------------------------
    # Stage 6 - Remote verification
    # ------------------------------------------------------------------

    def _verify_remote_artifacts(
        self,
        artifacts: Dict[str, Dict[str, Any]],
    ) -> None:
        """Verify remote size and SHA-256 metadata/content."""

        verify_stream = (
            self._remote_content_verification_enabled()
        )

        for logical_name in (
            "backup.tsbak",
            "settings.json",
        ):
            metadata = artifacts.get(
                logical_name
            )

            if not isinstance(
                metadata,
                dict,
            ):
                raise BackupError(
                    f"Missing artifact metadata: "
                    f"{logical_name}"
                )

            verified = (
                self.azure.verify_remote_blob(
                    blob_path=metadata[
                        "blob_path"
                    ],
                    expected_size_bytes=metadata[
                        "size_bytes"
                    ],
                    expected_sha256=metadata[
                        "sha256"
                    ],
                    verify_content_stream=verify_stream,
                )
            )

            if not verified:
                raise BackupError(
                    f"Remote verification failed: "
                    f"{logical_name}"
                )

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    def _remote_content_verification_enabled(
        self,
    ) -> bool:
        """Return the configured remote content verification setting."""

        return bool(
            self.config.backup[
                "verify_remote_content_sha256"
            ]
        )

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def _execute_local_cleanup(
        self,
    ) -> str:
        """
        Remove local staging only after successful remote verification.

        Cleanup failure does not invalidate the already verified remote
        backup. The caller receives an explicit FAILED cleanup status.
        """

        if not self.run_work_dir.exists():
            return "SUCCESS"

        try:
            shutil.rmtree(
                self.run_work_dir
            )

            self.logger.info(
                "Local backup staging cleanup completed."
            )

            return "SUCCESS"

        except OSError:
            self.logger.warning(
                "Local backup staging cleanup failed; "
                "remote backup remains verified."
            )

            return "FAILED"

    def _preserve_failed_workspace(
        self,
    ) -> None:
        """Preserve failed backup staging data for investigation."""

        if not self.run_work_dir.exists():
            return

        try:
            marker = (
                self.run_work_dir
                / "BACKUP_FAILED"
            )

            marker.write_text(
                (
                    "Backup pipeline failed.\n"
                    "Local staging intentionally preserved "
                    "for incident investigation.\n"
                ),
                encoding="utf-8",
            )

        except OSError:
            self.logger.warning(
                "Unable to create backup failure marker."
            )

    # ------------------------------------------------------------------
    # Security helpers
    # ------------------------------------------------------------------

    @classmethod
    def _validate_sha256(
        cls,
        value: Any,
    ) -> str:
        """Validate a SHA-256 hexadecimal digest."""

        if not isinstance(
            value,
            str,
        ):
            raise BackupError(
                "SHA-256 value must be a string."
            )

        normalized = value.strip().lower()

        if not cls.SHA256_PATTERN.fullmatch(
            normalized
        ):
            raise BackupError(
                "Invalid SHA-256 value."
            )

        return normalized

    @staticmethod
    def _constant_time_equal(
        left: str,
        right: str,
    ) -> bool:
        """Compare two hexadecimal digests in constant time."""

        try:
            left_bytes = bytes.fromhex(
                left
            )

            right_bytes = bytes.fromhex(
                right
            )

        except ValueError:
            return False

        return hmac.compare_digest(
            left_bytes,
            right_bytes,
        )

    # ------------------------------------------------------------------
    # Result sanitization
    # ------------------------------------------------------------------

    @staticmethod
    def _public_artifact_metadata(
        artifacts: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Return artifact metadata without exposing local filesystem paths.
        """

        public: Dict[
            str,
            Dict[str, Any],
        ] = {}

        for logical_name, metadata in artifacts.items():
            public[logical_name] = {
                "filename": metadata[
                    "filename"
                ],
                "size_bytes": metadata[
                    "size_bytes"
                ],
                "sha256": metadata[
                    "sha256"
                ],
                "blob_path": metadata[
                    "blob_path"
                ],
            }

        return public