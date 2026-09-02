"""Enterprise Tableau Server backup orchestration with integrity-first persistence."""

from __future__ import annotations

import datetime
import json
import logging
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict

from tableau_dr.azure_manager import AzureManager
from tableau_dr.config import Config
from tableau_dr.exceptions import IntegrityError, TableauDRError, ValidationError
from tableau_dr.security import sha256_file, validate_file
from tableau_dr.tab_server_connector import TSMConnector
from tableau_dr.validation import validate_disk_space


logger = logging.getLogger(__name__)

MANIFEST_VERSION = "2.0"
MANIFEST_STATUS = "ARTIFACTS_READY"

SETTINGS_KEY = "settings.json"
BACKUP_KEY = "backup.tsbak"

DEFAULT_MIN_BACKUP_SIZE_MB = 10.0
DEFAULT_MIN_FREE_SPACE_GB = 50.0


@dataclass
class BackupResult:
    """Final result of a completed or failed backup pipeline."""

    run_id: str
    status: str
    started_at_utc: str
    completed_at_utc: str
    duration_seconds: float
    manifest_path: str
    artifacts: Dict[str, dict]
    remote_verified: bool
    cleanup_status: str

    def to_dict(self) -> dict:
        """Return a JSON-serializable representation."""

        return asdict(self)


class BackupManager:
    """
    Execute the complete Tableau Server backup pipeline.

    Pipeline:

        Preflight
            ↓
        Settings Export
            ↓
        TSM Backup
            ↓
        Local Validation + SHA-256
            ↓
        Manifest Generation
            ↓
        Azure Upload
            ↓
        Remote Integrity Verification
            ↓
        Retention Cleanup

    Cleanup is fail-closed: local staging is removed only after every
    required artifact and the manifest have been successfully uploaded
    and remotely verified.
    """

    def __init__(self, config: Config, run_id: str) -> None:
        """Initialize backup dependencies and an isolated run directory."""

        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id must be a non-empty string.")

        self.config = config
        self.run_id = run_id.strip()

        yaml_executable = (
            config.tsm.get("executable")
            if config.tsm
            else None
        )

        self.tsm = TSMConnector(
            yaml_executable=yaml_executable,
        )

        azure_cfg = config.azure

        self.azure = AzureManager(
            account_name=azure_cfg["storage_account_name"],
            container_name=azure_cfg["storage_container"],
            max_retries=azure_cfg.get("max_retries", 3),
            backoff_factor=azure_cfg.get(
                "retry_backoff_factor",
                0.8,
            ),
        )

        self.started_at_dt = datetime.datetime.now(
            datetime.timezone.utc
        )

        self.timestamp_str = self.started_at_dt.strftime(
            "%Y%m%dT%H%M%SZ"
        )

        self.run_dir_name = (
            f"{self.timestamp_str}_{self.run_id}"
        )

        base_backup_dir = Path(
            config.paths["backup_dir"]
        ).expanduser()

        self.run_work_dir = (
            base_backup_dir / self.run_dir_name
        )

    def execute_backup_pipeline(self) -> BackupResult:
        """Execute the complete backup, upload, verification, and cleanup workflow."""

        pipeline_start = time.monotonic()

        logger.info(
            "Starting Tableau DR backup pipeline. run_id=%s",
            self.run_id,
        )

        self._run_preflight()

        self.run_work_dir.mkdir(
            parents=True,
            exist_ok=False,
        )

        local_artifacts: Dict[str, dict] = {}
        remote_blob_prefix = (
            f"backups/{self.run_dir_name}"
        )

        remote_verified = False
        cleanup_status = "SKIPPED"

        manifest_path: Path | None = None

        try:
            # ---------------------------------------------------------
            # 1. Export Tableau Server settings
            # ---------------------------------------------------------
            settings_filename = (
                f"tableau_settings_{self.timestamp_str}.json"
            )

            settings_path = (
                self.run_work_dir / settings_filename
            )

            logger.info(
                "Exporting Tableau Server settings."
            )

            self.tsm.export_settings(
                str(settings_path)
            )

            validate_file(
                settings_path,
                must_exist=True,
            )

            settings_size = settings_path.stat().st_size
            settings_sha256 = sha256_file(settings_path)

            local_artifacts[SETTINGS_KEY] = (
                self._build_artifact_metadata(
                    logical_name=SETTINGS_KEY,
                    local_path=settings_path,
                    blob_path=(
                        f"{remote_blob_prefix}/"
                        f"{settings_filename}"
                    ),
                    sha256=settings_sha256,
                    size_bytes=settings_size,
                )
            )

            # ---------------------------------------------------------
            # 2. Create Tableau Server repository backup
            # ---------------------------------------------------------
            backup_filename = (
                f"tableau_backup_{self.timestamp_str}.tsbak"
            )

            backup_path = (
                self.run_work_dir / backup_filename
            )

            backup_stem_path = (
                self.run_work_dir
                / f"tableau_backup_{self.timestamp_str}"
            )

            logger.info(
                "Creating Tableau Server .tsbak backup."
            )

            self.tsm.create_backup(
                str(backup_stem_path),
                append_date=False,
            )

            self._resolve_backup_output(
                expected_path=backup_path,
                output_stem=backup_stem_path,
            )

            minimum_backup_size_mb = float(
                self.config.backup.get(
                    "minimum_backup_size_mb",
                    DEFAULT_MIN_BACKUP_SIZE_MB,
                )
            )

            validate_file(
                backup_path,
                must_exist=True,
                min_size_mb=minimum_backup_size_mb,
            )

            backup_size = backup_path.stat().st_size
            backup_sha256 = sha256_file(backup_path)

            local_artifacts[BACKUP_KEY] = (
                self._build_artifact_metadata(
                    logical_name=BACKUP_KEY,
                    local_path=backup_path,
                    blob_path=(
                        f"{remote_blob_prefix}/"
                        f"{backup_filename}"
                    ),
                    sha256=backup_sha256,
                    size_bytes=backup_size,
                )
            )

            # ---------------------------------------------------------
            # 3. Generate manifest
            # ---------------------------------------------------------
            manifest_filename = (
                f"manifest_{self.timestamp_str}.json"
            )

            manifest_path = (
                self.run_work_dir / manifest_filename
            )

            manifest_data = (
                self._build_manifest(
                    artifacts=local_artifacts,
                    remote_blob_prefix=remote_blob_prefix,
                )
            )

            self._write_json(
                manifest_path,
                manifest_data,
            )

            validate_file(
                manifest_path,
                must_exist=True,
            )

            manifest_sha256 = sha256_file(
                manifest_path
            )

            manifest_blob_path = (
                f"{remote_blob_prefix}/"
                f"{manifest_filename}"
            )

            # ---------------------------------------------------------
            # 4. Upload all artifacts
            # ---------------------------------------------------------
            logger.info(
                "Uploading backup artifacts to Azure Blob Storage."
            )

            for artifact in local_artifacts.values():
                self.azure.upload_file(
                    local_path=artifact["local_path"],
                    blob_path=artifact["blob_path"],
                    sha256_checksum=artifact["sha256"],
                )

            self.azure.upload_file(
                local_path=manifest_path,
                blob_path=manifest_blob_path,
                sha256_checksum=manifest_sha256,
            )

            # ---------------------------------------------------------
            # 5. Verify every remote object
            # ---------------------------------------------------------
            verify_stream = bool(
                self.config.backup.get(
                    "verify_remote_content_sha256",
                    False,
                )
            )

            logger.info(
                "Verifying uploaded Azure Blob artifacts."
            )

            for artifact in local_artifacts.values():
                self.azure.verify_remote_blob(
                    blob_path=artifact["blob_path"],
                    expected_size_bytes=artifact["size_bytes"],
                    expected_sha256=artifact["sha256"],
                    verify_content_stream=verify_stream,
                )

            self.azure.verify_remote_blob(
                blob_path=manifest_blob_path,
                expected_size_bytes=manifest_path.stat().st_size,
                expected_sha256=manifest_sha256,
                verify_content_stream=verify_stream,
            )

            remote_verified = True

            # ---------------------------------------------------------
            # 6. Retention cleanup
            # ---------------------------------------------------------
            cleanup_status = self._execute_local_cleanup()

            completed_at_dt = datetime.datetime.now(
                datetime.timezone.utc
            )

            duration_seconds = round(
                time.monotonic() - pipeline_start,
                2,
            )

            logger.info(
                "Tableau DR backup pipeline completed successfully. "
                "run_id=%s duration_seconds=%s cleanup=%s",
                self.run_id,
                duration_seconds,
                cleanup_status,
            )

            return BackupResult(
                run_id=self.run_id,
                status="SUCCESS",
                started_at_utc=self.started_at_dt.isoformat(),
                completed_at_utc=completed_at_dt.isoformat(),
                duration_seconds=duration_seconds,
                manifest_path=manifest_blob_path,
                artifacts=self._public_artifact_metadata(
                    local_artifacts
                ),
                remote_verified=remote_verified,
                cleanup_status=cleanup_status,
            )

        except Exception as exc:
            logger.critical(
                "Backup pipeline failed. "
                "Local staging is being preserved for diagnosis. "
                "run_id=%s error=%s",
                self.run_id,
                self._sanitize_error(exc),
            )

            # Deliberately do not clean up here.
            # A failed pipeline must preserve evidence and artifacts.
            if isinstance(exc, TableauDRError):
                raise

            raise TableauDRError(
                "Backup execution failed."
            ) from exc

    def _run_preflight(self) -> None:
        """Validate disk capacity and TSM availability before modifying state."""

        minimum_free_space_gb = float(
            self.config.backup.get(
                "minimum_free_space_gb",
                DEFAULT_MIN_FREE_SPACE_GB,
            )
        )

        backup_dir = Path(
            self.config.paths["backup_dir"]
        ).expanduser()

        validate_disk_space(
            backup_dir,
            required_gb=minimum_free_space_gb,
        )

        logger.info(
            "Preflight disk-space validation passed."
        )

        status_result = self.tsm.status()

        if not status_result.success:
            raise ValidationError(
                "TSM status validation failed before backup."
            )

        logger.info(
            "Preflight TSM status validation passed."
        )

    def _resolve_backup_output(
        self,
        expected_path: Path,
        output_stem: Path,
    ) -> None:
        """
        Resolve the TSM-generated .tsbak file.

        Tableau/TSM may append the .tsbak extension when the output path
        is supplied without it. The search is restricted to the isolated
        run directory and never follows arbitrary filesystem locations.
        """

        if expected_path.exists():
            return

        if not output_stem.exists():
            candidates = sorted(
                self.run_work_dir.glob(
                    f"{output_stem.name}*.tsbak"
                )
            )

            if len(candidates) == 1:
                candidate = candidates[0]

                candidate.replace(expected_path)
                return

        if expected_path.exists():
            return

        raise ValidationError(
            "TSM reported successful backup creation, but the expected "
            ".tsbak artifact was not found in the isolated staging directory."
        )

    @staticmethod
    def _build_artifact_metadata(
        logical_name: str,
        local_path: Path,
        blob_path: str,
        sha256: str,
        size_bytes: int,
    ) -> dict:
        """Build a normalized artifact metadata record."""

        if not logical_name.strip():
            raise ValueError(
                "logical_name cannot be empty."
            )

        if size_bytes <= 0:
            raise IntegrityError(
                f"Artifact '{logical_name}' is empty."
            )

        return {
            "logical_name": logical_name,
            "filename": local_path.name,
            "local_path": str(local_path),
            "size_bytes": size_bytes,
            "sha256": sha256,
            "blob_path": blob_path,
        }

    def _build_manifest(
        self,
        artifacts: Dict[str, dict],
        remote_blob_prefix: str,
    ) -> dict:
        """Create an immutable inventory manifest for the backup run."""

        completed_at = datetime.datetime.now(
            datetime.timezone.utc
        )

        production = self.config.servers["production"]

        return {
            "manifest_version": MANIFEST_VERSION,
            "run_id": self.run_id,
            "status": MANIFEST_STATUS,
            "source": {
                "environment": self.config.environment.get(
                    "name",
                    "production",
                ),
                "hostname": production["hostname"],
                "tableau_version": self.config.environment[
                    "version"
                ],
                "identity_store": production[
                    "identity_store"
                ],
            },
            "timing": {
                "started_at_utc": (
                    self.started_at_dt.isoformat()
                ),
                "completed_at_utc": (
                    completed_at.isoformat()
                ),
            },
            "artifacts": {
                key: {
                    "logical_name": value["logical_name"],
                    "filename": value["filename"],
                    "size_bytes": value["size_bytes"],
                    "sha256": value["sha256"],
                    "blob_path": value["blob_path"],
                }
                for key, value in artifacts.items()
            },
            "remote_storage": {
                "account": self.config.azure[
                    "storage_account_name"
                ],
                "container": self.config.azure[
                    "storage_container"
                ],
                "prefix": remote_blob_prefix,
            },
        }

    @staticmethod
    def _write_json(
        path: Path,
        data: Dict[str, Any],
    ) -> None:
        """Write JSON using deterministic UTF-8 formatting."""

        try:
            with path.open(
                "w",
                encoding="utf-8",
                newline="\n",
            ) as file:
                json.dump(
                    data,
                    file,
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                )
                file.write("\n")

        except OSError as exc:
            raise ValidationError(
                "Unable to write backup manifest."
            ) from exc

    def _execute_local_cleanup(self) -> str:
        """
        Remove the isolated staging directory after remote verification.

        Cleanup failure is intentionally non-fatal because the backup has
        already been verified remotely. The result explicitly records the
        cleanup state for operational visibility.
        """

        if not self.run_work_dir.exists():
            return "ALREADY_CLEAN"

        logger.info(
            "Starting local staging cleanup."
        )

        try:
            shutil.rmtree(
                self.run_work_dir
            )

            logger.info(
                "Local staging cleanup completed successfully."
            )

            return "SUCCESS"

        except OSError as exc:
            logger.warning(
                "Local staging cleanup failed. "
                "Remote backup remains verified. error=%s",
                self._sanitize_error(exc),
            )

            return "FAILED"

    @staticmethod
    def _public_artifact_metadata(
        artifacts: Dict[str, dict],
    ) -> Dict[str, dict]:
        """Remove local filesystem paths from externally returned metadata."""

        return {
            key: {
                "logical_name": value["logical_name"],
                "filename": value["filename"],
                "size_bytes": value["size_bytes"],
                "sha256": value["sha256"],
                "blob_path": value["blob_path"],
            }
            for key, value in artifacts.items()
        }

    @staticmethod
    def _sanitize_error(error: object) -> str:
        """Return a minimal safe error representation."""

        text = str(error)

        sensitive_words = (
            "password",
            "secret",
            "token",
            "passphrase",
            "client_secret",
            "access_token",
            "sas",
        )

        if any(
            word in text.lower()
            for word in sensitive_words
        ):
            return "[REDACTED_ERROR]"

        return text[:1000]