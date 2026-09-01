"""Orchestrates isolated DR backup execution and remote persistence."""

from __future__ import annotations

import datetime
import json
import logging
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from tableau_dr.azure_manager import AzureManager
from tableau_dr.config import Config
from tableau_dr.exceptions import TableauDRError, ValidationError
from tableau_dr.security import sha256_file, validate_file
from tableau_dr.tab_server_connector import TSMConnector
from tableau_dr.validation import validate_disk_space

logger = logging.getLogger(__name__)


@dataclass
class BackupResult:
    run_id: str
    status: str
    started_at_utc: str
    completed_at_utc: str
    duration_seconds: float
    manifest_path: str
    artifacts: dict
    remote_verified: bool
    cleanup_status: str

    def to_dict(self) -> dict:
        return asdict(self)


class BackupManager:
    """Executes backup pipelines, manifest serialization, remote verification, and cleanup."""

    def __init__(self, config: Config, run_id: str):
        self.config = config
        self.run_id = run_id

        yaml_executable = config.tsm.get("executable") if config.tsm else None
        self.tsm = TSMConnector(yaml_executable=yaml_executable)

        azure_cfg = config.azure
        self.azure = AzureManager(
            account_name=azure_cfg["storage_account_name"],
            container_name=azure_cfg["storage_container"],
            max_retries=int(azure_cfg.get("max_retries", 3)),
            backoff_factor=float(
                azure_cfg.get("retry_initial_backoff_seconds", 2)
            ),
        )

        self.started_at_dt = datetime.datetime.now(datetime.timezone.utc)
        self.timestamp_str = self.started_at_dt.strftime("%Y%m%dT%H%M%SZ")
        self.run_dir_name = f"{self.timestamp_str}_{self.run_id}"

        base_backup_dir = Path(config.paths["backup_dir"])
        self.run_work_dir = base_backup_dir / self.run_dir_name

    def execute_backup_pipeline(self) -> BackupResult:
        start_time = time.monotonic()

        logger.info(
            "Starting DR Backup Pipeline [RUN_ID=%s]...",
            self.run_id,
        )

        local_artifacts: dict[str, dict] = {}
        remote_blob_folder = f"backups/{self.run_dir_name}"
        cleanup_status = "SKIPPED"
        remote_verified = False

        try:
            # 1. Pre-flight checks
            self._run_preflight()

            # 2. Create run-isolated working directory
            self.run_work_dir.mkdir(parents=True, exist_ok=False)

            logger.info(
                "Created isolated backup workspace [RUN_ID=%s]: %s",
                self.run_id,
                self.run_work_dir,
            )

            # 3. Export Tableau configuration/settings
            settings_filename = (
                f"tableau_settings_{self.timestamp_str}.json"
            )
            settings_path = self.run_work_dir / settings_filename

            self.tsm.export_settings(str(settings_path))

            validate_file(
                settings_path,
                must_exist=True,
            )

            settings_sha256 = sha256_file(settings_path)

            local_artifacts["settings.json"] = {
                "local_path": str(settings_path),
                "filename": settings_filename,
                "size_bytes": settings_path.stat().st_size,
                "sha256": settings_sha256,
                "blob_path": (
                    f"{remote_blob_folder}/{settings_filename}"
                ),
            }

            # 4. Create Tableau repository backup
            tsbak_filename = (
                f"tableau_backup_{self.timestamp_str}.tsbak"
            )

            tsbak_target_path = self.run_work_dir / tsbak_filename

            # TSM expects the backup path without the .tsbak extension.
            tsbak_arg_path = str(
                self.run_work_dir
                / f"tableau_backup_{self.timestamp_str}"
            )

            logger.info(
                "Creating Tableau repository backup: %s",
                tsbak_arg_path,
            )

            self.tsm.create_backup(
                tsbak_arg_path,
                append_date=False,
            )

            min_backup_mb = float(
                self.config.backup.get(
                    "minimum_backup_size_mb",
                    10,
                )
            )

            validate_file(
                tsbak_target_path,
                must_exist=True,
                min_size_mb=min_backup_mb,
            )

            tsbak_sha256 = sha256_file(tsbak_target_path)

            local_artifacts["backup.tsbak"] = {
                "local_path": str(tsbak_target_path),
                "filename": tsbak_filename,
                "size_bytes": tsbak_target_path.stat().st_size,
                "sha256": tsbak_sha256,
                "blob_path": (
                    f"{remote_blob_folder}/{tsbak_filename}"
                ),
            }

            # 5. Build non-circular manifest.
            #
            # IMPORTANT:
            # The manifest does NOT contain its own hash or size.
            # Only source artifacts are included here.
            duration_so_far = round(
                time.monotonic() - start_time,
                2,
            )

            clean_manifest_artifacts = {
                key: {
                    "filename": item["filename"],
                    "size_bytes": item["size_bytes"],
                    "sha256": item["sha256"],
                    "blob_path": item["blob_path"],
                }
                for key, item in local_artifacts.items()
            }

            manifest_data = {
                "manifest_version": "2.0",
                "run_id": self.run_id,
                "status": "ARTIFACTS_READY",
                "source": {
                    "environment": "production",
                    "hostname": self.config.servers[
                        "production"
                    ]["hostname"],
                    "tableau_version": self.config.environment[
                        "version"
                    ],
                    "identity_store": self.config.servers[
                        "production"
                    ]["identity_store"],
                },
                "timing": {
                    "started_at_utc": (
                        self.started_at_dt.isoformat()
                    ),
                    "created_at_utc": (
                        datetime.datetime.now(
                            datetime.timezone.utc
                        ).isoformat()
                    ),
                    "duration_seconds": duration_so_far,
                },
                "artifacts": clean_manifest_artifacts,
                "remote_storage": {
                    "container": self.config.azure[
                        "storage_container"
                    ],
                    "prefix": remote_blob_folder,
                },
            }

            manifest_filename = (
                f"manifest_{self.timestamp_str}.json"
            )
            manifest_path = self.run_work_dir / manifest_filename

            with manifest_path.open(
                "w",
                encoding="utf-8",
            ) as manifest_file:
                json.dump(
                    manifest_data,
                    manifest_file,
                    indent=2,
                    sort_keys=True,
                )
                manifest_file.write("\n")

            validate_file(
                manifest_path,
                must_exist=True,
            )

            manifest_sha256 = sha256_file(manifest_path)
            manifest_size = manifest_path.stat().st_size

            manifest_blob_path = (
                f"{remote_blob_folder}/{manifest_filename}"
            )

            # 6. Upload source artifacts.
            logger.info(
                "Uploading source artifacts to Azure Blob Storage..."
            )

            for meta in local_artifacts.values():
                self.azure.upload_file(
                    local_path=meta["local_path"],
                    blob_path=meta["blob_path"],
                    sha256_checksum=meta["sha256"],
                )

            # 7. Upload manifest separately.
            self.azure.upload_file(
                local_path=str(manifest_path),
                blob_path=manifest_blob_path,
                sha256_checksum=manifest_sha256,
            )

            # 8. Remote verification.
            verify_stream = bool(
                self.config.backup.get(
                    "verify_remote_content_sha256",
                    False,
                )
            )

            logger.info(
                "Verifying all remote artifacts [stream_verification=%s]...",
                verify_stream,
            )

            for meta in local_artifacts.values():
                self.azure.verify_remote_blob(
                    blob_path=meta["blob_path"],
                    expected_size_bytes=meta["size_bytes"],
                    expected_sha256=meta["sha256"],
                    verify_content_stream=verify_stream,
                )

            self.azure.verify_remote_blob(
                blob_path=manifest_blob_path,
                expected_size_bytes=manifest_size,
                expected_sha256=manifest_sha256,
                verify_content_stream=verify_stream,
            )

            remote_verified = True

            logger.info(
                "[PASS] All remote artifacts verified successfully "
                "[RUN_ID=%s].",
                self.run_id,
            )

            # 9. Fail-closed cleanup.
            #
            # Cleanup is reached only after every uploaded artifact,
            # including the manifest, has passed remote verification.
            cleanup_status = self._execute_local_cleanup()

            completed_at_dt = datetime.datetime.now(
                datetime.timezone.utc
            )

            total_duration = round(
                time.monotonic() - start_time,
                2,
            )

            return BackupResult(
                run_id=self.run_id,
                status="SUCCESS",
                started_at_utc=self.started_at_dt.isoformat(),
                completed_at_utc=completed_at_dt.isoformat(),
                duration_seconds=total_duration,
                manifest_path=manifest_blob_path,
                artifacts=local_artifacts,
                remote_verified=remote_verified,
                cleanup_status=cleanup_status,
            )

        except Exception as exc:
            logger.error(
                "BACKUP PIPELINE FAILED [RUN_ID=%s]: %s. "
                "Local staging will be preserved where possible.",
                self.run_id,
                exc,
            )

            raise TableauDRError(
                f"Backup execution failure: {exc}"
            ) from exc

    def _run_preflight(self) -> None:
        """Validate disk capacity and TSM availability before backup."""

        min_free_gb = float(
            self.config.backup.get(
                "minimum_free_space_gb",
                50.0,
            )
        )

        validate_disk_space(
            self.config.paths["backup_dir"],
            required_gb=min_free_gb,
        )

        status_res = self.tsm.status()

        if not status_res.success:
            raise ValidationError(
                "TSM check failed prior to backup: "
                f"{status_res.stderr}"
            )

        logger.info("[PASS] Backup pre-flight checks completed.")

    def _execute_local_cleanup(self) -> str:
        """
        Remove only the current run's isolated staging directory.

        This method is called only after complete remote verification.
        """

        logger.info(
            "Cleaning up local staging directory: %s",
            self.run_work_dir,
        )

        try:
            if not self.run_work_dir.exists():
                logger.info(
                    "Local staging directory already absent."
                )
                return "SUCCESS"

            if not self.run_work_dir.is_dir():
                logger.error(
                    "Cleanup safety check failed: path is not a directory: %s",
                    self.run_work_dir,
                )
                return "FAILED"

            shutil.rmtree(self.run_work_dir)

            logger.info(
                "[PASS] Local staging cleanup complete."
            )

            return "SUCCESS"

        except Exception as exc:
            logger.warning(
                "Cleanup non-fatal error: Could not remove "
                "local staging directory: %s",
                exc,
            )
            return "FAILED"