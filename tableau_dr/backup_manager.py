"""Backup Orchestration Manager with robust error boundary logging and BackupResult DTO."""

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
    status: str  # SUCCESS, FAILED
    started_at_utc: str
    completed_at_utc: str
    duration_seconds: float
    manifest_path: str
    artifacts: dict
    remote_verified: bool
    cleanup_status: str  # SUCCESS, FAILED, SKIPPED

    def to_dict(self) -> dict:
        return asdict(self)


class BackupManager:
    """Orchestrates end-to-end Tableau backup execution and structured result generation."""

    def __init__(self, config: Config, run_id: str):
        self.config = config
        self.run_id = run_id
        
        # Configure TSM with explicit path resolution
        yaml_executable = config.tsm.get("executable") if config.tsm else None
        self.tsm = TSMConnector(yaml_executable=yaml_executable)
        
        azure_cfg = config.azure
        self.azure = AzureManager(
            account_name=azure_cfg["storage_account_name"],
            container_name=azure_cfg["storage_container"],
        )
        
        self.started_at_dt = datetime.datetime.now(datetime.timezone.utc)
        self.timestamp_str = self.started_at_dt.strftime("%Y%m%dT%H%M%SZ")
        self.run_dir_name = f"{self.timestamp_str}_{self.run_id}"
        
        base_backup_dir = Path(config.paths["backup_dir"])
        self.run_work_dir = base_backup_dir / self.run_dir_name

    def execute_backup_pipeline(self) -> BackupResult:
        """Executes the complete fail-closed backup workflow."""
        start_time = time.time()
        logger.info(f"Starting DR Backup Pipeline [RUN_ID={self.run_id}]...")

        # 1. Pre-flight Validation
        self._run_preflight()

        # Create isolated workspace directory
        self.run_work_dir.mkdir(parents=True, exist_ok=True)

        local_artifacts = {}
        remote_blob_folder = f"backups/{self.run_dir_name}"
        cleanup_status = "SKIPPED"
        remote_verified = False

        try:
            # 2. Export TSM Settings
            settings_filename = f"tableau_settings_{self.timestamp_str}.json"
            settings_path = self.run_work_dir / settings_filename
            self.tsm.export_settings(str(settings_path))
            
            validate_file(settings_path, must_exist=True)
            settings_sha256 = sha256_file(settings_path)
            local_artifacts["settings.json"] = {
                "local_path": str(settings_path),
                "filename": settings_filename,
                "size_bytes": settings_path.stat().st_size,
                "sha256": settings_sha256,
                "blob_path": f"{remote_blob_folder}/{settings_filename}",
            }

            # 3. Create TSM Repository Backup (.tsbak) using explicit pathing
            tsbak_filename = f"tableau_backup_{self.timestamp_str}.tsbak"
            tsbak_target_path = self.run_work_dir / tsbak_filename
            
            # Pass explicit path (without .tsbak extension as expected by TSM CLI)
            tsbak_arg_path = str(self.run_work_dir / f"tableau_backup_{self.timestamp_str}")
            self.tsm.create_backup(tsbak_arg_path, append_date=False)

            min_backup_mb = self.config.backup.get("minimum_backup_size_mb", 10)
            validate_file(tsbak_target_path, must_exist=True, min_size_mb=min_backup_mb)
            
            tsbak_sha256 = sha256_file(tsbak_target_path)
            local_artifacts["backup.tsbak"] = {
                "local_path": str(tsbak_target_path),
                "filename": tsbak_filename,
                "size_bytes": tsbak_target_path.stat().st_size,
                "sha256": tsbak_sha256,
                "blob_path": f"{remote_blob_folder}/{tsbak_filename}",
            }

            # 4. Build Clean Manifest (Resolves Circular Dependency)
            duration_so_far = round(time.time() - start_time, 2)
            manifest_data = {
                "manifest_version": "2.0",
                "run_id": self.run_id,
                "status": "SUCCESS",
                "source": {
                    "environment": "production",
                    "hostname": self.config.servers["production"]["hostname"],
                    "tableau_version": self.config.environment["version"],
                    "identity_store": self.config.servers["production"]["identity_store"],
                },
                "timing": {
                    "started_at_utc": self.started_at_dt.isoformat(),
                    "completed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "duration_seconds": duration_so_far,
                },
                "artifacts": local_artifacts,
                "remote_storage": {
                    "account": self.config.azure["storage_account_name"],
                    "container": self.config.azure["storage_container"],
                    "prefix": remote_blob_folder,
                },
            }

            manifest_filename = f"manifest_{self.timestamp_str}.json"
            manifest_path = self.run_work_dir / manifest_filename
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2)

            manifest_sha256 = sha256_file(manifest_path)
            manifest_blob_path = f"{remote_blob_folder}/{manifest_filename}"

            # 5. Azure Upload Sequence
            logger.info("Uploading source artifacts and manifest to Azure Blob Storage...")
            for artifact_key, meta in local_artifacts.items():
                self.azure.upload_file(
                    local_path=meta["local_path"],
                    blob_path=meta["blob_path"],
                    sha256_checksum=meta["sha256"],
                )
            
            # Upload manifest
            self.azure.upload_file(
                local_path=str(manifest_path),
                blob_path=manifest_blob_path,
                sha256_checksum=manifest_sha256,
            )

            # 6. Remote Integrity Verification
            logger.info("Verifying remote Azure Blob Storage integrity...")
            for artifact_key, meta in local_artifacts.items():
                self.azure.verify_remote_blob(
                    blob_path=meta["blob_path"],
                    expected_size_bytes=meta["size_bytes"],
                    expected_sha256=meta["sha256"],
                )
            
            self.azure.verify_remote_blob(
                blob_path=manifest_blob_path,
                expected_size_bytes=manifest_path.stat().st_size,
                expected_sha256=manifest_sha256,
            )
            remote_verified = True

            # 7. Fail-Closed Local Cleanup
            cleanup_status = self._execute_local_cleanup()

            completed_at_dt = datetime.datetime.now(datetime.timezone.utc)
            total_duration = round(time.time() - start_time, 2)

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

        except Exception as e:
            logger.error(f"BACKUP PIPELINE FAILED: {e}. Preserving local workspace.")
            raise TableauDRError(f"Backup pipeline execution failure: {e}") from e

    def _run_preflight(self) -> None:
        """Runs pre-flight disk capacity and TSM checks."""
        logger.info("Running pre-flight system checks...")
        min_free_gb = float(self.config.backup.get("minimum_free_space_gb", 50.0))
        validate_disk_space(self.config.paths["backup_dir"], required_gb=min_free_gb)
        
        status_res = self.tsm.status()
        if not status_res.success:
            raise ValidationError(f"TSM cluster check failed prior to backup: {status_res.stderr}")

    def _execute_local_cleanup(self) -> str:
        """Deletes local working directory after verified upload."""
        logger.info("Cleaning up local staging directory...")
        try:
            shutil.rmtree(self.run_work_dir)
            logger.info("[PASS] Local cleanup complete.")
            return "SUCCESS"
        except Exception as e:
            logger.warning(f"Cleanup non-fatal error: Failed to remove working directory: {e}")
            return "FAILED"