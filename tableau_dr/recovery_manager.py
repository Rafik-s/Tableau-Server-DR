"""State-Machine DR Recovery Orchestrator with fixed state-assignment sequence."""

from __future__ import annotations

import datetime
import enum
import json
import logging
import os
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from tableau_dr.azure_manager import AzureManager
from tableau_dr.config import Config
from tableau_dr.exceptions import IntegrityError, RecoveryError, SecurityValidationError, ValidationError
from tableau_dr.fencing import FencingResult, ProductionFencer
from tableau_dr.health_check import HealthCheckResult, HealthChecker
from tableau_dr.security import sha256_file, validate_file
from tableau_dr.tab_server_connector import TSMConnector

logger = logging.getLogger(__name__)


class RecoveryState(str, enum.Enum):
    DISASTER_DECLARED = "DISASTER_DECLARED"
    FENCING_PENDING = "FENCING_PENDING"
    PRODUCTION_FENCED = "PRODUCTION_FENCED"
    DR_PREFLIGHT_PASSED = "DR_PREFLIGHT_PASSED"
    MANIFEST_VALIDATED = "MANIFEST_VALIDATED"
    BACKUP_ARTIFACTS_VALIDATED = "BACKUP_ARTIFACTS_VALIDATED"
    DR_STOPPED = "DR_STOPPED"
    REPOSITORY_RESTORED = "REPOSITORY_RESTORED"
    SETTINGS_IMPORTED = "SETTINGS_IMPORTED"
    SECURITY_REBOUND = "SECURITY_REBOUND"
    DR_STARTED = "DR_STARTED"
    HEALTH_VALIDATED = "HEALTH_VALIDATED"
    RECOVERY_COMPLETED = "RECOVERY_COMPLETED"
    FAILED = "FAILED"


@dataclass
class StageTiming:
    started_at: str
    completed_at: str
    duration_seconds: float


@dataclass
class RecoveryResult:
    run_id: str
    status: str
    current_state: RecoveryState
    completed_steps: List[RecoveryState]
    failed_step: Optional[RecoveryState]
    fencing_result: Optional[dict]
    health_result: Optional[dict]
    disaster_declared_at_utc: str
    recovery_completed_at_utc: str
    backup_created_at_utc: str
    measured_backup_age_rpo_seconds: float
    total_rto_seconds: float
    stage_timings: Dict[str, dict]

    def to_dict(self) -> dict:
        res = asdict(self)
        res["current_state"] = self.current_state.value
        res["completed_steps"] = [s.value for s in self.completed_steps]
        res["failed_step"] = self.failed_step.value if self.failed_step else None
        return res


class RecoveryManager:
    """Executes state-machine gated DR recovery against target DR infrastructure."""

    def __init__(self, config: Config, run_id: str):
        self.config = config
        self.run_id = run_id
        
        yaml_exe = config.tsm.get("executable") if config.tsm else None
        self.tsm = TSMConnector(yaml_executable=yaml_exe)
        
        azure_cfg = config.azure
        self.azure = AzureManager(
            account_name=azure_cfg["storage_account_name"],
            container_name=azure_cfg["storage_container"],
            max_retries=azure_cfg.get("max_retries", 3),
            backoff_factor=azure_cfg.get("retry_backoff_factor", 0.8),
        )
        
        self.fencer = ProductionFencer(config)
        self.completed_steps: List[RecoveryState] = []
        self.current_state = RecoveryState.DISASTER_DECLARED
        self.stage_timings: Dict[str, StageTiming] = {}
        
        base_recovery_dir = Path(config.paths["recovery_work_dir"])
        self.work_dir = base_recovery_dir / f"recovery_{self.run_id}"

    def _execute_stage(self, target_state: RecoveryState, func, *args, **kwargs):
        """Executes a recovery stage with pre-execution state setting for precise error isolation."""
        logger.info(f"=== STATE TRANSITION: Entering {target_state.value} ===")
        t_start = time.time()
        start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # State updated before function call to isolate failure stage accurately
        self.current_state = target_state
        
        try:
            result = func(*args, **kwargs)
            t_end = time.time()
            end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            
            self.stage_timings[target_state.value] = StageTiming(
                started_at=start_iso,
                completed_at=end_iso,
                duration_seconds=round(t_end - t_start, 2),
            )
            self.completed_steps.append(target_state)
            return result
        except Exception as e:
            logger.critical(f"STATE EXECUTION FAILED at [{target_state.value}]: {e}")
            raise RecoveryError(f"Recovery failed at state {target_state.value}: {e}") from e

    def execute_failover(
        self,
        emergency_auth_code: Optional[str] = None,
        operator_reason: Optional[str] = None,
        target_manifest_blob: Optional[str] = None,
    ) -> RecoveryResult:
        disaster_declared_dt = datetime.datetime.now(datetime.timezone.utc)
        self.completed_steps.append(RecoveryState.DISASTER_DECLARED)
        self.work_dir.mkdir(parents=True, exist_ok=True)

        fencing_res: Optional[FencingResult] = None
        health_res: Optional[HealthCheckResult] = None
        backup_created_at_dt: datetime.datetime = disaster_declared_dt
        failed_stage: Optional[RecoveryState] = None

        try:
            # 1. Production Fencing
            def _fencing_step():
                nonlocal fencing_res
                fencing_res = self.fencer.evaluate_fencing(
                    emergency_authorization_code=emergency_auth_code,
                    operator_reason=operator_reason,
                )
                if not fencing_res.is_fenced:
                    raise SecurityValidationError(f"Fencing Check Failed: {fencing_res.details}")

            self._execute_stage(RecoveryState.PRODUCTION_FENCED, _fencing_step)

            # 2. DR Pre-flight
            def _preflight_step():
                res = self.tsm.status()
                if not res.success:
                    raise ValidationError(f"Target DR TSM cluster is unresponsive: {res.stderr}")

            self._execute_stage(RecoveryState.DR_PREFLIGHT_PASSED, _preflight_step)

            # 3. Acquire Manifest
            manifest_data: dict = {}
            local_manifest_path = self.work_dir / "manifest.json"

            def _manifest_step():
                nonlocal manifest_data, backup_created_at_dt
                blob_name = target_manifest_blob
                if not blob_name:
                    blobs = list(self.azure.container_client.list_blobs(name_starts_with="backups/"))
                    manifest_blobs = sorted([b.name for b in blobs if b.name.endswith(".json") and "manifest" in b.name])
                    if not manifest_blobs:
                        raise ValidationError("No manifest JSON files found in remote storage.")
                    blob_name = manifest_blobs[-1]

                blob_client = self.azure.container_client.get_blob_client(blob_name)
                with open(local_manifest_path, "wb") as f:
                    f.write(blob_client.download_blob().readall())

                with open(local_manifest_path, "r", encoding="utf-8") as f:
                    manifest_data = json.load(f)

                source_ver = manifest_data.get("source", {}).get("tableau_version")
                dr_ver = self.config.environment["version"]
                if source_ver != dr_ver:
                    raise ValidationError(
                        f"Version Mismatch! Manifest Version: {source_ver} | DR Target Version: {dr_ver}"
                    )

                started_str = manifest_data["timing"]["started_at_utc"]
                # Normalize ISO string 'Z' suffix for Python parsing compatibility
                normalized_iso = started_str.replace("Z", "+00:00")
                backup_created_at_dt = datetime.datetime.fromisoformat(normalized_iso)

            self._execute_stage(RecoveryState.MANIFEST_VALIDATED, _manifest_step)

            # 4. Download & Validate Artifacts
            local_artifacts: Dict[str, Path] = {}

            def _artifacts_step():
                artifacts = manifest_data.get("artifacts", {})
                for key, info in artifacts.items():
                    blob_path = info["blob_path"]
                    expected_sha256 = info["sha256"]
                    expected_size = info["size_bytes"]
                    local_target = self.work_dir / info["filename"]

                    logger.info(f"Downloading recovery artifact '{info['filename']}'...")
                    blob_client = self.azure.container_client.get_blob_client(blob_path)
                    with open(local_target, "wb") as f:
                        f.write(blob_client.download_blob().readall())

                    validate_file(local_target, must_exist=True)
                    if local_target.stat().st_size != expected_size:
                        raise IntegrityError(f"Downloaded artifact size mismatch for {key}")
                    
                    downloaded_hash = sha256_file(local_target)
                    if downloaded_hash.lower() != expected_sha256.lower():
                        raise IntegrityError(f"Downloaded SHA-256 hash mismatch for {key}")
                    
                    local_artifacts[key] = local_target

            self._execute_stage(RecoveryState.BACKUP_ARTIFACTS_VALIDATED, _artifacts_step)

            # 5. Stop DR Server
            def _stop_step():
                self.tsm.run(["stop", "--ignore-prompt"], timeout=1800)

            self._execute_stage(RecoveryState.DR_STOPPED, _stop_step)

            # 6. Restore Repository Data
            def _restore_step():
                tsbak_path = str(local_artifacts["backup.tsbak"])
                self.tsm.run(["maintenance", "restore", "--file", tsbak_path], timeout=14400)

            self._execute_stage(RecoveryState.REPOSITORY_RESTORED, _restore_step)

            # 7. Import Settings
            def _settings_step():
                settings_path = str(local_artifacts["settings.json"])
                self.tsm.run(["settings", "import", "-f", settings_path], timeout=1800)

            self._execute_stage(RecoveryState.SETTINGS_IMPORTED, _settings_step)

            # 8. Security Credential Rebinding
            def _security_step():
                self._apply_key_vault_security_bindings()

            self._execute_stage(RecoveryState.SECURITY_REBOUND, _security_step)

            # 9. Start DR Server
            def _start_step():
                self.tsm.run(["start"], timeout=3600)

            self._execute_stage(RecoveryState.DR_STARTED, _start_step)

            # 10. Post-Restore Health Checks
            def _health_step():
                nonlocal health_res
                checker = HealthChecker(
                    tsm_connector=self.tsm,
                    gateway_hostname=self.config.servers["disaster_recovery"]["hostname"],
                )
                health_res = checker.run_all_checks()
                if not health_res.overall_healthy:
                    raise RecoveryError(f"DR Health Verification Failed: {health_res.layers}")

            self._execute_stage(RecoveryState.HEALTH_VALIDATED, _health_step)

            self.completed_steps.append(RecoveryState.RECOVERY_COMPLETED)
            final_state = RecoveryState.RECOVERY_COMPLETED

        except Exception as e:
            failed_stage = self.current_state
            final_state = RecoveryState.FAILED
            logger.critical(f"DR Failover Execution ABORTED: {e}")

        completed_dt = datetime.datetime.now(datetime.timezone.utc)
        rpo_seconds = (disaster_declared_dt - backup_created_at_dt).total_seconds()
        rto_seconds = (completed_dt - disaster_declared_dt).total_seconds()

        return RecoveryResult(
            run_id=self.run_id,
            status="SUCCESS" if final_state == RecoveryState.RECOVERY_COMPLETED else "FAILED",
            current_state=final_state,
            completed_steps=self.completed_steps,
            failed_step=failed_stage,
            fencing_result=fencing_res.to_dict() if fencing_res else None,
            health_result=health_res.to_dict() if health_res else None,
            disaster_declared_at_utc=disaster_declared_dt.isoformat(),
            recovery_completed_at_utc=completed_dt.isoformat(),
            backup_created_at_utc=backup_created_at_dt.isoformat(),
            measured_backup_age_rpo_seconds=round(rpo_seconds, 2),
            total_rto_seconds=round(rto_seconds, 2),
            stage_timings={k: asdict(v) for k, v in self.stage_timings.items()},
        )

    def _apply_key_vault_security_bindings(self) -> None:
        kv_name = self.config.azure["key_vault_name"]
        kv_uri = f"https://{kv_name}.vault.azure.net"
        credential = DefaultAzureCredential()
        secret_client = SecretClient(vault_url=kv_uri, credential=credential)

        ssl_cert_secret = secret_client.get_secret("tableau-dr-ssl-cert")
        ssl_key_secret = secret_client.get_secret("tableau-dr-ssl-key")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            cert_file = temp_path / "ssl_cert.crt"
            key_file = temp_path / "ssl_key.key"

            cert_file.write_text(ssl_cert_secret.value, encoding="utf-8")
            key_file.write_text(ssl_key_secret.value, encoding="utf-8")

            if os.name != "nt":
                os.chmod(cert_file, 0o600)
                os.chmod(key_file, 0o600)

            logger.info("Applying SSL configuration bindings via TSM...")
            self.tsm.run([
                "security", "external-ssl", "enable",
                "--cert-file", str(cert_file),
                "--key-file", str(key_file),
            ])
            self.tsm.run(["pending-changes", "apply"])