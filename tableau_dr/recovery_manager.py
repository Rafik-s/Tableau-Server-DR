"""State-machine DR recovery orchestrator with strict validation and fail-closed recovery."""

from __future__ import annotations

import datetime
import enum
import hmac
import json
import logging
import os
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from tableau_dr.azure_manager import AzureManager
from tableau_dr.config import Config
from tableau_dr.exceptions import (
    IntegrityError,
    RecoveryError,
    SecurityValidationError,
    ValidationError,
)
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
        result = asdict(self)
        result["current_state"] = self.current_state.value
        result["completed_steps"] = [
            state.value for state in self.completed_steps
        ]
        result["failed_step"] = (
            self.failed_step.value if self.failed_step else None
        )
        return result


class RecoveryManager:
    """Executes state-machine gated DR recovery against target DR infrastructure."""

    REQUIRED_ARTIFACTS = {
        "backup.tsbak",
        "settings.json",
    }

    def __init__(self, config: Config, run_id: str):
        self.config = config
        self.run_id = run_id

        yaml_executable = (
            config.tsm.get("executable")
            if config.tsm
            else None
        )

        self.tsm = TSMConnector(
            yaml_executable=yaml_executable
        )

        azure_cfg = config.azure

        self.azure = AzureManager(
            account_name=azure_cfg["storage_account_name"],
            container_name=azure_cfg["storage_container"],
            max_retries=int(
                azure_cfg.get("max_retries", 3)
            ),
            backoff_factor=float(
                azure_cfg.get(
                    "retry_initial_backoff_seconds",
                    2,
                )
            ),
        )

        self.fencer = ProductionFencer(config)

        self.completed_steps: List[RecoveryState] = []
        self.current_state = RecoveryState.DISASTER_DECLARED
        self.stage_timings: Dict[str, StageTiming] = {}

        base_recovery_dir = Path(
            config.paths["recovery_work_dir"]
        )

        self.work_dir = (
            base_recovery_dir
            / f"recovery_{self.run_id}"
        )

    def _execute_stage(
        self,
        target_state: RecoveryState,
        func: Callable,
        *args,
        **kwargs,
    ):
        """Execute a recovery stage with explicit state tracking."""

        logger.info(
            "=== STATE TRANSITION: Entering %s ===",
            target_state.value,
        )

        start_monotonic = time.monotonic()
        start_iso = (
            datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()
        )

        self.current_state = target_state

        try:
            result = func(*args, **kwargs)

            completed_iso = (
                datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat()
            )

            duration = round(
                time.monotonic() - start_monotonic,
                2,
            )

            self.stage_timings[
                target_state.value
            ] = StageTiming(
                started_at=start_iso,
                completed_at=completed_iso,
                duration_seconds=duration,
            )

            self.completed_steps.append(
                target_state
            )

            logger.info(
                "=== STATE COMPLETED: %s ===",
                target_state.value,
            )

            return result

        except Exception as exc:
            logger.critical(
                "STATE EXECUTION FAILED [%s]: %s",
                target_state.value,
                exc,
            )

            raise RecoveryError(
                f"Recovery failed at state "
                f"{target_state.value}: {exc}"
            ) from exc

    def execute_failover(
        self,
        emergency_auth_code: Optional[str] = None,
        operator_reason: Optional[str] = None,
        target_manifest_blob: Optional[str] = None,
    ) -> RecoveryResult:
        disaster_declared_dt = (
            datetime.datetime.now(
                datetime.timezone.utc
            )
        )

        self.completed_steps = [
            RecoveryState.DISASTER_DECLARED
        ]

        self.current_state = (
            RecoveryState.DISASTER_DECLARED
        )

        self.work_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        fencing_res: Optional[FencingResult] = None
        health_res: Optional[HealthCheckResult] = None

        backup_created_at_dt = (
            disaster_declared_dt
        )

        failed_stage: Optional[RecoveryState] = None
        final_state = RecoveryState.FAILED

        try:
            # ---------------------------------------------------------
            # 1. Production Fencing
            # ---------------------------------------------------------
            def fencing_step() -> None:
                nonlocal fencing_res

                fencing_res = (
                    self.fencer.evaluate_fencing(
                        emergency_authorization_code=(
                            emergency_auth_code
                        ),
                        operator_reason=operator_reason,
                    )
                )

                if not fencing_res.is_fenced:
                    raise SecurityValidationError(
                        "Production fencing validation failed: "
                        f"{fencing_res.details}"
                    )

            self._execute_stage(
                RecoveryState.PRODUCTION_FENCED,
                fencing_step,
            )

            # ---------------------------------------------------------
            # 2. DR Pre-flight
            # ---------------------------------------------------------
            def preflight_step() -> None:
                recovery_dir = self.work_dir.resolve()
                base_dir = Path(
                    self.config.paths[
                        "recovery_work_dir"
                    ]
                ).resolve()

                if base_dir not in recovery_dir.parents:
                    raise SecurityValidationError(
                        "Recovery working directory is outside "
                        "the configured recovery root."
                    )

                min_free_gb = float(
                    self.config.backup.get(
                        "minimum_free_space_gb",
                        50.0,
                    )
                )

                from tableau_dr.validation import (
                    validate_disk_space,
                )

                validate_disk_space(
                    str(self.work_dir),
                    required_gb=min_free_gb,
                )

                result = self.tsm.status()

                if not result.success:
                    raise ValidationError(
                        "Target DR TSM cluster is unresponsive: "
                        f"{result.stderr}"
                    )

                dr_version = self.config.environment[
                    "version"
                ]

                version_result = self.tsm.version()

                if not version_result.success:
                    raise ValidationError(
                        "Unable to validate DR Tableau version."
                    )

                if dr_version not in (
                    version_result.stdout
                ):
                    raise ValidationError(
                        "Configured DR Tableau version does not "
                        "match the actual TSM version output."
                    )

            self._execute_stage(
                RecoveryState.DR_PREFLIGHT_PASSED,
                preflight_step,
            )

            # ---------------------------------------------------------
            # 3. Acquire and Cryptographically Validate Manifest
            # ---------------------------------------------------------
            manifest_data: dict = {}
            local_manifest_path = (
                self.work_dir / "manifest.json"
            )

            def manifest_step() -> None:
                nonlocal manifest_data
                nonlocal backup_created_at_dt

                blob_name = target_manifest_blob

                if not blob_name:
                    blobs = list(
                        self.azure.container_client.list_blobs(
                            name_starts_with="backups/"
                        )
                    )

                    manifest_blobs = sorted(
                        (
                            blob.name
                            for blob in blobs
                            if blob.name.endswith(".json")
                            and "/manifest_" in blob.name
                        )
                    )

                    if not manifest_blobs:
                        raise ValidationError(
                            "No manifest files found in remote storage."
                        )

                    blob_name = manifest_blobs[-1]

                if not blob_name.startswith(
                    "backups/"
                ):
                    raise SecurityValidationError(
                        "Manifest path is outside the permitted "
                        "backup prefix."
                    )

                if ".." in Path(blob_name).parts:
                    raise SecurityValidationError(
                        "Manifest blob path contains unsafe path components."
                    )

                blob_client = (
                    self.azure.container_client
                    .get_blob_client(blob_name)
                )

                try:
                    properties = (
                        blob_client.get_blob_properties()
                    )

                    remote_metadata = (
                        properties.metadata or {}
                    )

                    expected_sha256 = (
                        remote_metadata
                        .get("sha256", "")
                        .lower()
                    )

                    if not expected_sha256:
                        raise IntegrityError(
                            "Remote manifest is missing SHA-256 metadata."
                        )

                    with local_manifest_path.open(
                        "wb"
                    ) as manifest_file:
                        manifest_file.write(
                            blob_client.download_blob().readall()
                        )

                except AzureError as exc:
                    raise ValidationError(
                        f"Failed to download manifest: {exc}"
                    ) from exc

                validate_file(
                    local_manifest_path,
                    must_exist=True,
                )

                actual_sha256 = (
                    sha256_file(
                        local_manifest_path
                    ).lower()
                )

                if not hmac.compare_digest(
                    actual_sha256,
                    expected_sha256,
                ):
                    raise IntegrityError(
                        "Manifest SHA-256 verification failed."
                    )

                if (
                    local_manifest_path.stat().st_size
                    != properties.size
                ):
                    raise IntegrityError(
                        "Manifest size verification failed."
                    )

                try:
                    with local_manifest_path.open(
                        "r",
                        encoding="utf-8",
                    ) as manifest_file:
                        manifest_data = json.load(
                            manifest_file
                        )
                except (
                    json.JSONDecodeError
                ) as exc:
                    raise ValidationError(
                        f"Manifest JSON is invalid: {exc}"
                    ) from exc

                if manifest_data.get(
                    "manifest_version"
                ) != "2.0":
                    raise ValidationError(
                        "Unsupported manifest version."
                    )

                if manifest_data.get(
                    "status"
                ) != "ARTIFACTS_READY":
                    raise ValidationError(
                        "Manifest is not in ARTIFACTS_READY state."
                    )

                manifest_run_id = manifest_data.get(
                    "run_id"
                )

                if not manifest_run_id:
                    raise ValidationError(
                        "Manifest does not contain a valid run_id."
                    )

                source = manifest_data.get(
                    "source",
                    {}
                )

                source_version = source.get(
                    "tableau_version"
                )

                dr_version = self.config.environment[
                    "version"
                ]

                if source_version != dr_version:
                    raise ValidationError(
                        "Tableau version mismatch: "
                        f"Manifest={source_version} | "
                        f"DR Target={dr_version}"
                    )

                source_store = (
                    source.get("identity_store")
                )

                dr_store = self.config.servers[
                    "disaster_recovery"
                ]["identity_store"]

                if (
                    source_store
                    and source_store.lower()
                    != dr_store.lower()
                ):
                    raise ValidationError(
                        "Identity store mismatch: "
                        f"Manifest={source_store} | "
                        f"DR Target={dr_store}"
                    )

                timing = manifest_data.get(
                    "timing",
                    {}
                )

                backup_timestamp = (
                    timing.get("created_at_utc")
                    or timing.get("completed_at_utc")
                    or timing.get("started_at_utc")
                )

                if not backup_timestamp:
                    raise ValidationError(
                        "Manifest does not contain a valid backup timestamp."
                    )

                backup_created_at_dt = (
                    self._parse_utc_timestamp(
                        backup_timestamp
                    )
                )

                logger.info(
                    "[PASS] Manifest cryptographic and "
                    "environment validation completed."
                )

            self._execute_stage(
                RecoveryState.MANIFEST_VALIDATED,
                manifest_step,
            )

            # ---------------------------------------------------------
            # 4. Download and Validate Backup Artifacts
            # ---------------------------------------------------------
            local_artifacts: Dict[str, Path] = {}

            def artifacts_step() -> None:
                artifacts = manifest_data.get(
                    "artifacts"
                )

                if not isinstance(
                    artifacts,
                    dict,
                ):
                    raise ValidationError(
                        "Manifest artifacts section is invalid."
                    )

                missing = (
                    self.REQUIRED_ARTIFACTS
                    - set(artifacts.keys())
                )

                if missing:
                    raise ValidationError(
                        "Required recovery artifacts are missing: "
                        f"{sorted(missing)}"
                    )

                verify_stream = bool(
                    self.config.backup.get(
                        "verify_remote_content_sha256",
                        False,
                    )
                )

                for key, info in artifacts.items():
                    if not isinstance(
                        info,
                        dict,
                    ):
                        raise ValidationError(
                            f"Invalid artifact metadata for {key}."
                        )

                    filename = info.get(
                        "filename"
                    )
                    blob_path = info.get(
                        "blob_path"
                    )
                    expected_sha256 = str(
                        info.get(
                            "sha256",
                            ""
                        )
                    ).lower()
                    expected_size = info.get(
                        "size_bytes"
                    )

                    if not filename:
                        raise ValidationError(
                            f"Missing filename for artifact {key}."
                        )

                    if not blob_path:
                        raise ValidationError(
                            f"Missing blob path for artifact {key}."
                        )

                    if not expected_sha256:
                        raise ValidationError(
                            f"Missing SHA-256 for artifact {key}."
                        )

                    if not isinstance(
                        expected_size,
                        int,
                    ) or expected_size < 0:
                        raise ValidationError(
                            f"Invalid size for artifact {key}."
                        )

                    if (
                        Path(filename).name
                        != filename
                        or ".." in Path(filename).parts
                    ):
                        raise SecurityValidationError(
                            f"Unsafe artifact filename: {filename}"
                        )

                    if not blob_path.startswith(
                        "backups/"
                    ):
                        raise SecurityValidationError(
                            f"Artifact blob path is outside "
                            f"the backup prefix: {blob_path}"
                        )

                    if ".." in Path(blob_path).parts:
                        raise SecurityValidationError(
                            f"Unsafe artifact blob path: {blob_path}"
                        )

                    local_target = (
                        self.work_dir / filename
                    ).resolve()

                    work_root = (
                        self.work_dir.resolve()
                    )

                    if work_root not in (
                        local_target.parents
                    ):
                        raise SecurityValidationError(
                            f"Artifact target escapes recovery directory: "
                            f"{filename}"
                        )

                    logger.info(
                        "Downloading recovery artifact '%s'...",
                        filename,
                    )

                    try:
                        blob_client = (
                            self.azure.container_client
                            .get_blob_client(blob_path)
                        )

                        properties = (
                            blob_client.get_blob_properties()
                        )

                        remote_metadata = (
                            properties.metadata or {}
                        )

                        remote_sha256 = (
                            remote_metadata
                            .get("sha256", "")
                            .lower()
                        )

                        if not remote_sha256:
                            raise IntegrityError(
                                f"Remote artifact '{key}' "
                                "has no SHA-256 metadata."
                            )

                        if not hmac.compare_digest(
                            remote_sha256,
                            expected_sha256,
                        ):
                            raise IntegrityError(
                                f"Remote metadata SHA-256 mismatch "
                                f"for artifact '{key}'."
                            )

                        if properties.size != expected_size:
                            raise IntegrityError(
                                f"Remote size mismatch for artifact '{key}': "
                                f"expected={expected_size}, "
                                f"actual={properties.size}"
                            )

                        with local_target.open(
                            "wb"
                        ) as artifact_file:
                            artifact_file.write(
                                blob_client
                                .download_blob()
                                .readall()
                            )

                    except AzureError as exc:
                        raise ValidationError(
                            f"Failed downloading artifact "
                            f"'{key}': {exc}"
                        ) from exc

                    validate_file(
                        local_target,
                        must_exist=True,
                    )

                    actual_size = (
                        local_target.stat().st_size
                    )

                    if actual_size != expected_size:
                        raise IntegrityError(
                            f"Downloaded artifact size mismatch "
                            f"for '{key}': "
                            f"expected={expected_size}, "
                            f"actual={actual_size}"
                        )

                    downloaded_hash = (
                        sha256_file(
                            local_target
                        ).lower()
                    )

                    if not hmac.compare_digest(
                        downloaded_hash,
                        expected_sha256,
                    ):
                        raise IntegrityError(
                            f"Downloaded SHA-256 mismatch "
                            f"for artifact '{key}'."
                        )

                    if verify_stream:
                        logger.info(
                            "Full content verification enabled "
                            "for artifact '%s'.",
                            key,
                        )

                        self.azure.verify_remote_blob(
                            blob_path=blob_path,
                            expected_size_bytes=expected_size,
                            expected_sha256=expected_sha256,
                            verify_content_stream=True,
                        )

                    local_artifacts[key] = (
                        local_target
                    )

                logger.info(
                    "[PASS] All recovery artifacts "
                    "passed integrity validation."
                )

            self._execute_stage(
                RecoveryState.BACKUP_ARTIFACTS_VALIDATED,
                artifacts_step,
            )

            # ---------------------------------------------------------
            # 5. Stop DR Tableau Server
            # ---------------------------------------------------------
            def stop_step() -> None:
                result = self.tsm.run(
                    [
                        "stop",
                        "--ignore-prompt",
                    ],
                    timeout=1800,
                )

                if not result.success:
                    raise RecoveryError(
                        "Failed to stop DR Tableau Server."
                    )

            self._execute_stage(
                RecoveryState.DR_STOPPED,
                stop_step,
            )

            # ---------------------------------------------------------
            # 6. Restore Repository
            # ---------------------------------------------------------
            def restore_step() -> None:
                tsbak_path = local_artifacts.get(
                    "backup.tsbak"
                )

                if not tsbak_path:
                    raise ValidationError(
                        "Required backup.tsbak artifact is unavailable."
                    )

                result = self.tsm.run(
                    [
                        "maintenance",
                        "restore",
                        "--file",
                        str(tsbak_path),
                    ],
                    timeout=14400,
                )

                if not result.success:
                    raise RecoveryError(
                        "Tableau repository restore failed."
                    )

            self._execute_stage(
                RecoveryState.REPOSITORY_RESTORED,
                restore_step,
            )

            # ---------------------------------------------------------
            # 7. Import Settings
            # ---------------------------------------------------------
            def settings_step() -> None:
                settings_path = local_artifacts.get(
                    "settings.json"
                )

                if not settings_path:
                    raise ValidationError(
                        "Required settings.json artifact is unavailable."
                    )

                result = self.tsm.run(
                    [
                        "settings",
                        "import",
                        "-f",
                        str(settings_path),
                    ],
                    timeout=1800,
                )

                if not result.success:
                    raise RecoveryError(
                        "Tableau settings import failed."
                    )

            self._execute_stage(
                RecoveryState.SETTINGS_IMPORTED,
                settings_step,
            )

            # ---------------------------------------------------------
            # 8. Security Rebinding
            # ---------------------------------------------------------
            self._execute_stage(
                RecoveryState.SECURITY_REBOUND,
                self._apply_key_vault_security_bindings,
            )

            # ---------------------------------------------------------
            # 9. Start DR Tableau Server
            # ---------------------------------------------------------
            def start_step() -> None:
                result = self.tsm.run(
                    ["start"],
                    timeout=3600,
                )

                if not result.success:
                    raise RecoveryError(
                        "Failed to start DR Tableau Server."
                    )

            self._execute_stage(
                RecoveryState.DR_STARTED,
                start_step,
            )

            # ---------------------------------------------------------
            # 10. Post-Restore Health Validation
            # ---------------------------------------------------------
            def health_step() -> None:
                nonlocal health_res

                checker = HealthChecker(
                    tsm_connector=self.tsm,
                    gateway_hostname=self.config.servers[
                        "disaster_recovery"
                    ]["hostname"],
                )

                health_res = (
                    checker.run_all_checks()
                )

                if not health_res.overall_healthy:
                    raise RecoveryError(
                        "DR health validation failed: "
                        f"{health_res.layers}"
                    )

            self._execute_stage(
                RecoveryState.HEALTH_VALIDATED,
                health_step,
            )

            # ---------------------------------------------------------
            # 11. Recovery Complete
            # ---------------------------------------------------------
            self.current_state = (
                RecoveryState.RECOVERY_COMPLETED
            )

            self.completed_steps.append(
                RecoveryState.RECOVERY_COMPLETED
            )

            final_state = (
                RecoveryState.RECOVERY_COMPLETED
            )

            logger.info(
                "[PASS] DR RECOVERY COMPLETED SUCCESSFULLY "
                "[RUN_ID=%s].",
                self.run_id,
            )

        except Exception as exc:
            failed_stage = self.current_state
            final_state = RecoveryState.FAILED

            logger.critical(
                "DR FAILOVER EXECUTION ABORTED "
                "[RUN_ID=%s] at [%s]: %s",
                self.run_id,
                self.current_state.value,
                exc,
            )

        completed_dt = (
            datetime.datetime.now(
                datetime.timezone.utc
            )
        )

        rpo_seconds = max(
            0.0,
            (
                disaster_declared_dt
                - backup_created_at_dt
            ).total_seconds(),
        )

        rto_seconds = max(
            0.0,
            (
                completed_dt
                - disaster_declared_dt
            ).total_seconds(),
        )

        return RecoveryResult(
            run_id=self.run_id,
            status=(
                "SUCCESS"
                if final_state
                == RecoveryState.RECOVERY_COMPLETED
                else "FAILED"
            ),
            current_state=final_state,
            completed_steps=self.completed_steps,
            failed_step=failed_stage,
            fencing_result=(
                fencing_res.to_dict()
                if fencing_res
                else None
            ),
            health_result=(
                health_res.to_dict()
                if health_res
                else None
            ),
            disaster_declared_at_utc=(
                disaster_declared_dt.isoformat()
            ),
            recovery_completed_at_utc=(
                completed_dt.isoformat()
            ),
            backup_created_at_utc=(
                backup_created_at_dt.isoformat()
            ),
            measured_backup_age_rpo_seconds=round(
                rpo_seconds,
                2,
            ),
            total_rto_seconds=round(
                rto_seconds,
                2,
            ),
            stage_timings={
                key: asdict(value)
                for key, value
                in self.stage_timings.items()
            },
        )

    def _apply_key_vault_security_bindings(
        self,
    ) -> None:
        """Retrieve DR SSL material from Key Vault and apply it through TSM."""

        kv_name = self.config.azure[
            "key_vault_name"
        ]

        if not kv_name.strip():
            raise ValidationError(
                "Azure Key Vault name is empty."
            )

        kv_uri = (
            f"https://{kv_name}.vault.azure.net"
        )

        try:
            credential = (
                DefaultAzureCredential()
            )

            secret_client = SecretClient(
                vault_url=kv_uri,
                credential=credential,
            )

            ssl_cert_secret = (
                secret_client.get_secret(
                    "tableau-dr-ssl-cert"
                )
            )

            ssl_key_secret = (
                secret_client.get_secret(
                    "tableau-dr-ssl-key"
                )
            )

        except Exception as exc:
            raise ValidationError(
                "Failed to retrieve DR SSL material "
                "from Azure Key Vault."
            ) from exc

        if not ssl_cert_secret.value:
            raise SecurityValidationError(
                "DR SSL certificate secret is empty."
            )

        if not ssl_key_secret.value:
            raise SecurityValidationError(
                "DR SSL private key secret is empty."
            )

        with tempfile.TemporaryDirectory(
            prefix=f"tableau_dr_{self.run_id}_"
        ) as temp_dir:
            temp_path = Path(temp_dir)

            cert_file = (
                temp_path / "ssl_cert.crt"
            )

            key_file = (
                temp_path / "ssl_key.key"
            )

            cert_file.write_text(
                ssl_cert_secret.value,
                encoding="utf-8",
            )

            key_file.write_text(
                ssl_key_secret.value,
                encoding="utf-8",
            )

            if os.name != "nt":
                os.chmod(
                    cert_file,
                    0o600,
                )
                os.chmod(
                    key_file,
                    0o600,
                )

            logger.info(
                "Applying DR SSL configuration through TSM..."
            )

            self.tsm.run(
                [
                    "security",
                    "external-ssl",
                    "enable",
                    "--cert-file",
                    str(cert_file),
                    "--key-file",
                    str(key_file),
                ],
                timeout=1800,
            )

            self.tsm.run(
                [
                    "pending-changes",
                    "apply",
                ],
                timeout=1800,
            )

    @staticmethod
    def _parse_utc_timestamp(
        timestamp: str,
    ) -> datetime.datetime:
        """Parse ISO-8601 timestamp and normalize it to UTC."""

        normalized = timestamp.strip()

        if normalized.endswith("Z"):
            normalized = (
                normalized[:-1]
                + "+00:00"
            )

        try:
            parsed = datetime.datetime.fromisoformat(
                normalized
            )
        except ValueError as exc:
            raise ValidationError(
                f"Invalid UTC timestamp in manifest: "
                f"{timestamp}"
            ) from exc

        if parsed.tzinfo is None:
            raise ValidationError(
                f"Manifest timestamp has no timezone: "
                f"{timestamp}"
            )

        return parsed.astimezone(
            datetime.timezone.utc
        )