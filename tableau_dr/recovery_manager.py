"""Enterprise state-machine Tableau Server DR recovery orchestrator."""

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
from typing import Any, Callable, Dict, List, Optional

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
from tableau_dr.validation import (
    validate_disk_space,
    validate_identity_store,
    validate_tableau_version,
)


logger = logging.getLogger(__name__)

MANIFEST_VERSION = "2.0"
EXPECTED_MANIFEST_STATUS = "ARTIFACTS_READY"

BACKUP_ARTIFACT_KEY = "backup.tsbak"
SETTINGS_ARTIFACT_KEY = "settings.json"

DEFAULT_MIN_FREE_SPACE_GB = 50.0
DEFAULT_RECOVERY_TIMEOUT_SECONDS = 14_400

MAX_MANIFEST_SIZE_BYTES = 10 * 1024 * 1024
MAX_ARTIFACT_FILENAME_LENGTH = 255


class RecoveryState(str, enum.Enum):
    """States used by the fail-closed recovery state machine."""

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
    """Timing information for an individual recovery stage."""

    started_at: str
    completed_at: str
    duration_seconds: float


@dataclass
class RecoveryResult:
    """Machine-readable result of a DR recovery execution."""

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
        """Return a JSON-serializable representation."""

        result = asdict(self)

        result["current_state"] = self.current_state.value
        result["completed_steps"] = [
            state.value for state in self.completed_steps
        ]
        result["failed_step"] = (
            self.failed_step.value
            if self.failed_step
            else None
        )

        return result


class RecoveryManager:
    """
    Execute fail-closed Tableau Server disaster recovery.

    Recovery sequence:

        Disaster Declaration
            ↓
        Production Fencing
            ↓
        DR Preflight
            ↓
        Manifest Acquisition + Validation
            ↓
        Artifact Download + Integrity Validation
            ↓
        Stop DR
            ↓
        Restore Repository
            ↓
        Import Settings
            ↓
        Rebind Security
            ↓
        Start DR
            ↓
        Health Validation
            ↓
        Recovery Completed

    Any failed stage aborts the state machine. Recovery never proceeds to
    a later destructive stage when an earlier safety gate has failed.
    """

    def __init__(
        self,
        config: Config,
        run_id: str,
    ) -> None:
        """Initialize recovery dependencies and an isolated work directory."""

        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError(
                "run_id must be a non-empty string."
            )

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

        self.fencer = ProductionFencer(config)

        self.completed_steps: List[RecoveryState] = []

        self.current_state = RecoveryState.DISASTER_DECLARED

        self.stage_timings: Dict[str, StageTiming] = {}

        self.work_dir = self._build_work_directory()

    def _build_work_directory(self) -> Path:
        """Build a run-isolated recovery workspace."""

        base_recovery_dir = Path(
            self.config.paths["recovery_work_dir"]
        ).expanduser()

        if not str(base_recovery_dir).strip():
            raise ValidationError(
                "Recovery work directory cannot be empty."
            )

        return (
            base_recovery_dir
            / f"recovery_{self.run_id}"
        )

    def _execute_stage(
        self,
        target_state: RecoveryState,
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """
        Execute one state-machine stage.

        The state is assigned before execution so failures are accurately
        attributed to the stage that was actually running.
        """

        logger.info(
            "Entering recovery state: %s",
            target_state.value,
        )

        stage_start = time.monotonic()

        started_at = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()

        self.current_state = target_state

        try:
            result = func(*args, **kwargs)

            completed_at = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()

            duration = round(
                time.monotonic() - stage_start,
                2,
            )

            self.stage_timings[target_state.value] = StageTiming(
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
            )

            self.completed_steps.append(
                target_state
            )

            logger.info(
                "Recovery state completed: %s duration_seconds=%s",
                target_state.value,
                duration,
            )

            return result

        except Exception as exc:
            logger.critical(
                "Recovery state failed: %s error=%s",
                target_state.value,
                self._sanitize_error(exc),
            )

            raise RecoveryError(
                f"Recovery failed at state {target_state.value}."
            ) from exc

    def execute_failover(
        self,
        emergency_auth_code: Optional[str] = None,
        operator_reason: Optional[str] = None,
        target_manifest_blob: Optional[str] = None,
    ) -> RecoveryResult:
        """Execute the complete DR failover state machine."""

        disaster_declared_dt = datetime.datetime.now(
            datetime.timezone.utc
        )

        self.completed_steps = [
            RecoveryState.DISASTER_DECLARED
        ]

        self.current_state = (
            RecoveryState.DISASTER_DECLARED
        )

        fencing_res: Optional[FencingResult] = None
        health_res: Optional[HealthCheckResult] = None

        backup_created_at_dt = disaster_declared_dt

        failed_stage: Optional[RecoveryState] = None

        final_state = RecoveryState.FAILED

        manifest_data: dict = {}

        try:
            self._prepare_work_directory()

            # ---------------------------------------------------------
            # 1. Production fencing
            # ---------------------------------------------------------
            self.current_state = RecoveryState.FENCING_PENDING

            def fencing_step() -> None:
                nonlocal fencing_res

                fencing_res = self.fencer.evaluate_fencing(
                    emergency_authorization_code=(
                        emergency_auth_code
                    ),
                    operator_reason=operator_reason,
                )

                if not fencing_res.is_fenced:
                    raise SecurityValidationError(
                        "Production fencing validation failed."
                    )

            self._execute_stage(
                RecoveryState.PRODUCTION_FENCED,
                fencing_step,
            )

            # ---------------------------------------------------------
            # 2. DR preflight
            # ---------------------------------------------------------
            def preflight_step() -> None:
                self._validate_dr_preflight()

            self._execute_stage(
                RecoveryState.DR_PREFLIGHT_PASSED,
                preflight_step,
            )

            # ---------------------------------------------------------
            # 3. Acquire and validate manifest
            # ---------------------------------------------------------
            local_manifest_path = (
                self.work_dir / "manifest.json"
            )

            def manifest_step() -> None:
                nonlocal manifest_data
                nonlocal backup_created_at_dt

                blob_name = (
                    self._resolve_manifest_blob(
                        target_manifest_blob
                    )
                )

                self._download_blob_to_file(
                    blob_name=blob_name,
                    target_path=local_manifest_path,
                    maximum_size_bytes=MAX_MANIFEST_SIZE_BYTES,
                )

                manifest_data = (
                    self._load_manifest(
                        local_manifest_path
                    )
                )

                backup_created_at_dt = (
                    self._validate_manifest(
                        manifest_data
                    )
                )

            self._execute_stage(
                RecoveryState.MANIFEST_VALIDATED,
                manifest_step,
            )

            # ---------------------------------------------------------
            # 4. Download and validate artifacts
            # ---------------------------------------------------------
            local_artifacts: Dict[str, Path] = {}

            def artifacts_step() -> None:
                self._download_and_validate_artifacts(
                    manifest_data=manifest_data,
                    local_artifacts=local_artifacts,
                )

            self._execute_stage(
                RecoveryState.BACKUP_ARTIFACTS_VALIDATED,
                artifacts_step,
            )

            # ---------------------------------------------------------
            # 5. Stop DR Server
            # ---------------------------------------------------------
            def stop_step() -> None:
                self.tsm.run(
                    [
                        "stop",
                        "--ignore-prompt",
                    ],
                    timeout=1800,
                    check=True,
                )

            self._execute_stage(
                RecoveryState.DR_STOPPED,
                stop_step,
            )

            # ---------------------------------------------------------
            # 6. Restore repository
            # ---------------------------------------------------------
            def restore_step() -> None:
                backup_path = local_artifacts.get(
                    BACKUP_ARTIFACT_KEY
                )

                if backup_path is None:
                    raise ValidationError(
                        "Required backup.tsbak artifact is missing."
                    )

                self.tsm.run(
                    [
                        "maintenance",
                        "restore",
                        "--file",
                        str(backup_path),
                    ],
                    timeout=DEFAULT_RECOVERY_TIMEOUT_SECONDS,
                    check=True,
                )

            self._execute_stage(
                RecoveryState.REPOSITORY_RESTORED,
                restore_step,
            )

            # ---------------------------------------------------------
            # 7. Import settings
            # ---------------------------------------------------------
            def settings_step() -> None:
                settings_path = local_artifacts.get(
                    SETTINGS_ARTIFACT_KEY
                )

                if settings_path is None:
                    raise ValidationError(
                        "Required settings.json artifact is missing."
                    )

                self.tsm.run(
                    [
                        "settings",
                        "import",
                        "-f",
                        str(settings_path),
                    ],
                    timeout=1800,
                    check=True,
                )

            self._execute_stage(
                RecoveryState.SETTINGS_IMPORTED,
                settings_step,
            )

            # ---------------------------------------------------------
            # 8. Security credential rebinding
            # ---------------------------------------------------------
            def security_step() -> None:
                self._apply_key_vault_security_bindings()

            self._execute_stage(
                RecoveryState.SECURITY_REBOUND,
                security_step,
            )

            # ---------------------------------------------------------
            # 9. Start DR Server
            # ---------------------------------------------------------
            def start_step() -> None:
                self.tsm.run(
                    ["start"],
                    timeout=3600,
                    check=True,
                )

            self._execute_stage(
                RecoveryState.DR_STARTED,
                start_step,
            )

            # ---------------------------------------------------------
            # 10. Post-restore health validation
            # ---------------------------------------------------------
            def health_step() -> None:
                nonlocal health_res

                dr_hostname = self.config.servers[
                    "disaster_recovery"
                ]["hostname"]

                checker = HealthChecker(
                    tsm_connector=self.tsm,
                    gateway_hostname=dr_hostname,
                )

                health_res = checker.run_all_checks()

                if not health_res.overall_healthy:
                    raise RecoveryError(
                        "DR health validation failed."
                    )

            self._execute_stage(
                RecoveryState.HEALTH_VALIDATED,
                health_step,
            )

            self.completed_steps.append(
                RecoveryState.RECOVERY_COMPLETED
            )

            final_state = (
                RecoveryState.RECOVERY_COMPLETED
            )

            logger.info(
                "Tableau DR recovery completed successfully. "
                "run_id=%s",
                self.run_id,
            )

        except Exception as exc:
            failed_stage = self.current_state
            final_state = RecoveryState.FAILED

            logger.critical(
                "DR recovery aborted at state=%s error=%s",
                self.current_state.value,
                self._sanitize_error(exc),
            )

            # Deliberately preserve the recovery workspace on failure.
            # It may contain evidence required for diagnosis.
            self._preserve_failed_recovery_workspace()

        completed_dt = datetime.datetime.now(
            datetime.timezone.utc
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
                for key, value in self.stage_timings.items()
            },
        )

    def _prepare_work_directory(self) -> None:
        """Create a unique recovery workspace without overwriting an existing run."""

        if self.work_dir.exists():
            raise SecurityValidationError(
                "Recovery work directory already exists. "
                "Refusing to reuse an existing recovery workspace."
            )

        self.work_dir.mkdir(
            parents=True,
            exist_ok=False,
        )

        minimum_free_space_gb = float(
            self.config.backup.get(
                "minimum_free_space_gb",
                DEFAULT_MIN_FREE_SPACE_GB,
            )
        )

        validate_disk_space(
            self.work_dir,
            required_gb=minimum_free_space_gb,
        )

    def _validate_dr_preflight(self) -> None:
        """Validate the DR target before destructive restore operations."""

        status_result = self.tsm.status()

        if not status_result.success:
            raise ValidationError(
                "Target DR TSM cluster is not responding."
            )

        dr_hostname = self.config.servers[
            "disaster_recovery"
        ]["hostname"]

        production_hostname = self.config.servers[
            "production"
        ]["hostname"]

        if (
            dr_hostname.strip().lower()
            == production_hostname.strip().lower()
        ):
            raise SecurityValidationError(
                "Production and DR hostnames must never be identical."
            )

        logger.info(
            "DR preflight validation passed."
        )

    def _resolve_manifest_blob(
        self,
        target_manifest_blob: Optional[str],
    ) -> str:
        """Resolve an explicit manifest or discover the newest valid manifest."""

        if target_manifest_blob:
            return self._validate_blob_reference(
                target_manifest_blob
            )

        try:
            blobs = self.azure.container_client.list_blobs(
                name_starts_with="backups/"
            )

            manifest_blobs = sorted(
                blob.name
                for blob in blobs
                if (
                    isinstance(blob.name, str)
                    and blob.name.endswith(".json")
                    and "/manifest_" in blob.name
                )
            )

        except AzureError as exc:
            raise RecoveryError(
                "Unable to enumerate recovery manifests."
            ) from exc

        if not manifest_blobs:
            raise ValidationError(
                "No valid recovery manifest was found."
            )

        return self._validate_blob_reference(
            manifest_blobs[-1]
        )

    @staticmethod
    def _validate_blob_reference(
        blob_name: str,
    ) -> str:
        """Validate a remote Blob path before it is used."""

        if (
            not isinstance(blob_name, str)
            or not blob_name.strip()
        ):
            raise SecurityValidationError(
                "Manifest Blob path must be a non-empty string."
            )

        normalized = (
            blob_name.strip()
            .replace("\\", "/")
        )

        if normalized.startswith("/"):
            raise SecurityValidationError(
                "Manifest Blob path must not begin with '/'."
            )

        if "\x00" in normalized:
            raise SecurityValidationError(
                "Manifest Blob path contains a null character."
            )

        if any(
            part == ".."
            for part in normalized.split("/")
        ):
            raise SecurityValidationError(
                "Manifest Blob path contains traversal components."
            )

        if not normalized.startswith("backups/"):
            raise SecurityValidationError(
                "Manifest Blob must be located under the backups prefix."
            )

        if not normalized.endswith(".json"):
            raise SecurityValidationError(
                "Recovery manifest must be a JSON Blob."
            )

        return normalized

    def _download_blob_to_file(
        self,
        blob_name: str,
        target_path: Path,
        maximum_size_bytes: Optional[int] = None,
    ) -> None:
        """Download a Blob to an isolated local file with size enforcement."""

        blob_name = self._validate_blob_reference(
            blob_name
        )

        blob_client = (
            self.azure.container_client.get_blob_client(
                blob_name
            )
        )

        try:
            properties = blob_client.get_blob_properties()

            if (
                maximum_size_bytes is not None
                and properties.size > maximum_size_bytes
            ):
                raise SecurityValidationError(
                    f"Remote artifact '{blob_name}' exceeds the "
                    "allowed download size."
                )

            target_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            stream = blob_client.download_blob()

            with target_path.open(
                "wb"
            ) as output:
                for chunk in stream.chunks():
                    output.write(chunk)

        except (
            SecurityValidationError,
            RecoveryError,
        ):
            raise

        except AzureError as exc:
            raise RecoveryError(
                f"Unable to download recovery artifact '{blob_name}'."
            ) from exc

        except OSError as exc:
            raise RecoveryError(
                "Unable to write downloaded recovery artifact."
            ) from exc

    @staticmethod
    def _load_manifest(
        manifest_path: Path,
    ) -> dict:
        """Load and structurally validate the local manifest JSON."""

        validate_file(
            manifest_path,
            must_exist=True,
        )

        try:
            with manifest_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

        except json.JSONDecodeError as exc:
            raise ValidationError(
                "Recovery manifest contains invalid JSON."
            ) from exc

        except OSError as exc:
            raise ValidationError(
                "Unable to read recovery manifest."
            ) from exc

        if not isinstance(data, dict):
            raise ValidationError(
                "Recovery manifest root must be a JSON object."
            )

        return data

    def _validate_manifest(
        self,
        manifest_data: dict,
    ) -> datetime.datetime:
        """Validate manifest version, source, timing, and artifact inventory."""

        if (
            manifest_data.get("manifest_version")
            != MANIFEST_VERSION
        ):
            raise ValidationError(
                "Unsupported recovery manifest version."
            )

        if (
            manifest_data.get("status")
            != EXPECTED_MANIFEST_STATUS
        ):
            raise ValidationError(
                "Recovery manifest is not in an artifacts-ready state."
            )

        manifest_run_id = manifest_data.get(
            "run_id"
        )

        if (
            not isinstance(manifest_run_id, str)
            or not manifest_run_id.strip()
        ):
            raise ValidationError(
                "Recovery manifest is missing a valid run_id."
            )

        source = manifest_data.get(
            "source"
        )

        if not isinstance(source, dict):
            raise ValidationError(
                "Recovery manifest source section is invalid."
            )

        source_version = source.get(
            "tableau_version"
        )

        target_version = self.config.environment[
            "version"
        ]

        validate_tableau_version(
            backup_version=source_version,
            dr_version=target_version,
        )

        source_identity_store = source.get(
            "identity_store"
        )

        target_identity_store = self.config.servers[
            "disaster_recovery"
        ]["identity_store"]

        validate_identity_store(
            source_store=source_identity_store,
            dr_store=target_identity_store,
        )

        production_hostname = self.config.servers[
            "production"
        ]["hostname"]

        manifest_hostname = source.get(
            "hostname"
        )

        if (
            not isinstance(manifest_hostname, str)
            or not manifest_hostname.strip()
        ):
            raise ValidationError(
                "Recovery manifest source hostname is invalid."
            )

        if (
            manifest_hostname.strip().lower()
            != production_hostname.strip().lower()
        ):
            raise SecurityValidationError(
                "Recovery manifest source hostname does not match "
                "the configured production server."
            )

        timing = manifest_data.get(
            "timing"
        )

        if not isinstance(timing, dict):
            raise ValidationError(
                "Recovery manifest timing section is invalid."
            )

        started_at = timing.get(
            "started_at_utc"
        )

        if (
            not isinstance(started_at, str)
            or not started_at.strip()
        ):
            raise ValidationError(
                "Recovery manifest is missing backup creation time."
            )

        backup_created_at = (
            self._parse_utc_timestamp(
                started_at
            )
        )

        if backup_created_at > datetime.datetime.now(
            datetime.timezone.utc
        ):
            raise ValidationError(
                "Recovery manifest backup timestamp is in the future."
            )

        artifacts = manifest_data.get(
            "artifacts"
        )

        if not isinstance(artifacts, dict):
            raise ValidationError(
                "Recovery manifest artifact inventory is invalid."
            )

        required_artifacts = {
            BACKUP_ARTIFACT_KEY,
            SETTINGS_ARTIFACT_KEY,
        }

        missing = required_artifacts - set(
            artifacts.keys()
        )

        if missing:
            raise ValidationError(
                "Recovery manifest is missing required artifacts: "
                + ", ".join(sorted(missing))
            )

        for key, metadata in artifacts.items():
            self._validate_artifact_metadata(
                key=key,
                metadata=metadata,
            )

        logger.info(
            "Recovery manifest validation passed. "
            "source_version=%s target_version=%s",
            source_version,
            target_version,
        )

        return backup_created_at

    def _validate_artifact_metadata(
        self,
        key: str,
        metadata: Any,
    ) -> None:
        """Validate an individual artifact manifest entry."""

        if not isinstance(metadata, dict):
            raise ValidationError(
                f"Artifact metadata is invalid for '{key}'."
            )

        filename = metadata.get(
            "filename"
        )

        if (
            not isinstance(filename, str)
            or not filename.strip()
            or len(filename) > MAX_ARTIFACT_FILENAME_LENGTH
        ):
            raise SecurityValidationError(
                f"Invalid artifact filename for '{key}'."
            )

        filename_path = Path(filename)

        if (
            filename_path.name != filename
            or filename in {".", ".."}
            or "/" in filename
            or "\\" in filename
            or "\x00" in filename
        ):
            raise SecurityValidationError(
                f"Unsafe artifact filename for '{key}'."
            )

        blob_path = metadata.get(
            "blob_path"
        )

        normalized_blob_path = (
            self.azure._validate_blob_path(
                blob_path
            )
        )

        if not normalized_blob_path.startswith(
            "backups/"
        ):
            raise SecurityValidationError(
                f"Artifact '{key}' is outside the backup prefix."
            )

        sha256 = metadata.get(
            "sha256"
        )

        self.azure._validate_sha256(
            sha256
        )

        size_bytes = metadata.get(
            "size_bytes"
        )

        if (
            isinstance(size_bytes, bool)
            or not isinstance(size_bytes, int)
            or size_bytes <= 0
        ):
            raise ValidationError(
                f"Invalid artifact size for '{key}'."
            )

        logical_name = metadata.get(
            "logical_name"
        )

        if (
            not isinstance(logical_name, str)
            or not logical_name.strip()
        ):
            raise ValidationError(
                f"Invalid logical artifact name for '{key}'."
            )

    def _download_and_validate_artifacts(
        self,
        manifest_data: dict,
        local_artifacts: Dict[str, Path],
    ) -> None:
        """Download all manifest artifacts and verify size plus SHA-256."""

        artifacts = manifest_data[
            "artifacts"
        ]

        for key, metadata in artifacts.items():
            filename = metadata["filename"]

            local_target = (
                self.work_dir / filename
            )

            self._validate_local_target(
                local_target
            )

            blob_path = (
                self.azure._validate_blob_path(
                    metadata["blob_path"]
                )
            )

            expected_size = metadata[
                "size_bytes"
            ]

            expected_sha256 = (
                self.azure._validate_sha256(
                    metadata["sha256"]
                )
            )

            logger.info(
                "Downloading recovery artifact '%s'.",
                filename,
            )

            self._download_blob_to_file(
                blob_name=blob_path,
                target_path=local_target,
                maximum_size_bytes=(
                    expected_size
                    if expected_size > 0
                    else None
                ),
            )

            validate_file(
                local_target,
                must_exist=True,
            )

            actual_size = local_target.stat().st_size

            if actual_size != expected_size:
                raise IntegrityError(
                    f"Downloaded artifact size mismatch for '{key}'."
                )

            actual_sha256 = sha256_file(
                local_target
            )

            if not self._constant_time_equal(
                actual_sha256,
                expected_sha256,
            ):
                raise IntegrityError(
                    f"Downloaded artifact SHA-256 mismatch for '{key}'."
                )

            # Verify the remote object's metadata/content again.
            # This catches a mismatch between the manifest and the
            # currently stored remote object before restoration.
            self.azure.verify_remote_blob(
                blob_path=blob_path,
                expected_size_bytes=expected_size,
                expected_sha256=expected_sha256,
                verify_content_stream=bool(
                    self.config.backup.get(
                        "verify_remote_content_sha256",
                        False,
                    )
                ),
            )

            local_artifacts[key] = local_target

        logger.info(
            "All recovery artifacts passed integrity validation."
        )

    def _validate_local_target(
        self,
        target: Path,
    ) -> None:
        """Ensure a downloaded artifact remains inside the recovery workspace."""

        try:
            target.parent.resolve().relative_to(
                self.work_dir.resolve()
            )
        except ValueError as exc:
            raise SecurityValidationError(
                "Recovery artifact path escapes the isolated work directory."
            ) from exc

        if target.exists():
            raise SecurityValidationError(
                f"Recovery artifact already exists: {target.name}"
            )

    def _apply_key_vault_security_bindings(
        self,
    ) -> None:
        """
        Retrieve DR security material from Azure Key Vault and apply it via TSM.

        Secret values are never logged. Temporary credential files are removed
        automatically when the context exits.
        """

        key_vault_name = self.config.azure[
            "key_vault_name"
        ]

        if (
            not isinstance(key_vault_name, str)
            or not key_vault_name.strip()
        ):
            raise SecurityValidationError(
                "Azure Key Vault name is not configured."
            )

        key_vault_uri = (
            f"https://{key_vault_name.strip()}"
            ".vault.azure.net"
        )

        try:
            credential = DefaultAzureCredential()

            secret_client = SecretClient(
                vault_url=key_vault_uri,
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

        except AzureError as exc:
            raise SecurityValidationError(
                "Unable to retrieve DR security material from Key Vault."
            ) from exc

        if (
            not ssl_cert_secret.value
            or not ssl_key_secret.value
        ):
            raise SecurityValidationError(
                "Required DR SSL security material is missing."
            )

        with tempfile.TemporaryDirectory(
            prefix="tableau_dr_security_"
        ) as temp_dir:
            temp_path = Path(temp_dir)

            cert_file = (
                temp_path / "ssl_cert.crt"
            )

            key_file = (
                temp_path / "ssl_key.key"
            )

            try:
                cert_file.write_text(
                    ssl_cert_secret.value,
                    encoding="utf-8",
                    newline="\n",
                )

                key_file.write_text(
                    ssl_key_secret.value,
                    encoding="utf-8",
                    newline="\n",
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
                    "Applying DR external SSL configuration via TSM."
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
                    check=True,
                )

                self.tsm.run(
                    [
                        "pending-changes",
                        "apply",
                    ],
                    timeout=1800,
                    check=True,
                )

            except OSError as exc:
                raise SecurityValidationError(
                    "Unable to create temporary DR security files."
                ) from exc

    @staticmethod
    def _parse_utc_timestamp(
        timestamp: str,
    ) -> datetime.datetime:
        """Parse an ISO-8601 timestamp and require timezone awareness."""

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
                "Invalid UTC timestamp in recovery manifest."
            ) from exc

        if parsed.tzinfo is None:
            raise ValidationError(
                "Recovery manifest timestamp must contain timezone information."
            )

        return parsed.astimezone(
            datetime.timezone.utc
        )

    @staticmethod
    def _constant_time_equal(
        actual: str,
        expected: str,
    ) -> bool:
        """Perform constant-time string comparison for integrity values."""

        import hmac

        return hmac.compare_digest(
            actual.lower(),
            expected.lower(),
        )

    def _preserve_failed_recovery_workspace(
        self,
    ) -> None:
        """Log that failed recovery evidence is intentionally preserved."""

        if self.work_dir.exists():
            logger.warning(
                "Recovery workspace preserved for diagnosis: %s",
                self.work_dir.name,
            )

    @staticmethod
    def _sanitize_error(
        error: object,
    ) -> str:
        """Return a safe error representation without common secret material."""

        text = str(error)

        sensitive_terms = (
            "password",
            "passwd",
            "passphrase",
            "secret",
            "token",
            "access_token",
            "client_secret",
            "sas",
            "private_key",
        )

        if any(
            term in text.lower()
            for term in sensitive_terms
        ):
            return "[REDACTED_ERROR]"

        return text[:1000]