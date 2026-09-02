"""
Enterprise Tableau Server Disaster Recovery recovery orchestrator.

The recovery workflow is intentionally fail-closed:

    DISASTER_DECLARED
        -> FENCING_PENDING
        -> PRODUCTION_FENCED
        -> DR_PREFLIGHT_PASSED
        -> MANIFEST_VALIDATED
        -> BACKUP_ARTIFACTS_VALIDATED
        -> DR_STOPPED
        -> REPOSITORY_RESTORED
        -> SETTINGS_IMPORTED
        -> SECURITY_REBOUND
        -> DR_STARTED
        -> HEALTH_VALIDATED
        -> RECOVERY_COMPLETED

Any unexpected failure moves the workflow to FAILED.

Security principles:
- Never trust artifact names or blob paths from the manifest.
- Never restore an artifact whose integrity has not been validated.
- Never continue after a fencing failure.
- Never expose Key Vault secrets in logs.
- Never reuse a recovery workspace.
- Never report successful recovery unless health validation succeeds.
- Recovery run IDs and backup run IDs are independent identifiers.
- Temporary private-key files receive restrictive operating-system permissions.
"""

from __future__ import annotations

import datetime as dt
import enum
import hmac
import json
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from .azure_manager import AzureManager
from .config import Config
from .exceptions import RecoveryError
from .fencing import FencingResult, ProductionFencer
from .health_check import HealthCheckResult, HealthChecker
from .security import sha256_file
from .tab_server_connector import TSMConnector
from .validation import validate_identity_store, validate_tableau_version


LOGGER = logging.getLogger(__name__)


class RecoveryState(str, enum.Enum):
    """Recovery state machine states."""

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
class RecoveryResult:
    """Structured result returned by the recovery workflow."""

    run_id: str
    status: str
    current_state: str
    completed_steps: List[str]
    failed_step: Optional[str]
    fencing_result: Optional[Dict[str, Any]]
    health_result: Optional[Dict[str, Any]]
    disaster_declared_at_utc: str
    recovery_completed_at_utc: Optional[str]
    backup_created_at_utc: Optional[str]
    measured_backup_age_rpo_seconds: Optional[float]
    total_rto_seconds: Optional[float]
    stage_timings: Dict[str, float]


class RecoveryManager:
    """High-level fail-closed Tableau Server DR recovery orchestrator."""

    MANIFEST_VERSION = "2.0"
    MANIFEST_STATUS = "ARTIFACTS_READY"

    REQUIRED_ARTIFACTS = {
        "backup.tsbak",
        "settings.json",
    }

    MAX_MANIFEST_SIZE_BYTES = 10 * 1024 * 1024
    MAX_ARTIFACT_SIZE_BYTES = 1024 * 1024 * 1024 * 1024

    SAFE_NAME_PATTERN = re.compile(
        r"^[A-Za-z0-9_.-]+$"
    )

    SHA256_PATTERN = re.compile(
        r"^[a-fA-F0-9]{64}$"
    )

    RUN_ID_PATTERN = re.compile(
        r"^[A-Za-z0-9_.-]+$"
    )

    WINDOWS_ACL_TIMEOUT_SECONDS = 30

    def __init__(
        self,
        config: Config,
        run_id: str,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.config = config
        self.run_id = self._validate_run_id(run_id)
        self.logger = logger or LOGGER

        self.tsm = TSMConnector(
            config=config,
            logger_instance=self.logger,
        )

        self.azure = AzureManager(
            account_name=config.azure["storage_account_name"],
            container_name=config.azure["storage_container"],
            max_retries=config.azure["max_retries"],
            backoff_factor=config.azure["retry_backoff_factor"],
        )

        self.fencer = ProductionFencer(
            config=config,
        )

        dr_hostname = str(
            config.servers["disaster_recovery"]["hostname"]
        ).strip()

        self.health_checker = HealthChecker(
            tsm_connector=self.tsm,
            gateway_hostname=dr_hostname,
        )

        self.current_state = RecoveryState.DISASTER_DECLARED
        self.completed_steps: List[str] = [
            RecoveryState.DISASTER_DECLARED.value
        ]
        self.stage_timings: Dict[str, float] = {}

        self.failed_step: Optional[str] = None
        self.fencing_result: Optional[FencingResult] = None
        self.health_result: Optional[HealthCheckResult] = None

        self.disaster_declared_at = dt.datetime.now(
            dt.timezone.utc
        )

        self.recovery_completed_at: Optional[dt.datetime] = None
        self.backup_created_at: Optional[dt.datetime] = None

        self.work_dir: Optional[Path] = None
        self.manifest: Optional[Dict[str, Any]] = None

        self._validate_configuration()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute_failover(
        self,
        *,
        target_manifest_blob: Optional[str] = None,
        emergency_auth_code: Optional[str] = None,
        operator_reason: Optional[str] = None,
    ) -> RecoveryResult:
        """
        Execute the complete DR failover workflow.

        Recovery stops immediately after the first failed stage.
        """

        recovery_start = time.monotonic()

        try:
            self._prepare_work_directory()

            self._execute_stage(
                RecoveryState.FENCING_PENDING,
                self._fence_production,
                emergency_auth_code,
                operator_reason,
            )

            self._execute_stage(
                RecoveryState.PRODUCTION_FENCED,
                self._verify_fencing,
            )

            self._execute_stage(
                RecoveryState.DR_PREFLIGHT_PASSED,
                self._validate_dr_preflight,
            )

            self._execute_stage(
                RecoveryState.MANIFEST_VALIDATED,
                self._acquire_and_validate_manifest,
                target_manifest_blob,
            )

            self._execute_stage(
                RecoveryState.BACKUP_ARTIFACTS_VALIDATED,
                self._download_and_validate_artifacts,
            )

            self._execute_stage(
                RecoveryState.DR_STOPPED,
                self._stop_dr,
            )

            self._execute_stage(
                RecoveryState.REPOSITORY_RESTORED,
                self._restore_repository,
            )

            self._execute_stage(
                RecoveryState.SETTINGS_IMPORTED,
                self._import_settings,
            )

            self._execute_stage(
                RecoveryState.SECURITY_REBOUND,
                self._apply_key_vault_security_bindings,
            )

            self._execute_stage(
                RecoveryState.DR_STARTED,
                self._start_dr,
            )

            self._execute_stage(
                RecoveryState.HEALTH_VALIDATED,
                self._validate_health,
            )

            self.current_state = RecoveryState.RECOVERY_COMPLETED
            self.completed_steps.append(
                self.current_state.value
            )

            self.failed_step = None

            self.recovery_completed_at = (
                dt.datetime.now(dt.timezone.utc)
            )

            total_rto = (
                time.monotonic() - recovery_start
            )

            return self._build_result(
                status="SUCCESS",
                total_rto_seconds=total_rto,
            )

        except Exception:
            failed_stage = self.failed_step

            self.current_state = RecoveryState.FAILED

            if failed_stage is None:
                failed_stage = "RECOVERY_INITIALIZATION"

            self.failed_step = failed_stage

            self._preserve_failed_recovery_workspace()

            self.logger.error(
                "DR recovery failed at stage '%s'; "
                "recovery workspace preserved",
                failed_stage,
            )

            total_rto = (
                time.monotonic() - recovery_start
            )

            return self._build_result(
                status="FAILED",
                total_rto_seconds=total_rto,
            )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @classmethod
    def _validate_run_id(
        cls,
        run_id: str,
    ) -> str:
        """Validate a recovery or backup run identifier."""

        if not isinstance(run_id, str):
            raise ValueError(
                "run_id must be a string"
            )

        value = run_id.strip()

        if not value:
            raise ValueError(
                "run_id cannot be empty"
            )

        if len(value) > 128:
            raise ValueError(
                "run_id is too long"
            )

        if not cls.RUN_ID_PATTERN.fullmatch(value):
            raise ValueError(
                "run_id contains invalid characters"
            )

        return value

    def _validate_configuration(self) -> None:
        """Validate critical recovery configuration."""

        production = self.config.servers["production"]
        disaster_recovery = (
            self.config.servers["disaster_recovery"]
        )

        production_hostname = str(
            production["hostname"]
        ).strip().lower()

        dr_hostname = str(
            disaster_recovery["hostname"]
        ).strip().lower()

        if not production_hostname or not dr_hostname:
            raise RecoveryError(
                "Production and DR hostnames are required"
            )

        if production_hostname == dr_hostname:
            raise RecoveryError(
                "Production and DR hostnames must be different"
            )

        validate_identity_store(
            production["identity_store"],
            disaster_recovery["identity_store"],
        )

        if not str(
            self.config.azure["storage_account_name"]
        ).strip():
            raise RecoveryError(
                "Azure storage account is not configured"
            )

        if not str(
            self.config.azure["storage_container"]
        ).strip():
            raise RecoveryError(
                "Azure storage container is not configured"
            )

        if not str(
            self.config.azure["key_vault_name"]
        ).strip():
            raise RecoveryError(
                "Azure Key Vault is not configured"
            )

    # ------------------------------------------------------------------
    # State machine
    # ------------------------------------------------------------------

    def _execute_stage(
        self,
        state: RecoveryState,
        callback: Any,
        *args: Any,
    ) -> None:
        """Execute one recovery stage and record its timing."""

        stage_name = state.value

        self.current_state = state
        self.failed_step = stage_name

        started = time.monotonic()

        try:
            callback(*args)

            elapsed = time.monotonic() - started

            self.stage_timings[stage_name] = round(
                elapsed,
                3,
            )

            self.completed_steps.append(
                stage_name
            )

        except Exception as exc:
            elapsed = time.monotonic() - started

            self.stage_timings[stage_name] = round(
                elapsed,
                3,
            )

            self.logger.error(
                "Recovery stage failed: %s",
                stage_name,
            )

            raise RecoveryError(
                f"Recovery stage failed: {stage_name}"
            ) from exc

    # ------------------------------------------------------------------
    # Stage 1 - Fencing
    # ------------------------------------------------------------------

    def _fence_production(
        self,
        emergency_auth_code: Optional[str],
        operator_reason: Optional[str],
    ) -> None:
        """Production must be fenced before destructive DR operations."""

        if operator_reason is not None:
            operator_reason = operator_reason.strip()

            if not operator_reason:
                raise RecoveryError(
                    "Operator reason cannot be empty"
                )

            if len(operator_reason) > 1000:
                raise RecoveryError(
                    "Operator reason exceeds maximum length"
                )

        self.fencing_result = (
            self.fencer.evaluate_fencing(
                emergency_authorization_code=emergency_auth_code,
                operator_reason=operator_reason,
            )
        )

        if not self.fencing_result.is_fenced:
            raise RecoveryError(
                "Production fencing was not confirmed"
            )

    def _verify_fencing(self) -> None:
        """Verify that production fencing was actually confirmed."""

        if self.fencing_result is None:
            raise RecoveryError(
                "Fencing result is unavailable"
            )

        if not self.fencing_result.is_fenced:
            raise RecoveryError(
                "Production fencing failed"
            )

    # ------------------------------------------------------------------
    # Stage 2 - DR preflight
    # ------------------------------------------------------------------

    def _validate_dr_preflight(self) -> None:
        """Validate DR availability and required recovery disk space."""

        result = self.tsm.status()

        if not result.success:
            raise RecoveryError(
                "Unable to verify DR Tableau Server status"
            )

        production_hostname = str(
            self.config.servers["production"]["hostname"]
        ).strip().lower()

        dr_hostname = str(
            self.config.servers["disaster_recovery"]["hostname"]
        ).strip().lower()

        if production_hostname == dr_hostname:
            raise RecoveryError(
                "Production and DR hostnames are identical"
            )

        recovery_root = Path(
            self.config.paths["recovery_work_dir"]
        )

        recovery_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        disk = shutil.disk_usage(
            recovery_root
        )

        required_gb = float(
            self.config.backup["minimum_free_space_gb"]
        )

        if required_gb <= 0:
            raise RecoveryError(
                "Configured minimum free space must be positive"
            )

        required_bytes = int(
            required_gb * 1024 * 1024 * 1024
        )

        if disk.free < required_bytes:
            raise RecoveryError(
                "Insufficient disk space on DR recovery volume"
            )

    # ------------------------------------------------------------------
    # Stage 3 - Work directory
    # ------------------------------------------------------------------

    def _prepare_work_directory(self) -> None:
        """Create a unique isolated recovery workspace."""

        recovery_root = Path(
            self.config.paths["recovery_work_dir"]
        ).resolve()

        recovery_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        timestamp = dt.datetime.now(
            dt.timezone.utc
        ).strftime("%Y%m%dT%H%M%SZ")

        directory_name = (
            f"recovery_{timestamp}_{self.run_id}"
        )

        work_dir = (
            recovery_root / directory_name
        )

        if work_dir.exists():
            raise RecoveryError(
                "Recovery workspace already exists"
            )

        work_dir.mkdir(
            parents=True,
            exist_ok=False,
        )

        self.work_dir = work_dir

    # ------------------------------------------------------------------
    # Stage 4 - Manifest
    # ------------------------------------------------------------------

    def _acquire_and_validate_manifest(
        self,
        manifest_blob: Optional[str],
    ) -> None:
        """Acquire and validate the selected recovery manifest."""

        if manifest_blob:
            blob_name = (
                self._validate_blob_reference(
                    manifest_blob
                )
            )
        else:
            blob_name = (
                self._resolve_latest_manifest_blob()
            )

        if not blob_name.endswith(".json"):
            raise RecoveryError(
                "Recovery manifest must be a JSON object"
            )

        local_manifest = (
            self._download_blob_to_file(
                blob_name=blob_name,
                destination=(
                    self._require_work_dir()
                    / "manifest.json"
                ),
                maximum_size=(
                    self.MAX_MANIFEST_SIZE_BYTES
                ),
            )
        )

        manifest = self._load_manifest(
            local_manifest
        )

        self._validate_manifest(
            manifest
        )

        self.manifest = manifest

        self._set_backup_timestamp(
            manifest
        )

    def _resolve_latest_manifest_blob(self) -> str:
        """Resolve the newest manifest under the controlled backup prefix."""

        blobs = self.azure.list_blobs(
            prefix="backups/"
        )

        candidates: List[str] = []

        for blob in blobs:
            name = self._extract_blob_name(
                blob
            )

            if not name:
                continue

            normalized = name.replace(
                "\\",
                "/",
            )

            if (
                normalized.startswith("backups/")
                and "/manifest_" in normalized
                and normalized.endswith(".json")
            ):
                candidates.append(
                    normalized
                )

        if not candidates:
            raise RecoveryError(
                "No recovery manifest was found"
            )

        candidates.sort()

        return self._validate_blob_reference(
            candidates[-1]
        )

    @staticmethod
    def _extract_blob_name(
        blob: Any,
    ) -> Optional[str]:
        """Extract a blob name from common Azure SDK result formats."""

        if isinstance(blob, str):
            return blob

        if isinstance(blob, dict):
            value = blob.get("name")

            if isinstance(value, str):
                return value

        value = getattr(
            blob,
            "name",
            None,
        )

        if isinstance(value, str):
            return value

        return None

    def _validate_blob_reference(
        self,
        blob_name: str,
    ) -> str:
        """Validate a manifest-supplied Azure Blob path."""

        if not isinstance(blob_name, str):
            raise RecoveryError(
                "Blob reference must be a string"
            )

        value = blob_name.strip().replace(
            "\\",
            "/",
        )

        if not value:
            raise RecoveryError(
                "Blob reference cannot be empty"
            )

        if "\x00" in value:
            raise RecoveryError(
                "Blob reference contains invalid characters"
            )

        if value.startswith("/"):
            raise RecoveryError(
                "Absolute blob paths are not permitted"
            )

        if ":" in value:
            raise RecoveryError(
                "Drive-qualified blob paths are not permitted"
            )

        if len(value) > 1024:
            raise RecoveryError(
                "Blob path is too long"
            )

        parts = value.split("/")

        if any(
            part in {"", ".", ".."}
            for part in parts
        ):
            raise RecoveryError(
                "Invalid blob path"
            )

        if not value.startswith("backups/"):
            raise RecoveryError(
                "Blob must be located under backups/"
            )

        if not (
            value.endswith(".json")
            or value.endswith(".tsbak")
        ):
            raise RecoveryError(
                "Unsupported recovery artifact type"
            )

        return value

    # ------------------------------------------------------------------
    # Manifest validation
    # ------------------------------------------------------------------

    def _load_manifest(
        self,
        manifest_path: Path,
    ) -> Dict[str, Any]:
        """Load a bounded UTF-8 JSON manifest."""

        try:
            raw = manifest_path.read_bytes()

        except OSError as exc:
            raise RecoveryError(
                "Unable to read recovery manifest"
            ) from exc

        if len(raw) > self.MAX_MANIFEST_SIZE_BYTES:
            raise RecoveryError(
                "Recovery manifest exceeds maximum size"
            )

        try:
            manifest = json.loads(
                raw.decode("utf-8")
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise RecoveryError(
                "Recovery manifest is not valid UTF-8 JSON"
            ) from exc

        if not isinstance(manifest, dict):
            raise RecoveryError(
                "Recovery manifest root must be an object"
            )

        return manifest

    def _validate_manifest(
        self,
        manifest: Dict[str, Any],
    ) -> None:
        """Validate manifest schema and trust boundaries."""

        if manifest.get(
            "manifest_version"
        ) != self.MANIFEST_VERSION:
            raise RecoveryError(
                "Unsupported manifest version"
            )

        if manifest.get(
            "status"
        ) != self.MANIFEST_STATUS:
            raise RecoveryError(
                "Manifest is not marked ARTIFACTS_READY"
            )

        manifest_run_id = manifest.get(
            "run_id"
        )

        if not isinstance(
            manifest_run_id,
            str,
        ):
            raise RecoveryError(
                "Manifest run_id is missing"
            )

        try:
            self._validate_run_id(
                manifest_run_id
            )
        except ValueError as exc:
            raise RecoveryError(
                "Manifest run_id is invalid"
            ) from exc

        source = manifest.get(
            "source"
        )

        if not isinstance(
            source,
            dict,
        ):
            raise RecoveryError(
                "Manifest source section is invalid"
            )

        source_version = source.get(
            "version"
        )

        source_hostname = source.get(
            "hostname"
        )

        source_identity_store = source.get(
            "identity_store"
        )

        if not source_version:
            raise RecoveryError(
                "Manifest source version is missing"
            )

        if not source_hostname:
            raise RecoveryError(
                "Manifest source hostname is missing"
            )

        if not source_identity_store:
            raise RecoveryError(
                "Manifest identity store is missing"
            )

        dr_version = self.config.environment[
            "version"
        ]

        validate_tableau_version(
            source_version,
            dr_version,
        )

        validate_identity_store(
            source_identity_store,
            self.config.servers[
                "disaster_recovery"
            ]["identity_store"],
        )

        configured_production_hostname = str(
            self.config.servers[
                "production"
            ]["hostname"]
        ).strip().lower()

        if (
            str(source_hostname)
            .strip()
            .lower()
            != configured_production_hostname
        ):
            raise RecoveryError(
                "Manifest source hostname does not match production"
            )

        timing = manifest.get(
            "timing"
        )

        if not isinstance(
            timing,
            dict,
        ):
            raise RecoveryError(
                "Manifest timing section is invalid"
            )

        backup_created = timing.get(
            "backup_created_at_utc"
        )

        if not isinstance(
            backup_created,
            str,
        ):
            raise RecoveryError(
                "Manifest backup timestamp is missing"
            )

        backup_created_dt = (
            self._parse_utc_timestamp(
                backup_created
            )
        )

        now = dt.datetime.now(
            dt.timezone.utc
        )

        if backup_created_dt > (
            now + dt.timedelta(minutes=5)
        ):
            raise RecoveryError(
                "Manifest backup timestamp is in the future"
            )

        artifacts = manifest.get(
            "artifacts"
        )

        if not isinstance(
            artifacts,
            dict,
        ):
            raise RecoveryError(
                "Manifest artifacts section is invalid"
            )

        missing = (
            self.REQUIRED_ARTIFACTS
            - set(artifacts.keys())
        )

        if missing:
            raise RecoveryError(
                "Required recovery artifacts are missing"
            )

        for logical_name in (
            self.REQUIRED_ARTIFACTS
        ):
            self._validate_artifact_metadata(
                logical_name,
                artifacts.get(
                    logical_name
                ),
            )

    def _validate_artifact_metadata(
        self,
        logical_name: str,
        metadata: Any,
    ) -> None:
        """Validate one recovery artifact's metadata."""

        if not isinstance(
            metadata,
            dict,
        ):
            raise RecoveryError(
                f"Invalid metadata for artifact {logical_name}"
            )

        filename = metadata.get(
            "filename"
        )

        blob_path = metadata.get(
            "blob_path"
        )

        sha256 = metadata.get(
            "sha256"
        )

        size_bytes = metadata.get(
            "size_bytes"
        )

        if (
            not isinstance(
                filename,
                str,
            )
            or not filename
        ):
            raise RecoveryError(
                f"Missing filename for {logical_name}"
            )

        if (
            Path(filename).name != filename
            or not self.SAFE_NAME_PATTERN.fullmatch(
                filename
            )
        ):
            raise RecoveryError(
                f"Unsafe filename for {logical_name}"
            )

        if filename != logical_name:
            raise RecoveryError(
                f"Unexpected filename for {logical_name}"
            )

        if not isinstance(
            blob_path,
            str,
        ):
            raise RecoveryError(
                f"Missing blob path for {logical_name}"
            )

        validated_blob_path = (
            self._validate_blob_reference(
                blob_path
            )
        )

        if not (
            validated_blob_path.endswith(
                f"/{logical_name}"
            )
        ):
            raise RecoveryError(
                "Artifact blob path does not match "
                f"logical name: {logical_name}"
            )

        self._validate_sha256(
            sha256
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
        ):
            raise RecoveryError(
                f"Invalid size for {logical_name}"
            )

        if size_bytes <= 0:
            raise RecoveryError(
                f"Artifact size must be positive: {logical_name}"
            )

        if size_bytes > (
            self.MAX_ARTIFACT_SIZE_BYTES
        ):
            raise RecoveryError(
                "Artifact exceeds maximum allowed size: "
                f"{logical_name}"
            )

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
            raise RecoveryError(
                "SHA-256 value must be a string"
            )

        normalized = value.strip().lower()

        if not cls.SHA256_PATTERN.fullmatch(
            normalized
        ):
            raise RecoveryError(
                "Invalid SHA-256 value"
            )

        return normalized

    @staticmethod
    def _parse_utc_timestamp(
        value: str,
    ) -> dt.datetime:
        """Parse an ISO-8601 timestamp and normalize to UTC."""

        try:
            parsed = dt.datetime.fromisoformat(
                value.replace(
                    "Z",
                    "+00:00",
                )
            )

        except ValueError as exc:
            raise RecoveryError(
                "Invalid UTC timestamp"
            ) from exc

        if parsed.tzinfo is None:
            raise RecoveryError(
                "Timestamp must contain timezone information"
            )

        return parsed.astimezone(
            dt.timezone.utc
        )

    def _set_backup_timestamp(
        self,
        manifest: Dict[str, Any],
    ) -> None:
        """Store the validated backup creation timestamp."""

        timing = manifest.get(
            "timing",
            {},
        )

        timestamp = timing.get(
            "backup_created_at_utc"
        )

        if isinstance(
            timestamp,
            str,
        ):
            self.backup_created_at = (
                self._parse_utc_timestamp(
                    timestamp
                )
            )

    # ------------------------------------------------------------------
    # Secure blob download
    # ------------------------------------------------------------------

    def _download_blob_to_file(
        self,
        *,
        blob_name: str,
        destination: Path,
        maximum_size: int,
        expected_size: Optional[int] = None,
    ) -> Path:
        """
        Stream a Blob into the isolated recovery workspace.

        Both the remote size and the actual streamed byte count are
        bounded. Manifest-provided size is treated as untrusted input.
        """

        blob_name = (
            self._validate_blob_reference(
                blob_name
            )
        )

        if (
            isinstance(maximum_size, bool)
            or not isinstance(maximum_size, int)
            or maximum_size <= 0
        ):
            raise RecoveryError(
                "Invalid maximum download size"
            )

        if (
            expected_size is not None
            and (
                isinstance(
                    expected_size,
                    bool,
                )
                or not isinstance(
                    expected_size,
                    int,
                )
                or expected_size <= 0
                or expected_size > maximum_size
            )
        ):
            raise RecoveryError(
                "Invalid expected download size"
            )

        destination = destination.resolve()
        work_dir = (
            self._require_work_dir()
            .resolve()
        )

        try:
            destination.relative_to(
                work_dir
            )

        except ValueError as exc:
            raise RecoveryError(
                "Download destination escapes recovery workspace"
            ) from exc

        if destination.exists():
            raise RecoveryError(
                "Refusing to overwrite existing recovery artifact"
            )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        try:
            properties = (
                self.azure.get_blob_properties(
                    blob_name
                )
            )

        except AzureError as exc:
            raise RecoveryError(
                "Unable to retrieve recovery artifact properties"
            ) from exc

        remote_size = getattr(
            properties,
            "size",
            None,
        )

        if (
            isinstance(remote_size, bool)
            or not isinstance(
                remote_size,
                int,
            )
            or remote_size < 0
        ):
            raise RecoveryError(
                "Remote recovery artifact size is unavailable"
            )

        if remote_size > maximum_size:
            raise RecoveryError(
                "Remote recovery artifact exceeds allowed size"
            )

        if (
            expected_size is not None
            and remote_size != expected_size
        ):
            raise RecoveryError(
                "Remote recovery artifact size does not match manifest"
            )

        total_bytes = 0

        try:
            stream = (
                self.azure.download_blob_stream(
                    blob_name
                )
            )

            with destination.open(
                "xb"
            ) as output:
                for chunk in stream.chunks():
                    if not chunk:
                        continue

                    total_bytes += len(chunk)

                    if total_bytes > maximum_size:
                        raise RecoveryError(
                            "Recovery artifact exceeded "
                            "streaming size limit"
                        )

                    if (
                        expected_size is not None
                        and total_bytes > expected_size
                    ):
                        raise RecoveryError(
                            "Downloaded artifact exceeded "
                            "manifest size"
                        )

                    output.write(chunk)

        except RecoveryError:
            self._safe_delete_file(
                destination
            )
            raise

        except (
            OSError,
            AzureError,
        ) as exc:
            self._safe_delete_file(
                destination
            )

            raise RecoveryError(
                "Unable to download recovery artifact"
            ) from exc

        if total_bytes != remote_size:
            self._safe_delete_file(
                destination
            )

            raise RecoveryError(
                "Downloaded artifact size does not match "
                "remote Blob size"
            )

        if (
            expected_size is not None
            and total_bytes != expected_size
        ):
            self._safe_delete_file(
                destination
            )

            raise RecoveryError(
                "Downloaded artifact size does not match manifest"
            )

        return destination

    # ------------------------------------------------------------------
    # Artifact validation
    # ------------------------------------------------------------------

    def _download_and_validate_artifacts(
        self,
    ) -> None:
        """Download and independently validate every required artifact."""

        if self.manifest is None:
            raise RecoveryError(
                "Manifest has not been loaded"
            )

        artifacts = self.manifest.get(
            "artifacts"
        )

        if not isinstance(
            artifacts,
            dict,
        ):
            raise RecoveryError(
                "Manifest artifacts are invalid"
            )

        work_dir = self._require_work_dir()

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
                raise RecoveryError(
                    f"Missing artifact metadata: {logical_name}"
                )

            blob_path = (
                self._validate_blob_reference(
                    metadata["blob_path"]
                )
            )

            expected_sha256 = (
                self._validate_sha256(
                    metadata["sha256"]
                )
            )

            expected_size = metadata[
                "size_bytes"
            ]

            if (
                isinstance(
                    expected_size,
                    bool,
                )
                or not isinstance(
                    expected_size,
                    int,
                )
                or expected_size <= 0
                or expected_size > self.MAX_ARTIFACT_SIZE_BYTES
            ):
                raise RecoveryError(
                    f"Invalid expected size: {logical_name}"
                )

            destination = (
                work_dir / logical_name
            )

            local_file = (
                self._download_blob_to_file(
                    blob_name=blob_path,
                    destination=destination,
                    maximum_size=(
                        self.MAX_ARTIFACT_SIZE_BYTES
                    ),
                    expected_size=expected_size,
                )
            )

            self._validate_local_target(
                local_file
            )

            try:
                actual_size = (
                    local_file.stat().st_size
                )
            except OSError as exc:
                self._safe_delete_file(
                    local_file
                )

                raise RecoveryError(
                    f"Unable to determine local artifact size: "
                    f"{logical_name}"
                ) from exc

            if actual_size != expected_size:
                self._safe_delete_file(
                    local_file
                )

                raise RecoveryError(
                    f"Local artifact size mismatch: {logical_name}"
                )

            actual_sha256 = sha256_file(
                local_file
            )

            if not self._constant_time_equal(
                actual_sha256,
                expected_sha256,
            ):
                self._safe_delete_file(
                    local_file
                )

                raise RecoveryError(
                    f"SHA-256 validation failed: {logical_name}"
                )

            remote_verified = (
                self.azure.verify_remote_blob(
                    blob_path,
                    expected_size_bytes=expected_size,
                    expected_sha256=expected_sha256,
                    verify_content_stream=bool(
                        self.config.backup[
                            "verify_remote_content_sha256"
                        ]
                    ),
                )
            )

            if not remote_verified:
                self._safe_delete_file(
                    local_file
                )

                raise RecoveryError(
                    "Remote artifact verification failed: "
                    f"{logical_name}"
                )

    def _validate_local_target(
        self,
        target: Path,
    ) -> None:
        """Ensure a local recovery artifact remains inside the workspace."""

        work_dir = (
            self._require_work_dir()
            .resolve()
        )

        target = target.resolve()

        try:
            target.relative_to(
                work_dir
            )

        except ValueError as exc:
            raise RecoveryError(
                "Recovery artifact escapes isolated workspace"
            ) from exc

        if target == work_dir:
            raise RecoveryError(
                "Recovery artifact cannot equal workspace root"
            )

        if target.exists() and not target.is_file():
            raise RecoveryError(
                "Recovery artifact target is not a regular file"
            )

    # ------------------------------------------------------------------
    # Stage 5 - Stop DR
    # ------------------------------------------------------------------

    def _stop_dr(self) -> None:
        """Stop Tableau Server before repository restoration."""

        result = self.tsm.run(
            ["stop"]
        )

        if not result.success:
            raise RecoveryError(
                "Unable to stop DR Tableau Server"
            )

    # ------------------------------------------------------------------
    # Stage 6 - Restore repository
    # ------------------------------------------------------------------

    def _restore_repository(self) -> None:
        """Restore the validated Tableau repository backup."""

        backup_file = (
            self._require_work_dir()
            / "backup.tsbak"
        )

        self._validate_local_target(
            backup_file
        )

        if not backup_file.is_file():
            raise RecoveryError(
                "Validated backup artifact is missing"
            )

        result = self.tsm.run(
            [
                "maintenance",
                "restore",
                "--file",
                str(backup_file),
            ]
        )

        if not result.success:
            raise RecoveryError(
                "Tableau repository restore failed"
            )

    # ------------------------------------------------------------------
    # Stage 7 - Settings import
    # ------------------------------------------------------------------

    def _import_settings(self) -> None:
        """Import validated Tableau Server settings."""

        settings_file = (
            self._require_work_dir()
            / "settings.json"
        )

        self._validate_local_target(
            settings_file
        )

        if not settings_file.is_file():
            raise RecoveryError(
                "Validated settings artifact is missing"
            )

        result = self.tsm.run(
            [
                "settings",
                "import",
                "--input-config",
                str(settings_file),
            ]
        )

        if not result.success:
            raise RecoveryError(
                "Tableau settings import failed"
            )

    # ------------------------------------------------------------------
    # Stage 8 - Security rebound
    # ------------------------------------------------------------------

    def _apply_key_vault_security_bindings(
        self,
    ) -> None:
        """
        Retrieve SSL material from Key Vault and apply it to Tableau.

        Secret values are never written to logs.
        """

        key_vault_name = str(
            self.config.azure[
                "key_vault_name"
            ]
        ).strip()

        if not key_vault_name:
            raise RecoveryError(
                "Key Vault name is not configured"
            )

        vault_url = (
            f"https://{key_vault_name}.vault.azure.net/"
        )

        credential = DefaultAzureCredential(
            exclude_interactive_browser_credential=True
        )

        client = SecretClient(
            vault_url=vault_url,
            credential=credential,
        )

        cert_secret_name = (
            "tableau-dr-ssl-cert"
        )

        key_secret_name = (
            "tableau-dr-ssl-key"
        )

        cert_path: Optional[Path] = None
        key_path: Optional[Path] = None

        try:
            cert_secret = client.get_secret(
                cert_secret_name
            )

            key_secret = client.get_secret(
                key_secret_name
            )

            cert_value = cert_secret.value
            key_value = key_secret.value

            if not cert_value or not key_value:
                raise RecoveryError(
                    "Required SSL secrets are empty"
                )

            security_dir = (
                self._require_work_dir()
                / "security"
            )

            security_dir.mkdir(
                mode=0o700,
                parents=True,
                exist_ok=False,
            )

            cert_path = (
                security_dir / "server.crt"
            )

            key_path = (
                security_dir / "server.key"
            )

            self._write_secret_file(
                cert_path,
                cert_value,
            )

            self._write_secret_file(
                key_path,
                key_value,
            )

            result = self.tsm.run(
                [
                    "security",
                    "external-ssl",
                    "enable",
                    "--cert-file",
                    str(cert_path),
                    "--key-file",
                    str(key_path),
                ]
            )

            if not result.success:
                raise RecoveryError(
                    "Unable to configure external SSL"
                )

            pending_result = self.tsm.run(
                [
                    "pending-changes",
                    "apply",
                    "--ignore-prompt",
                ]
            )

            if not pending_result.success:
                raise RecoveryError(
                    "Unable to apply Tableau pending security changes"
                )

        except AzureError as exc:
            raise RecoveryError(
                "Unable to retrieve required security material "
                "from Key Vault"
            ) from exc

        finally:
            self._safe_delete_file(
                cert_path
            )

            self._safe_delete_file(
                key_path
            )

            if cert_path is not None:
                self._safe_delete_directory(
                    cert_path.parent
                )

    @classmethod
    def _write_secret_file(
        cls,
        path: Path,
        value: str,
    ) -> None:
        """
        Write a temporary secret file with restrictive permissions.

        POSIX:
            0600 file permissions.

        Windows:
            Inherited ACLs are removed and access is explicitly granted
            to the current user, SYSTEM, and local Administrators.
        """

        if not isinstance(
            value,
            str,
        ) or not value:
            raise RecoveryError(
                "Secret value is invalid"
            )

        if not isinstance(
            path,
            Path,
        ):
            raise RecoveryError(
                "Secret file path is invalid"
            )

        try:
            path.parent.mkdir(
                mode=0o700,
                parents=True,
                exist_ok=True,
            )

            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
            )

            fd = os.open(
                path,
                flags,
                0o600,
            )

            try:
                with os.fdopen(
                    fd,
                    "w",
                    encoding="utf-8",
                ) as secret_file:
                    secret_file.write(value)

            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise

            if os.name != "nt":
                path.chmod(0o600)
                return

            cls._restrict_windows_file_acl(
                path
            )

        except RecoveryError:
            cls._safe_delete_file(
                path
            )
            raise

        except OSError as exc:
            cls._safe_delete_file(
                path
            )

            raise RecoveryError(
                "Unable to create secure temporary secret file"
            ) from exc

    @classmethod
    def _restrict_windows_file_acl(
        cls,
        path: Path,
    ) -> None:
        """Restrict a Windows secret file using icacls."""

        if os.name != "nt":
            raise RecoveryError(
                "Windows ACL operation requested on non-Windows host"
            )

        username = os.environ.get(
            "USERNAME"
        )

        user_domain = os.environ.get(
            "USERDOMAIN"
        )

        if not username:
            raise RecoveryError(
                "Unable to determine current Windows user"
            )

        if user_domain:
            current_user = (
                f"{user_domain}\\{username}"
            )
        else:
            current_user = username

        command = [
            "icacls",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"{current_user}:F",
            "SYSTEM:F",
            "Administrators:F",
        ]

        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=cls.WINDOWS_ACL_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )

        except (
            OSError,
            subprocess.SubprocessError,
        ) as exc:
            cls._safe_delete_file(
                path
            )

            raise RecoveryError(
                "Unable to apply Windows ACL to temporary secret file"
            ) from exc

        if completed.returncode != 0:
            cls._safe_delete_file(
                path
            )

            raise RecoveryError(
                "Windows ACL restriction failed for temporary secret file"
            )

    # ------------------------------------------------------------------
    # Stage 9 - Start DR
    # ------------------------------------------------------------------

    def _start_dr(self) -> None:
        """Start Tableau Server after recovery configuration."""

        result = self.tsm.run(
            ["start"]
        )

        if not result.success:
            raise RecoveryError(
                "Unable to start DR Tableau Server"
            )

    # ------------------------------------------------------------------
    # Stage 10 - Health validation
    # ------------------------------------------------------------------

    def _validate_health(self) -> None:
        """Require successful post-recovery health validation."""

        self.health_result = (
            self.health_checker.run_all_checks()
        )

        if not self.health_result.overall_healthy:
            raise RecoveryError(
                "DR health validation failed"
            )

    # ------------------------------------------------------------------
    # Result / metrics
    # ------------------------------------------------------------------

    def _build_result(
        self,
        *,
        status: str,
        total_rto_seconds: float,
    ) -> RecoveryResult:
        """Build the structured recovery result."""

        backup_age: Optional[float] = None

        if self.backup_created_at is not None:
            backup_age = (
                self.disaster_declared_at
                - self.backup_created_at
            ).total_seconds()

            if backup_age < 0:
                backup_age = 0.0

        fencing_dict: Optional[
            Dict[str, Any]
        ] = None

        if self.fencing_result is not None:
            fencing_dict = asdict(
                self.fencing_result
            )

        health_dict: Optional[
            Dict[str, Any]
        ] = None

        if self.health_result is not None:
            health_dict = asdict(
                self.health_result
            )

        return RecoveryResult(
            run_id=self.run_id,
            status=status,
            current_state=self.current_state.value,
            completed_steps=list(
                self.completed_steps
            ),
            failed_step=(
                self.failed_step
                if status == "FAILED"
                else None
            ),
            fencing_result=fencing_dict,
            health_result=health_dict,
            disaster_declared_at_utc=(
                self.disaster_declared_at.isoformat()
            ),
            recovery_completed_at_utc=(
                self.recovery_completed_at.isoformat()
                if self.recovery_completed_at
                else None
            ),
            backup_created_at_utc=(
                self.backup_created_at.isoformat()
                if self.backup_created_at
                else None
            ),
            measured_backup_age_rpo_seconds=backup_age,
            total_rto_seconds=round(
                total_rto_seconds,
                3,
            ),
            stage_timings=dict(
                self.stage_timings
            ),
        )

    # ------------------------------------------------------------------
    # Workspace / cleanup
    # ------------------------------------------------------------------

    def _require_work_dir(self) -> Path:
        """Return the active isolated recovery workspace."""

        if self.work_dir is None:
            raise RecoveryError(
                "Recovery workspace has not been initialized"
            )

        return self.work_dir

    def _preserve_failed_recovery_workspace(
        self,
    ) -> None:
        """Preserve failed recovery artifacts for incident investigation."""

        if self.work_dir is None:
            return

        try:
            marker = (
                self.work_dir
                / "RECOVERY_FAILED"
            )

            marker.write_text(
                (
                    "Recovery failed.\n"
                    "Workspace intentionally preserved "
                    "for incident investigation.\n"
                ),
                encoding="utf-8",
            )

        except OSError:
            self.logger.warning(
                "Unable to create recovery failure marker"
            )

    @staticmethod
    def _safe_delete_file(
        path: Optional[Path],
    ) -> None:
        """Best-effort file deletion without masking the original failure."""

        if path is None:
            return

        try:
            if path.exists():
                path.unlink()

        except OSError:
            pass

    @staticmethod
    def _safe_delete_directory(
        path: Path,
    ) -> None:
        """Best-effort removal of an empty temporary directory."""

        try:
            if path.exists():
                path.rmdir()

        except OSError:
            pass

    # ------------------------------------------------------------------
    # Constant-time comparison
    # ------------------------------------------------------------------

    @staticmethod
    def _constant_time_equal(
        left: str,
        right: str,
    ) -> bool:
        """Compare hexadecimal digests using constant-time comparison."""

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