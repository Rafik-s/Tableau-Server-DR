"""High-level orchestration wrapper for Tableau DR backup and recovery."""

from __future__ import annotations

import logging
import re
import uuid
from pathlib import Path
from typing import Optional

from tableau_dr.backup_manager import BackupManager, BackupResult
from tableau_dr.config import Config
from tableau_dr.exceptions import ConfigurationError
from tableau_dr.recovery_manager import RecoveryManager, RecoveryResult


logger = logging.getLogger(__name__)

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class DROrchestrator:
    """
    Unified entry point for Tableau Server disaster recovery workflows.

    The orchestrator intentionally contains no low-level recovery logic.
    Backup and recovery safety controls remain inside their respective
    managers so that both direct and orchestrated execution follow the
    same validation and fail-closed behavior.
    """

    def __init__(
        self,
        config_path: str | Path = "config/config.yaml",
        run_id: Optional[str] = None,
    ) -> None:
        """Load and validate configuration and establish the execution ID."""

        self.config_path = Path(config_path)

        self.config = Config(
            self.config_path
        )

        self.run_id = self._resolve_run_id(
            run_id
        )

        logger.info(
            "DR orchestrator initialized. run_id=%s",
            self.run_id,
        )

    @staticmethod
    def _resolve_run_id(
        run_id: Optional[str],
    ) -> str:
        """Validate a supplied run ID or generate a cryptographically strong one."""

        if run_id is None:
            return uuid.uuid4().hex.upper()

        if not isinstance(run_id, str):
            raise ValueError(
                "run_id must be a string when provided."
            )

        normalized = run_id.strip()

        if not normalized:
            raise ValueError(
                "run_id cannot be empty."
            )

        if not RUN_ID_PATTERN.fullmatch(
            normalized
        ):
            raise ValueError(
                "run_id contains invalid characters or exceeds "
                "the maximum allowed length."
            )

        return normalized

    def run_backup(
        self,
    ) -> BackupResult:
        """
        Execute the complete Tableau DR backup pipeline.

        The BackupManager performs preflight validation, TSM backup,
        hashing, manifest generation, Azure persistence, remote
        verification, and fail-closed cleanup.
        """

        logger.info(
            "Starting orchestrated DR backup. run_id=%s",
            self.run_id,
        )

        manager = BackupManager(
            config=self.config,
            run_id=self.run_id,
        )

        result = manager.execute_backup_pipeline()

        logger.info(
            "Orchestrated DR backup finished. "
            "status=%s remote_verified=%s cleanup=%s",
            result.status,
            result.remote_verified,
            result.cleanup_status,
        )

        return result

    def run_recovery(
        self,
        emergency_auth_code: Optional[str] = None,
        operator_reason: Optional[str] = None,
        manifest_blob: Optional[str] = None,
    ) -> RecoveryResult:
        """
        Execute the complete Tableau DR recovery state machine.

        RecoveryManager is responsible for production fencing,
        manifest validation, artifact integrity verification, repository
        restoration, security rebinding, startup, and health validation.
        """

        logger.warning(
            "Starting orchestrated DR recovery. run_id=%s",
            self.run_id,
        )

        self._validate_recovery_arguments(
            emergency_auth_code=emergency_auth_code,
            operator_reason=operator_reason,
            manifest_blob=manifest_blob,
        )

        manager = RecoveryManager(
            config=self.config,
            run_id=self.run_id,
        )

        result = manager.execute_failover(
            emergency_auth_code=emergency_auth_code,
            operator_reason=operator_reason,
            target_manifest_blob=manifest_blob,
        )

        if result.status == "SUCCESS":
            logger.info(
                "Orchestrated DR recovery completed successfully. "
                "rto_seconds=%s rpo_seconds=%s",
                result.total_rto_seconds,
                result.measured_backup_age_rpo_seconds,
            )
        else:
            logger.error(
                "Orchestrated DR recovery failed. "
                "state=%s failed_step=%s",
                result.current_state.value,
                (
                    result.failed_step.value
                    if result.failed_step
                    else "UNKNOWN"
                ),
            )

        return result

    @staticmethod
    def _validate_recovery_arguments(
        emergency_auth_code: Optional[str],
        operator_reason: Optional[str],
        manifest_blob: Optional[str],
    ) -> None:
        """Validate recovery inputs without exposing sensitive values."""

        if emergency_auth_code is not None:
            if not isinstance(
                emergency_auth_code,
                str,
            ):
                raise ConfigurationError(
                    "Emergency authorization code must be a string."
                )

            if not emergency_auth_code.strip():
                raise ConfigurationError(
                    "Emergency authorization code cannot be empty."
                )

            if operator_reason is None:
                raise ConfigurationError(
                    "operator_reason is required when "
                    "emergency_auth_code is supplied."
                )

        if operator_reason is not None:
            if not isinstance(
                operator_reason,
                str,
            ):
                raise ConfigurationError(
                    "Operator reason must be a string."
                )

            if not operator_reason.strip():
                raise ConfigurationError(
                    "Operator reason cannot be empty."
                )

            if len(operator_reason.strip()) > 1000:
                raise ConfigurationError(
                    "Operator reason exceeds the maximum allowed length."
                )

        if manifest_blob is not None:
            if not isinstance(
                manifest_blob,
                str,
            ):
                raise ConfigurationError(
                    "manifest_blob must be a string."
                )

            if not manifest_blob.strip():
                raise ConfigurationError(
                    "manifest_blob cannot be empty."
                )

    def reload_config(self) -> None:
        """
        Reload configuration from disk.

        This is primarily useful for long-running administrative processes.
        A new Config instance is created and fully validated before replacing
        the current configuration.
        """

        logger.info(
            "Reloading DR configuration."
        )

        new_config = Config(
            self.config_path
        )

        self.config = new_config

        logger.info(
            "DR configuration reload completed successfully."
        )