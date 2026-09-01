"""High-level orchestration wrapper for Tableau DR backup and recovery workflows."""

from __future__ import annotations

import uuid

from tableau_dr.backup_manager import BackupManager, BackupResult
from tableau_dr.config import Config
from tableau_dr.recovery_manager import RecoveryManager, RecoveryResult


class DROrchestrator:
    """Unified entry point for disaster recovery backup and recovery workflows."""

    def __init__(
        self,
        config_path: str = "config/config.yaml",
        run_id: str | None = None,
    ) -> None:
        self.config = Config(config_path)
        self.run_id = run_id or uuid.uuid4().hex[:8].upper()

    def run_backup(self) -> BackupResult:
        """Execute the Tableau DR backup pipeline."""
        manager = BackupManager(
            config=self.config,
            run_id=self.run_id,
        )
        return manager.execute_backup_pipeline()

    def run_recovery(
        self,
        emergency_auth_code: str | None = None,
        operator_reason: str | None = None,
        manifest_blob: str | None = None,
    ) -> RecoveryResult:
        """Execute the Tableau DR failover and recovery pipeline."""
        manager = RecoveryManager(
            config=self.config,
            run_id=self.run_id,
        )
        return manager.execute_failover(
            emergency_auth_code=emergency_auth_code,
            operator_reason=operator_reason,
            target_manifest_blob=manifest_blob,
        )