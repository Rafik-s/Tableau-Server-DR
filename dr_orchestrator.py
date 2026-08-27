"""High-level Orchestration Wrapper unifying Backup and Recovery Pipelines."""

from __future__ import annotations

import logging
from tableau_dr.backup_manager import BackupManager, BackupResult
from tableau_dr.config import Config
from tableau_dr.recovery_manager import RecoveryManager, RecoveryResult

logger = logging.getLogger(__name__)


class DROrchestrator:
    """Unified entry point for disaster recovery workflows."""

    def __init__(self, config_path: str = "config/config.yaml", run_id: str = "DEFAULT"):
        self.config = Config(config_path)
        self.run_id = run_id

    def run_backup(self) -> BackupResult:
        manager = BackupManager(self.config, self.run_id)
        return manager.execute_backup_pipeline()

    def run_recovery(
        self,
        emergency_auth_code: str | None = None,
        operator_reason: str | None = None,
        manifest_blob: str | None = None,
    ) -> RecoveryResult:
        manager = RecoveryManager(self.config, self.run_id)
        return manager.execute_failover(
            emergency_auth_code=emergency_auth_code,
            operator_reason=operator_reason,
            target_manifest_blob=manifest_blob,
        )