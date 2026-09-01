"""Unit tests for the backup execution manager."""

import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

from tableau_dr.backup_manager import BackupManager
from tableau_dr.config import Config


class TestBackupManager(unittest.TestCase):

    @patch("tableau_dr.backup_manager.AzureManager")
    @patch("tableau_dr.backup_manager.TSMConnector")
    def setUp(self, mock_tsm_cls, mock_azure_cls):
        self.mock_tsm = mock_tsm_cls.return_value
        self.mock_azure = mock_azure_cls.return_value

        self.mock_config = MagicMock(spec=Config)
        self.mock_config.paths = {
            "backup_dir": "/tmp/test_backups",
            "recovery_work_dir": "/tmp/test_recovery",
        }
        self.mock_config.azure = {
            "storage_account_name": "testacc",
            "storage_container": "testcontainer",
        }
        self.mock_config.servers = {
            "production": {"hostname": "prod.test.com", "identity_store": "activedirectory"}
        }
        self.mock_config.environment = {"version": "2025.1.0"}
        self.mock_config.backup = {
            "minimum_free_space_gb": 1.0,
            "minimum_backup_size_mb": 0.0,
            "verify_remote_content_sha256": False,
        }
        self.mock_config.tsm = {"executable": None}

        self.manager = BackupManager(self.mock_config, run_id="TEST1234")

    @patch("tableau_dr.backup_manager.validate_disk_space", return_value=True)
    @patch("tableau_dr.backup_manager.validate_file", return_value=True)
    @patch("tableau_dr.backup_manager.sha256_file", return_value="a" * 64)
    @patch("tableau_dr.backup_manager.shutil.rmtree")
    def test_execute_backup_pipeline_success(
        self, mock_rmtree, mock_sha, mock_val_file, mock_val_disk
    ):
        mock_status_res = MagicMock()
        mock_status_res.success = True
        self.mock_tsm.status.return_value = mock_status_res

        # Mock physical creation of settings and tsbak files in the work directory
        self.manager.run_work_dir.mkdir(parents=True, exist_ok=True)
        (self.manager.run_work_dir / f"tableau_settings_{self.manager.timestamp_str}.json").write_text("{}")
        (self.manager.run_work_dir / f"tableau_backup_{self.manager.timestamp_str}.tsbak").write_text("content")

        result = self.manager.execute_backup_pipeline()

        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.run_id, "TEST1234")
        self.assertTrue(result.remote_verified)
        self.assertEqual(self.mock_azure.upload_file.call_count, 3)  # Settings, Backup, Manifest


if __name__ == "__main__":
    unittest.main()