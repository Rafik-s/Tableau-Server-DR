"""Unit tests for state transitions and failover orchestrations."""

import unittest
from unittest.mock import MagicMock, patch

from tableau_dr.config import Config
from tableau_dr.exceptions import RecoveryError
from tableau_dr.recovery_manager import RecoveryManager, RecoveryState


class TestRecoveryManager(unittest.TestCase):

    @patch("tableau_dr.recovery_manager.AzureManager")
    @patch("tableau_dr.recovery_manager.TSMConnector")
    @patch("tableau_dr.recovery_manager.ProductionFencer")
    def setUp(self, mock_fencer_cls, mock_tsm_cls, mock_azure_cls):
        self.mock_fencer = mock_fencer_cls.return_value
        self.mock_tsm = mock_tsm_cls.return_value
        self.mock_azure = mock_azure_cls.return_value

        self.mock_config = MagicMock(spec=Config)
        self.mock_config.paths = {"recovery_work_dir": "/tmp/test_recovery"}
        self.mock_config.azure = {
            "storage_account_name": "testacc",
            "storage_container": "testcontainer",
            "key_vault_name": "testkv",
        }
        self.mock_config.servers = {
            "disaster_recovery": {"hostname": "dr.test.com", "identity_store": "activedirectory"}
        }
        self.mock_config.environment = {"version": "2025.1.0"}
        self.mock_config.tsm = {"executable": None}

        self.manager = RecoveryManager(self.mock_config, run_id="FAILOVER123")

    def test_state_transition_assignment_on_failure(self):
        """Validates that current_state updates BEFORE executing the stage block."""
        def failing_step():
            raise RuntimeError("Fencing network failure simulated")

        with self.assertRaises(RecoveryError):
            self.manager._execute_stage(RecoveryState.PRODUCTION_FENCED, failing_step)

        # Asserts state was updated to PRODUCTION_FENCED when exception occurred
        self.assertEqual(self.manager.current_state, RecoveryState.PRODUCTION_FENCED)

    def test_failover_aborts_if_fencing_fails(self):
        mock_fencing_res = MagicMock()
        mock_fencing_res.is_fenced = False
        mock_fencing_res.details = "Production HTTP server still active"
        self.mock_fencer.evaluate_fencing.return_value = mock_fencing_res

        result = self.manager.execute_failover()

        self.assertEqual(result.status, "FAILED")
        self.assertEqual(result.failed_step, RecoveryState.PRODUCTION_FENCED)


if __name__ == "__main__":
    unittest.main()