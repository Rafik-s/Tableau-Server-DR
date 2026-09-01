"""Unit tests for the production fencing isolation engine."""

import unittest
from unittest.mock import MagicMock, patch
from tableau_dr.fencing import ProductionFencer
from tableau_dr.config import Config


class TestProductionFencer(unittest.TestCase):

    def setUp(self):
        self.mock_config = MagicMock(spec=Config)
        self.mock_config.servers = {"production": {"hostname": "tableau-prod.internal.net"}}
        self.mock_config.security = {"emergency_fencing_auth_code": "AUTH123456"}
        self.fencer = ProductionFencer(self.mock_config)

    @patch.object(ProductionFencer, "_check_dns", return_value=True)
    @patch.object(ProductionFencer, "_check_http", return_value=False)
    @patch.object(ProductionFencer, "_check_port", return_value=False)
    def test_evaluate_fencing_success(self, mock_port, mock_http, mock_dns):
        res = self.fencer.evaluate_fencing()
        self.assertTrue(res.is_fenced)
        self.assertFalse(res.http_reachable)
        self.assertFalse(res.override_applied)

    @patch.object(ProductionFencer, "_check_dns", return_value=True)
    @patch.object(ProductionFencer, "_check_http", return_value=True)
    @patch.object(ProductionFencer, "_check_port", return_value=True)
    def test_evaluate_fencing_blocks_active_prod(self, mock_port, mock_http, mock_dns):
        res = self.fencer.evaluate_fencing()
        self.assertFalse(res.is_fenced)
        self.assertTrue(res.http_reachable)

    @patch.object(ProductionFencer, "_check_dns", return_value=True)
    @patch.object(ProductionFencer, "_check_http", return_value=True)
    @patch.object(ProductionFencer, "_check_port", return_value=True)
    def test_emergency_override_success(self, mock_port, mock_http, mock_dns):
        res = self.fencer.evaluate_fencing(
            emergency_authorization_code="AUTH123456",
            operator_reason="Valid audited reason for primary datacenter failover",
        )
        self.assertTrue(res.is_fenced)
        self.assertTrue(res.override_applied)


if __name__ == "__main__":
    unittest.main()