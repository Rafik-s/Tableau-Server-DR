"""Unit tests for the multi-layered post-restoration health checker."""

import unittest
from unittest.mock import MagicMock, patch

from tableau_dr.health_check import HealthChecker
from tableau_dr.tab_server_connector import TSMConnector, TSMResult


class TestHealthChecker(unittest.TestCase):

    def setUp(self):
        self.mock_tsm = MagicMock(spec=TSMConnector)
        self.checker = HealthChecker(tsm_connector=self.mock_tsm, gateway_hostname="tableau-dr.test.com")

    @patch("tableau_dr.health_check.socket.create_connection")
    @patch("tableau_dr.health_check.urllib.request.urlopen")
    def test_run_all_checks_success(self, mock_urlopen, mock_socket):
        # Layer 1 - Process mock
        self.mock_tsm.status.return_value = TSMResult(
            command=["tsm", "status"], return_code=0, stdout="Status: RUNNING", stderr=""
        )

        # Layer 3 - Application HTTP response mock
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Layer 4 - Licensing mock
        self.mock_tsm.run.return_value = TSMResult(
            command=["tsm", "licenses", "list"], return_code=0, stdout="Status: LICENSED", stderr=""
        )

        result = self.checker.run_all_checks()

        self.assertTrue(result.overall_healthy)
        self.assertTrue(result.layers["layer1_process"].passed)
        self.assertTrue(result.layers["layer2_gateway"].passed)
        self.assertTrue(result.layers["layer3_application"].passed)
        self.assertTrue(result.layers["layer4_licensing"].passed)

    def test_run_all_checks_fails_when_tsm_stopped(self):
        self.mock_tsm.status.return_value = TSMResult(
            command=["tsm", "status"], return_code=0, stdout="Status: STOPPED", stderr=""
        )

        result = self.checker.run_all_checks()

        self.assertFalse(result.overall_healthy)
        self.assertFalse(result.layers["layer1_process"].passed)


if __name__ == "__main__":
    unittest.main()