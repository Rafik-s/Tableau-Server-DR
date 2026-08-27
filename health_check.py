"""Layered Post-Restore Tableau Server Health Smoke Verification Engine."""

from __future__ import annotations

import logging
import socket
import urllib.request
from dataclasses import dataclass, asdict
from typing import Dict

from tableau_dr.tab_server_connector import TSMConnector

logger = logging.getLogger(__name__)


@dataclass
class LayerHealth:
    layer_name: str
    passed: bool
    details: str


@dataclass
class HealthCheckResult:
    overall_healthy: bool
    layers: Dict[str, LayerHealth]

    def to_dict(self) -> dict:
        return {
            "overall_healthy": self.overall_healthy,
            "layers": {k: asdict(v) for k, v in self.layers.items()},
        }


class HealthChecker:
    """Executes multi-layered health checks against the target DR Tableau Server."""

    def __init__(self, tsm_connector: TSMConnector, gateway_hostname: str):
        self.tsm = tsm_connector
        self.gateway_hostname = gateway_hostname

    def run_all_checks(self) -> HealthCheckResult:
        layers: Dict[str, LayerHealth] = {}
        
        # Layer 1 — Process Level (TSM Status)
        layers["layer1_process"] = self._check_process_layer()

        # Layer 2 — Gateway Level (Port 80/443)
        layers["layer2_gateway"] = self._check_gateway_layer()

        # Layer 3 — Application API Level (Ping endpoint)
        layers["layer3_application"] = self._check_application_layer()

        # Layer 4 — Licensing State
        layers["layer4_licensing"] = self._check_licensing_layer()

        overall = all(layer.passed for layer in layers.values())
        return HealthCheckResult(overall_healthy=overall, layers=layers)

    def _check_process_layer(self) -> LayerHealth:
        res = self.tsm.status()
        if res.success and "status: RUNNING" in res.stdout.upper():
            return LayerHealth("Layer 1 - Process", True, "TSM reports cluster is RUNNING.")
        return LayerHealth("Layer 1 - Process", False, f"TSM Status Check Failed: {res.stdout}")

    def _check_gateway_layer(self) -> LayerHealth:
        for port in (443, 80):
            try:
                with socket.create_connection((self.gateway_hostname, port), timeout=3):
                    return LayerHealth("Layer 2 - Gateway", True, f"Gateway reachable on port {port}.")
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue
        return LayerHealth("Layer 2 - Gateway", False, f"Could not establish connection to {self.gateway_hostname} on 80/443.")

    def _check_application_layer(self) -> LayerHealth:
        url = f"https://{self.gateway_hostname}/vizportal/api/web/v1/ping"
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                if resp.status == 200:
                    return LayerHealth("Layer 3 - Application", True, "Vizportal ping endpoint returned HTTP 200 OK.")
                return LayerHealth("Layer 3 - Application", False, f"Vizportal ping returned HTTP status {resp.status}.")
        except Exception as e:
            return LayerHealth("Layer 3 - Application", False, f"Application HTTP check error: {e}")

    def _check_licensing_layer(self) -> LayerHealth:
        res = self.tsm.run(["licenses", "list"], check=False)
        if res.success and "LICENSED" in res.stdout.upper():
            return LayerHealth("Layer 4 - Licensing", True, "Tableau Server licenses validated.")
        return LayerHealth("Layer 4 - Licensing", False, f"Licensing verification issue: {res.stderr or res.stdout}")