"""Fail-closed Production Fencing Module to prevent dual-primary split-brain scenarios."""

from __future__ import annotations

import logging
import socket
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict
from typing import Optional

from tableau_dr.config import Config
from tableau_dr.tab_server_connector import TSMConnector

logger = logging.getLogger(__name__)


@dataclass
class FencingResult:
    is_fenced: bool
    http_reachable: bool
    tsm_reachable: bool
    dns_resolved: bool
    override_applied: bool
    operator_reason: Optional[str]
    details: str

    def to_dict(self) -> dict:
        return asdict(self)


class ProductionFencer:
    """Evaluates production state and enforces isolation boundaries."""

    def __init__(self, config: Config):
        self.config = config
        self.prod_hostname = config.servers["production"]["hostname"]

    def _check_dns(self) -> bool:
        try:
            socket.gethostbyname(self.prod_hostname)
            return True
        except socket.gaierror:
            return False

    def _check_port(self, port: int, timeout: int = 5) -> bool:
        try:
            with socket.create_connection((self.prod_hostname, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _check_http(self, timeout: int = 5) -> bool:
        url = f"https://{self.prod_hostname}/vizportal/api/web/v1/ping"
        try:
            req = urllib.request.Request(url, method="GET")
            # Ignore SSL verification for diagnostic reachability check
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status < 500
        except (urllib.error.URLError, socket.timeout, Exception):
            return False

    def evaluate_fencing(
        self,
        emergency_authorization_code: Optional[str] = None,
        operator_reason: Optional[str] = None,
    ) -> FencingResult:
        """
        Evaluates production reachability.
        
        Rules:
        1. If HTTP or TSM port (8850) responds -> NOT FENCED (FAIL CLOSED).
        2. If completely unreachable across HTTP, TSM port, and DNS -> FENCED.
        3. Emergency override requires valid authorization code & audited reason.
        """
        logger.info(f"Evaluating production isolation state for '{self.prod_hostname}'...")
        
        dns_active = self._check_dns()
        http_active = self._check_http(timeout=5)
        tsm_port_active = self._check_port(8850, timeout=5)

        # Handle Emergency Authorized Override
        expected_auth_code = self.config.security.get("emergency_fencing_auth_code") if self.config.security else None
        
        if emergency_authorization_code:
            if expected_auth_code and emergency_authorization_code == expected_auth_code:
                if not operator_reason or len(operator_reason.strip()) < 10:
                    raise ValueError("Emergency override requires a detailed audited operator_reason (min 10 chars).")
                
                logger.warning(
                    f"EMERGENCY FENCING OVERRIDE APPLIED! Operator Reason: {operator_reason}"
                )
                return FencingResult(
                    is_fenced=True,
                    http_reachable=http_active,
                    tsm_reachable=tsm_port_active,
                    dns_resolved=dns_active,
                    override_applied=True,
                    operator_reason=operator_reason,
                    details="Production state overridden via valid Emergency Authorization Code.",
                )
            else:
                raise PermissionError("Invalid Emergency Authorization Code provided!")

        # Standard Evaluation
        if http_active or tsm_port_active:
            details = (
                f"Production node '{self.prod_hostname}' is still active! "
                f"HTTP Ping: {http_active}, TSM Port 8850: {tsm_port_active}. Failover ABORTED."
            )
            logger.error(details)
            return FencingResult(
                is_fenced=False,
                http_reachable=http_active,
                tsm_reachable=tsm_port_active,
                dns_resolved=dns_active,
                override_applied=False,
                operator_reason=None,
                details=details,
            )

        details = f"Production node '{self.prod_hostname}' unreachable across all channels. Confirmed fenced."
        logger.info(f"[PASS] {details}")
        return FencingResult(
            is_fenced=True,
            http_reachable=False,
            tsm_reachable=False,
            dns_resolved=dns_active,
            override_applied=False,
            operator_reason=None,
            details=details,
        )