"""Production fencing engine to prevent dual-primary split-brain states."""

from __future__ import annotations

import logging
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Optional

from tableau_dr.config import Config

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
    """Evaluates production node network state and validates isolation boundaries."""

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
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status < 500
        except (urllib.error.URLError, socket.timeout, Exception):
            return False

    def evaluate_fencing(
        self,
        emergency_authorization_code: Optional[str] = None,
        operator_reason: Optional[str] = None,
    ) -> FencingResult:
        logger.info(f"Evaluating isolation status for production host '{self.prod_hostname}'...")
        
        dns_active = self._check_dns()
        http_active = self._check_http(timeout=5)
        tsm_port_active = self._check_port(8850, timeout=5)

        expected_auth_code = self.config.security.get("emergency_fencing_auth_code") if self.config.security else None
        
        if emergency_authorization_code:
            if expected_auth_code and emergency_authorization_code == expected_auth_code:
                if not operator_reason or len(operator_reason.strip()) < 10:
                    raise ValueError("Emergency override requires an audited reason (min 10 characters).")
                
                logger.warning(f"EMERGENCY FENCING OVERRIDE APPLIED! Reason: {operator_reason}")
                return FencingResult(
                    is_fenced=True,
                    http_reachable=http_active,
                    tsm_reachable=tsm_port_active,
                    dns_resolved=dns_active,
                    override_applied=True,
                    operator_reason=operator_reason,
                    details="Production isolation overridden via Emergency Authorization Code.",
                )
            else:
                raise PermissionError("Invalid Emergency Authorization Code!")

        if http_active or tsm_port_active:
            details = (
                f"Production host '{self.prod_hostname}' is active! "
                f"HTTP Ping: {http_active}, TSM Port 8850: {tsm_port_active}. Restoration ABORTED."
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

        details = f"Production host '{self.prod_hostname}' confirmed unreachable across HTTP/TSM interfaces."
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