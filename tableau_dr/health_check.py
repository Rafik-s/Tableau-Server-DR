"""Post-recovery health checks for Tableau Server DR validation."""

from __future__ import annotations

import datetime
import logging
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import List

from tableau_dr.tab_server_connector import TSMConnector


logger = logging.getLogger(__name__)

DEFAULT_HTTP_TIMEOUT_SECONDS = 15
DEFAULT_TSM_TIMEOUT_SECONDS = 120

MIN_HTTP_TIMEOUT_SECONDS = 1
MAX_HTTP_TIMEOUT_SECONDS = 300

MAX_HOSTNAME_LENGTH = 253

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"\.)*"
    r"[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


@dataclass(frozen=True)
class HealthCheckResult:
    """Machine-readable result of Tableau DR health validation."""

    overall_healthy: bool
    evaluated_at_utc: str
    gateway_reachable: bool
    tsm_healthy: bool
    checks: List[dict]

    def to_dict(self) -> dict:
        """Return a JSON-serializable representation."""
        return asdict(self)


class HealthChecker:
    """
    Validate that the recovered Tableau Server is operational.

    Checks:

    - TSM status.
    - Tableau Gateway HTTPS reachability.
    - TLS certificate validation.
    - HTTP response from the Tableau Gateway.

    A successful network connection alone is not treated as proof that
    Tableau is healthy. TSM status must also pass.

    HTTP 2xx-4xx responses are treated as gateway reachability because
    authentication or application-level authorization may legitimately
    return 401/403 while proving that the Gateway is responding.
    """

    def __init__(
        self,
        tsm_connector: TSMConnector,
        gateway_hostname: str,
        http_timeout_seconds: int = DEFAULT_HTTP_TIMEOUT_SECONDS,
    ) -> None:
        """Initialize the health checker."""

        if not isinstance(tsm_connector, TSMConnector):
            raise TypeError(
                "tsm_connector must be a TSMConnector instance."
            )

        self.gateway_hostname = self._validate_hostname(
            gateway_hostname
        )

        self._validate_http_timeout(
            http_timeout_seconds
        )

        self.tsm = tsm_connector
        self.http_timeout_seconds = http_timeout_seconds

    @staticmethod
    def _validate_hostname(hostname: str) -> str:
        """Validate a DNS hostname before constructing the health URL."""
        if not isinstance(hostname, str):
            raise TypeError(
                "gateway_hostname must be a string."
            )

        clean_hostname = hostname.strip().rstrip(".")

        if not clean_hostname:
            raise ValueError(
                "gateway_hostname must be a non-empty string."
            )

        if len(clean_hostname) > MAX_HOSTNAME_LENGTH:
            raise ValueError(
                "gateway_hostname exceeds the maximum DNS hostname length."
            )

        if any(
            ord(character) < 32 or ord(character) == 127
            for character in clean_hostname
        ):
            raise ValueError(
                "gateway_hostname contains invalid control characters."
            )

        if "/" in clean_hostname:
            raise ValueError(
                "gateway_hostname must contain only a hostname."
            )

        if ":" in clean_hostname:
            raise ValueError(
                "gateway_hostname must not contain a port."
            )

        if not HOSTNAME_PATTERN.fullmatch(clean_hostname):
            raise ValueError(
                "gateway_hostname is not a valid DNS hostname."
            )

        return clean_hostname

    @staticmethod
    def _validate_http_timeout(timeout: int) -> None:
        """Validate the HTTP health-check timeout."""
        if isinstance(timeout, bool) or not isinstance(timeout, int):
            raise ValueError(
                "http_timeout_seconds must be an integer."
            )

        if not (
            MIN_HTTP_TIMEOUT_SECONDS
            <= timeout
            <= MAX_HTTP_TIMEOUT_SECONDS
        ):
            raise ValueError(
                "http_timeout_seconds must be between "
                f"{MIN_HTTP_TIMEOUT_SECONDS} and "
                f"{MAX_HTTP_TIMEOUT_SECONDS} seconds."
            )

    def run_all_checks(self) -> HealthCheckResult:
        """Execute all required post-recovery health checks."""

        evaluated_at = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()

        checks: List[dict] = []

        tsm_healthy = self._check_tsm_status(checks)

        gateway_reachable = self._check_gateway(checks)

        overall_healthy = (
            tsm_healthy
            and gateway_reachable
        )

        if overall_healthy:
            logger.info(
                "All Tableau DR health checks passed."
            )
        else:
            logger.error(
                "Tableau DR health validation failed. "
                "tsm_healthy=%s gateway_reachable=%s",
                tsm_healthy,
                gateway_reachable,
            )

        return HealthCheckResult(
            overall_healthy=overall_healthy,
            evaluated_at_utc=evaluated_at,
            gateway_reachable=gateway_reachable,
            tsm_healthy=tsm_healthy,
            checks=checks,
        )

    def _check_tsm_status(
        self,
        checks: List[dict],
    ) -> bool:
        """Validate Tableau Services Manager cluster status."""

        try:
            result = self.tsm.status()

        except Exception as exc:
            logger.error(
                "TSM health check could not be completed: %s",
                self._sanitize_error(exc),
            )

            checks.append(
                {
                    "name": "TSM_STATUS",
                    "status": "FAIL",
                    "details": (
                        "TSM health check could not be completed."
                    ),
                }
            )

            return False

        healthy = result.success

        checks.append(
            {
                "name": "TSM_STATUS",
                "status": (
                    "PASS"
                    if healthy
                    else "FAIL"
                ),
                "details": (
                    "TSM reported a successful status."
                    if healthy
                    else (
                        "TSM status command returned a "
                        "non-zero exit code."
                    )
                ),
            }
        )

        if healthy:
            logger.info(
                "TSM health check passed."
            )
        else:
            logger.error(
                "TSM health check failed."
            )

        return healthy

    def _check_gateway(
        self,
        checks: List[dict],
    ) -> bool:
        """
        Validate Tableau Gateway reachability over HTTPS.

        TLS certificate verification remains enabled. Redirects are disabled
        so the check cannot silently move to an unexpected host.
        """

        url = (
            f"https://{self.gateway_hostname}/"
        )

        request = urllib.request.Request(
            url=url,
            method="HEAD",
            headers={
                "User-Agent": "Tableau-DR-HealthCheck/2.0",
                "Accept": "text/html,application/xhtml+xml",
            },
        )

        try:
            ssl_context = ssl.create_default_context()

            opener = urllib.request.build_opener(
                _NoRedirectHandler()
            )

            with opener.open(
                request,
                timeout=self.http_timeout_seconds,
                context=ssl_context,
            ) as response:
                status_code = int(response.status)

                healthy = (
                    200
                    <= status_code
                    < 500
                )

                self._record_gateway_result(
                    checks=checks,
                    status_code=status_code,
                    healthy=healthy,
                )

                if healthy:
                    logger.info(
                        "Tableau Gateway health check passed. "
                        "http_status=%s",
                        status_code,
                    )
                else:
                    logger.error(
                        "Tableau Gateway returned an unhealthy "
                        "HTTP status. http_status=%s",
                        status_code,
                    )

                return healthy

        except urllib.error.HTTPError as exc:
            # HTTP 401/403 and other 4xx responses still prove that
            # the Gateway endpoint is reachable.
            reachable = (
                200
                <= exc.code
                < 500
            )

            self._record_gateway_result(
                checks=checks,
                status_code=exc.code,
                healthy=reachable,
            )

            if reachable:
                logger.info(
                    "Tableau Gateway is reachable. "
                    "http_status=%s",
                    exc.code,
                )
            else:
                logger.error(
                    "Tableau Gateway returned an unhealthy "
                    "HTTP status. http_status=%s",
                    exc.code,
                )

            return reachable

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as exc:
            logger.error(
                "Tableau Gateway health check failed: %s",
                self._sanitize_error(exc),
            )

            checks.append(
                {
                    "name": "TABLEAU_GATEWAY",
                    "status": "FAIL",
                    "details": (
                        "Tableau Gateway was not reachable."
                    ),
                }
            )

            return False

        except Exception as exc:
            logger.error(
                "Unexpected Gateway health-check failure: %s",
                self._sanitize_error(exc),
            )

            checks.append(
                {
                    "name": "TABLEAU_GATEWAY",
                    "status": "FAIL",
                    "details": (
                        "Tableau Gateway health check "
                        "could not be completed."
                    ),
                }
            )

            return False

    @staticmethod
    def _record_gateway_result(
        checks: List[dict],
        status_code: int,
        healthy: bool,
    ) -> None:
        """Record a gateway health-check result."""
        checks.append(
            {
                "name": "TABLEAU_GATEWAY",
                "status": (
                    "PASS"
                    if healthy
                    else "FAIL"
                ),
                "details": (
                    f"Gateway responded with HTTP {status_code}."
                ),
            }
        )

    @staticmethod
    def _sanitize_error(error: object) -> str:
        """Return a safe error representation without exposing secrets."""
        text = str(error)

        sensitive_terms = (
            "password",
            "passwd",
            "passphrase",
            "secret",
            "token",
            "access_token",
            "client_secret",
            "sas",
            "private_key",
        )

        if any(
            term in text.lower()
            for term in sensitive_terms
        ):
            return "[REDACTED_ERROR]"

        # Avoid multiline log injection and keep diagnostics bounded.
        text = " ".join(text.split())

        return text[:500]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent the health check from following HTTP redirects."""

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        """Reject redirects instead of following another endpoint."""
        return None