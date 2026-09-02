"""Post-recovery health checks for Tableau Server DR validation."""

from __future__ import annotations

import datetime
import logging
from dataclasses import asdict, dataclass
from typing import List

from tableau_dr.exceptions import HealthCheckError
from tableau_dr.tab_server_connector import TSMConnector


logger = logging.getLogger(__name__)

DEFAULT_HTTP_TIMEOUT_SECONDS = 15
DEFAULT_TSM_TIMEOUT_SECONDS = 120


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
    - Tableau Gateway HTTP/HTTPS reachability.
    - HTTP response indicates a reachable Tableau endpoint.

    A successful TCP/HTTP connection alone is not treated as proof that
    Tableau is fully healthy; TSM status must also pass.
    """

    def __init__(
        self,
        tsm_connector: TSMConnector,
        gateway_hostname: str,
        http_timeout_seconds: int = DEFAULT_HTTP_TIMEOUT_SECONDS,
    ) -> None:
        """Initialize the health checker."""

        if not isinstance(
            tsm_connector,
            TSMConnector,
        ):
            raise TypeError(
                "tsm_connector must be a TSMConnector instance."
            )

        if (
            not isinstance(gateway_hostname, str)
            or not gateway_hostname.strip()
        ):
            raise ValueError(
                "gateway_hostname must be a non-empty string."
            )

        if (
            isinstance(http_timeout_seconds, bool)
            or not isinstance(http_timeout_seconds, int)
            or http_timeout_seconds <= 0
        ):
            raise ValueError(
                "http_timeout_seconds must be a positive integer."
            )

        self.tsm = tsm_connector
        self.gateway_hostname = gateway_hostname.strip()
        self.http_timeout_seconds = http_timeout_seconds

    def run_all_checks(self) -> HealthCheckResult:
        """Execute all required post-recovery health checks."""

        evaluated_at = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()

        checks: List[dict] = []

        tsm_healthy = self._check_tsm_status(
            checks
        )

        gateway_reachable = self._check_gateway(
            checks
        )

        overall_healthy = (
            tsm_healthy
            and gateway_reachable
        )

        if overall_healthy:
            logger.info(
                "All Tableau DR health checks passed. hostname=%s",
                self.gateway_hostname,
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
            result = self.tsm.run(
                ["status", "-v"],
                timeout=DEFAULT_TSM_TIMEOUT_SECONDS,
                check=False,
            )

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
                        else "TSM status command returned a non-zero exit code."
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

        except Exception as exc:
            logger.error(
                "TSM health check encountered an error: %s",
                self._sanitize_error(exc),
            )

            checks.append(
                {
                    "name": "TSM_STATUS",
                    "status": "FAIL",
                    "details": "TSM health check could not be completed.",
                }
            )

            return False

    def _check_gateway(
        self,
        checks: List[dict],
    ) -> bool:
        """Validate Tableau Gateway reachability over HTTPS."""

        import ssl
        import urllib.error
        import urllib.request

        url = (
            f"https://{self.gateway_hostname}/"
        )

        request = urllib.request.Request(
            url=url,
            method="GET",
            headers={
                "User-Agent": "Tableau-DR-HealthCheck/1.0",
            },
        )

        try:
            ssl_context = ssl.create_default_context()

            with urllib.request.urlopen(
                request,
                timeout=self.http_timeout_seconds,
                context=ssl_context,
            ) as response:
                status_code = response.status

                healthy = (
                    200
                    <= status_code
                    < 500
                )

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

                if healthy:
                    logger.info(
                        "Tableau Gateway health check passed. "
                        "http_status=%s",
                        status_code,
                    )

                return healthy

        except urllib.error.HTTPError as exc:
            # HTTP 401/403 still proves that the Gateway is reachable.
            reachable = (
                200
                <= exc.code
                < 500
            )

            checks.append(
                {
                    "name": "TABLEAU_GATEWAY",
                    "status": (
                        "PASS"
                        if reachable
                        else "FAIL"
                    ),
                    "details": (
                        f"Gateway responded with HTTP {exc.code}."
                    ),
                }
            )

            if reachable:
                logger.info(
                    "Tableau Gateway is reachable. "
                    "http_status=%s",
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
                        "Tableau Gateway health check could not be completed."
                    ),
                }
            )

            return False

    @staticmethod
    def _sanitize_error(
        error: object,
    ) -> str:
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

        return text[:500]