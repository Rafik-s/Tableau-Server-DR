"""Production fencing controls for safe Tableau Server DR failover."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import logging
from dataclasses import asdict, dataclass
from typing import Optional

from tableau_dr.config import Config
from tableau_dr.exceptions import FencingError, SecurityValidationError


logger = logging.getLogger(__name__)

AUTH_CODE_MIN_LENGTH = 16
AUTH_CODE_MAX_LENGTH = 256
OPERATOR_REASON_MAX_LENGTH = 1000


@dataclass(frozen=True)
class FencingResult:
    """Machine-readable result of the production fencing evaluation."""

    is_fenced: bool
    method: str
    evaluated_at_utc: str
    authorization_required: bool
    authorization_provided: bool
    operator_reason_provided: bool

    def to_dict(self) -> dict:
        """Return a JSON-serializable representation."""

        return asdict(self)


class ProductionFencer:
    """
    Validate that production is safe to abandon before DR activation.

    This class intentionally does not claim to physically power off,
    isolate, or disable a production server. Actual infrastructure
    fencing should be implemented through an approved external control
    such as an Azure Load Balancer, DNS workflow, VM/network isolation,
    or enterprise automation platform.

    The framework therefore fails closed unless a configured fencing
    signal or explicitly authorized emergency override proves that
    production has been fenced.
    """

    def __init__(
        self,
        config: Config,
    ) -> None:
        """Initialize fencing configuration."""

        self.config = config

        self.production_hostname = self._get_hostname(
            "production"
        )

        self.dr_hostname = self._get_hostname(
            "disaster_recovery"
        )

        if (
            self.production_hostname.lower()
            == self.dr_hostname.lower()
        ):
            raise SecurityValidationError(
                "Production and DR hostnames must be different."
            )

    def evaluate_fencing(
        self,
        emergency_authorization_code: Optional[str] = None,
        operator_reason: Optional[str] = None,
    ) -> FencingResult:
        """
        Evaluate whether production fencing requirements are satisfied.

        Normal operation requires an externally supplied fencing state.

        Emergency authorization can only bypass the normal fencing signal
        when both an authorization code and a documented operator reason
        are supplied. The authorization value is never logged.
        """

        evaluated_at = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()

        fencing_config = self.config.security

        fencing_enabled = self._get_bool(
            fencing_config,
            "production_fencing_enabled",
            default=False,
        )

        fencing_confirmed = self._get_bool(
            fencing_config,
            "production_fencing_confirmed",
            default=False,
        )

        expected_auth_code = self._get_configured_auth_code()

        authorization_provided = (
            emergency_authorization_code is not None
        )

        operator_reason_provided = (
            isinstance(operator_reason, str)
            and bool(operator_reason.strip())
        )

        if authorization_provided:
            self._validate_emergency_override(
                provided_code=emergency_authorization_code,
                operator_reason=operator_reason,
                expected_code=expected_auth_code,
            )

            logger.critical(
                "Emergency fencing authorization accepted. "
                "Production=%s DR=%s reason_provided=%s",
                self.production_hostname,
                self.dr_hostname,
                operator_reason_provided,
            )

            return FencingResult(
                is_fenced=True,
                method="EMERGENCY_AUTHORIZATION",
                evaluated_at_utc=evaluated_at,
                authorization_required=True,
                authorization_provided=True,
                operator_reason_provided=True,
            )

        if not fencing_enabled:
            raise FencingError(
                "Production fencing is not enabled in configuration. "
                "Refusing to continue with DR failover."
            )

        if not fencing_confirmed:
            raise FencingError(
                "Production fencing has not been confirmed. "
                "Refusing to continue with DR failover."
            )

        logger.warning(
            "Production fencing confirmed. "
            "Production=%s DR=%s",
            self.production_hostname,
            self.dr_hostname,
        )

        return FencingResult(
            is_fenced=True,
            method="CONFIGURED_FENCING_CONFIRMATION",
            evaluated_at_utc=evaluated_at,
            authorization_required=False,
            authorization_provided=False,
            operator_reason_provided=False,
        )

    def _get_configured_auth_code(self) -> Optional[str]:
        """
        Retrieve the configured emergency authorization value.

        For portfolio/demo configuration this supports a configured value,
        but production deployments should source the secret from Azure
        Key Vault or another approved secret-management system.
        """

        security_config = self.config.security

        value = security_config.get(
            "emergency_fencing_auth_code"
        )

        if value is None:
            return None

        if not isinstance(value, str):
            raise SecurityValidationError(
                "Configured emergency fencing authorization "
                "code must be a string."
            )

        normalized = value.strip()

        if not normalized:
            return None

        return normalized

    def _validate_emergency_override(
        self,
        provided_code: Optional[str],
        operator_reason: Optional[str],
        expected_code: Optional[str],
    ) -> None:
        """Validate emergency fencing authorization without exposing secrets."""

        if expected_code is None:
            raise SecurityValidationError(
                "Emergency fencing authorization is unavailable."
            )

        if not isinstance(provided_code, str):
            raise SecurityValidationError(
                "Emergency fencing authorization is invalid."
            )

        normalized_code = provided_code.strip()

        if not (
            AUTH_CODE_MIN_LENGTH
            <= len(normalized_code)
            <= AUTH_CODE_MAX_LENGTH
        ):
            raise SecurityValidationError(
                "Emergency fencing authorization is invalid."
            )

        if not isinstance(
            operator_reason,
            str,
        ):
            raise SecurityValidationError(
                "Operator reason is required for emergency fencing."
            )

        normalized_reason = operator_reason.strip()

        if not normalized_reason:
            raise SecurityValidationError(
                "Operator reason is required for emergency fencing."
            )

        if len(normalized_reason) > OPERATOR_REASON_MAX_LENGTH:
            raise SecurityValidationError(
                "Operator reason exceeds the maximum allowed length."
            )

        if (
            expected_code == "CHANGE_ME_IN_SECURE_VAULT"
        ):
            raise SecurityValidationError(
                "Emergency fencing authorization is still using "
                "the placeholder configuration."
            )

        expected_digest = hashlib.sha256(
            expected_code.encode("utf-8")
        ).digest()

        provided_digest = hashlib.sha256(
            normalized_code.encode("utf-8")
        ).digest()

        if not hmac.compare_digest(
            provided_digest,
            expected_digest,
        ):
            raise SecurityValidationError(
                "Emergency fencing authorization failed."
            )

    def _get_hostname(
        self,
        server_name: str,
    ) -> str:
        """Retrieve and validate a configured server hostname."""

        try:
            server_config = self.config.servers[
                server_name
            ]
        except (KeyError, TypeError) as exc:
            raise SecurityValidationError(
                f"Missing {server_name} server configuration."
            ) from exc

        hostname = server_config.get(
            "hostname"
        )

        if (
            not isinstance(hostname, str)
            or not hostname.strip()
        ):
            raise SecurityValidationError(
                f"{server_name} hostname must be configured."
            )

        return hostname.strip()

    @staticmethod
    def _get_bool(
        config: dict,
        key: str,
        default: bool,
    ) -> bool:
        """Read a strictly boolean security setting."""

        value = config.get(
            key,
            default,
        )

        if not isinstance(value, bool):
            raise SecurityValidationError(
                f"Security configuration '{key}' must be boolean."
            )

        return value