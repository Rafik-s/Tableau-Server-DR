"""
Production fencing controls for safe Tableau Server DR failover.

This module evaluates whether production has been safely fenced before
allowing DR recovery to proceed.

IMPORTANT:
    This component does not physically isolate or shut down production.
    Physical fencing must be performed by an approved infrastructure
    control such as Azure networking, Load Balancer, DNS, VM isolation,
    or an enterprise automation platform.

The recovery workflow fails closed unless:
    1. Configured production fencing is explicitly enabled AND confirmed,
       OR
    2. A valid emergency authorization code and operator reason are supplied.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import logging
import re
from dataclasses import asdict, dataclass
from typing import Any, Optional

from tableau_dr.config import Config
from tableau_dr.exceptions import (
    FencingError,
    SecurityValidationError,
)


logger = logging.getLogger(__name__)


AUTH_CODE_MIN_LENGTH = 16
AUTH_CODE_MAX_LENGTH = 256
OPERATOR_REASON_MAX_LENGTH = 1000
HOSTNAME_MAX_LENGTH = 253

# Prevent control characters from entering audit/logging fields.
SAFE_HOSTNAME_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
)

PLACEHOLDER_AUTH_CODES = {
    "CHANGE_ME_IN_SECURE_VAULT",
    "CHANGE_ME",
    "REPLACE_ME",
}


@dataclass(frozen=True)
class FencingResult:
    """Machine-readable result of production fencing evaluation."""

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
    Fail-closed production fencing evaluator.

    The class deliberately does not claim to perform physical fencing.
    It only validates an externally supplied fencing state or an
    explicitly authorized emergency override.
    """

    def __init__(
        self,
        config: Config,
    ) -> None:
        """Initialize and validate fencing configuration."""

        self.config = config

        self.production_hostname = self._get_hostname(
            "production"
        )

        self.dr_hostname = self._get_hostname(
            "disaster_recovery"
        )

        if (
            self.production_hostname.casefold()
            == self.dr_hostname.casefold()
        ):
            raise SecurityValidationError(
                "Production and DR hostnames must be different."
            )

    # ------------------------------------------------------------------
    # Public fencing evaluation
    # ------------------------------------------------------------------

    def evaluate_fencing(
        self,
        emergency_authorization_code: Optional[str] = None,
        operator_reason: Optional[str] = None,
    ) -> FencingResult:
        """
        Evaluate whether production fencing requirements are satisfied.

        Normal path:
            production_fencing_enabled = true
            production_fencing_confirmed = true

        Emergency path:
            valid authorization code
            + documented operator reason

        The authorization code and operator reason are never written
        to logs.
        """

        evaluated_at = (
            dt.datetime.now(
                dt.timezone.utc
            ).isoformat()
        )

        security_config = self.config.security

        fencing_enabled = self._get_bool(
            security_config,
            "production_fencing_enabled",
            default=False,
        )

        fencing_confirmed = self._get_bool(
            security_config,
            "production_fencing_confirmed",
            default=False,
        )

        expected_auth_code = (
            self._get_configured_auth_code()
        )

        authorization_provided = (
            emergency_authorization_code is not None
        )

        operator_reason_provided = (
            isinstance(
                operator_reason,
                str,
            )
            and bool(
                operator_reason.strip()
            )
        )

        # --------------------------------------------------------------
        # Emergency authorization path
        # --------------------------------------------------------------

        if authorization_provided:
            self._validate_emergency_override(
                provided_code=(
                    emergency_authorization_code
                ),
                operator_reason=operator_reason,
                expected_code=expected_auth_code,
            )

            # Do not log the reason or authorization code.
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

        # --------------------------------------------------------------
        # Normal configured-fencing path
        # --------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Emergency authorization
    # ------------------------------------------------------------------

    def _get_configured_auth_code(
        self,
    ) -> Optional[str]:
        """
        Retrieve the configured emergency authorization value.

        The current configuration interface supports a configured value
        for portfolio/demo deployments.

        Production deployments should retrieve this secret from Azure
        Key Vault or another approved enterprise secret store rather than
        storing the actual secret in YAML.
        """

        security_config = self.config.security

        value = security_config.get(
            "emergency_fencing_auth_code"
        )

        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
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
        *,
        provided_code: Optional[str],
        operator_reason: Optional[str],
        expected_code: Optional[str],
    ) -> None:
        """
        Validate emergency authorization without exposing the secret.

        SHA-256 digests are compared using hmac.compare_digest().
        """

        if expected_code is None:
            raise SecurityValidationError(
                "Emergency fencing authorization is unavailable."
            )

        if not isinstance(
            provided_code,
            str,
        ):
            raise SecurityValidationError(
                "Emergency fencing authorization is invalid."
            )

        normalized_code = (
            provided_code.strip()
        )

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

        normalized_reason = (
            operator_reason.strip()
        )

        if not normalized_reason:
            raise SecurityValidationError(
                "Operator reason is required for emergency fencing."
            )

        if len(normalized_reason) > (
            OPERATOR_REASON_MAX_LENGTH
        ):
            raise SecurityValidationError(
                "Operator reason exceeds the maximum allowed length."
            )

        # Reject known configuration placeholders.
        if (
            expected_code.strip()
            in PLACEHOLDER_AUTH_CODES
        ):
            raise SecurityValidationError(
                "Emergency fencing authorization is still using "
                "placeholder configuration."
            )

        if (
            len(expected_code)
            < AUTH_CODE_MIN_LENGTH
            or len(expected_code)
            > AUTH_CODE_MAX_LENGTH
        ):
            raise SecurityValidationError(
                "Configured emergency fencing authorization is invalid."
            )

        # Hash both values before comparison so the actual secret is
        # never passed directly to the comparison operation.
        expected_digest = hashlib.sha256(
            expected_code.encode(
                "utf-8"
            )
        ).digest()

        provided_digest = hashlib.sha256(
            normalized_code.encode(
                "utf-8"
            )
        ).digest()

        if not hmac.compare_digest(
            provided_digest,
            expected_digest,
        ):
            raise SecurityValidationError(
                "Emergency fencing authorization failed."
            )

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    def _get_hostname(
        self,
        server_name: str,
    ) -> str:
        """Retrieve and validate a configured server hostname."""

        try:
            server_config = (
                self.config.servers[
                    server_name
                ]
            )
        except (
            KeyError,
            TypeError,
        ) as exc:
            raise SecurityValidationError(
                f"Missing {server_name} server configuration."
            ) from exc

        if not isinstance(
            server_config,
            dict,
        ):
            raise SecurityValidationError(
                f"{server_name} server configuration is invalid."
            )

        hostname = server_config.get(
            "hostname"
        )

        if not isinstance(
            hostname,
            str,
        ):
            raise SecurityValidationError(
                f"{server_name} hostname must be configured."
            )

        hostname = hostname.strip()

        if not hostname:
            raise SecurityValidationError(
                f"{server_name} hostname must be configured."
            )

        if len(hostname) > HOSTNAME_MAX_LENGTH:
            raise SecurityValidationError(
                f"{server_name} hostname is too long."
            )

        if any(
            ord(character) < 32
            or ord(character) == 127
            for character in hostname
        ):
            raise SecurityValidationError(
                f"{server_name} hostname contains invalid characters."
            )

        if not SAFE_HOSTNAME_PATTERN.fullmatch(
            hostname
        ):
            raise SecurityValidationError(
                f"{server_name} hostname contains invalid characters."
            )

        return hostname

    @staticmethod
    def _get_bool(
        config: dict,
        key: str,
        default: bool,
    ) -> bool:
        """Read a strictly boolean security setting."""

        if not isinstance(
            config,
            dict,
        ):
            raise SecurityValidationError(
                "Security configuration is invalid."
            )

        value = config.get(
            key,
            default,
        )

        # bool must be checked explicitly because bool is a subclass
        # of int in Python.
        if not isinstance(
            value,
            bool,
        ):
            raise SecurityValidationError(
                f"Security configuration '{key}' must be boolean."
            )

        return value