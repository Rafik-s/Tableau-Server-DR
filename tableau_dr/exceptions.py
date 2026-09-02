"""Custom exception hierarchy for the Tableau Server DR framework."""

from __future__ import annotations


class TableauDRError(Exception):
    """Base exception for all Tableau DR framework failures."""


class ConfigurationError(TableauDRError):
    """Raised when configuration is missing, invalid, or unsafe."""


class ValidationError(TableauDRError):
    """Raised when a required operational validation fails."""


class SecurityValidationError(ValidationError):
    """Raised when a security control or security validation fails."""


class IntegrityError(ValidationError):
    """Raised when backup or recovery artifact integrity validation fails."""


class TSMError(TableauDRError):
    """Raised when a Tableau Services Manager operation fails."""


class AzureError(TableauDRError):
    """Raised when an Azure storage or Azure service operation fails."""


class RecoveryError(TableauDRError):
    """Raised when the disaster recovery state machine cannot continue."""


class FencingError(SecurityValidationError):
    """Raised when production fencing cannot be safely completed."""


class HealthCheckError(RecoveryError):
    """Raised when post-recovery health validation fails."""