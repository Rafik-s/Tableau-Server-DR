"""Custom exception hierarchy for Tableau DR automation."""

class TableauDRError(Exception):
    """Base exception for all Tableau DR operations."""


class ConfigurationError(TableauDRError):
    """Raised when configuration validation or parsing fails."""


class TSMError(TableauDRError):
    """Raised when TSM CLI command execution fails."""


class ValidationError(TableauDRError):
    """Raised when preflight or artifact validation checks fail."""


class SecurityValidationError(ValidationError):
    """Raised when SHA-256 integrity or security boundaries are violated."""


class IntegrityError(ValidationError):
    """Raised when artifact payload sizes or checksums mismatch remote targets."""


class RecoveryError(TableauDRError):
    """Raised when DR recovery or failover steps fail."""