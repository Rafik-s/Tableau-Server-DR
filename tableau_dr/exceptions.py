"""Custom exception hierarchy for Tableau DR Operations."""

class TableauDRError(Exception):
    """Base exception for all Tableau DR operations."""
    pass

class TSMError(TableauDRError):
    """Raised when a TSM CLI command fails."""
    pass

class SecurityValidationError(TableauDRError):
    """Raised when SHA-256 checksum or file validation fails."""
    pass

class ValidationError(TableauDRError):
    """Raised during pre-flight or system compatibility checks."""
    pass

class ConfigurationError(TableauDRError):
    """Raised when configuration parsing or validation fails."""
    pass

class HealthCheckError(TableauDRError):
    """Raised when Tableau fails post-restore health smoke tests."""
    pass