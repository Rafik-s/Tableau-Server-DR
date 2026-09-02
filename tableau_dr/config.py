"""
Enterprise YAML configuration parser with strict schema validation.

The configuration layer is intentionally fail-closed. Invalid, missing,
empty, or unsafe configuration values raise ConfigurationError before any
backup or recovery operation can start.
"""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any, Dict

import yaml

from tableau_dr.exceptions import ConfigurationError


class Config:
    """Parse and validate Tableau Server DR YAML configuration."""

    REQUIRED_SCHEMA = {
        ("environment", "version"): str,
        ("azure", "key_vault_name"): str,
        ("azure", "storage_account_name"): str,
        ("azure", "storage_container"): str,
        ("azure", "max_retries"): int,
        ("azure", "retry_backoff_factor"): (int, float),
        ("servers", "production", "hostname"): str,
        ("servers", "production", "identity_store"): str,
        ("servers", "disaster_recovery", "hostname"): str,
        ("servers", "disaster_recovery", "identity_store"): str,
        ("paths", "backup_dir"): str,
        ("paths", "recovery_work_dir"): str,
        ("backup", "minimum_free_space_gb"): (int, float),
        ("backup", "minimum_backup_size_mb"): (int, float),
        ("backup", "verify_remote_content_sha256"): bool,
    }

    ALLOWED_IDENTITY_STORES = {
        "activedirectory",
        "local",
        "ldap",
    }

    MAX_RETRIES_LIMIT = 10
    MAX_RETRY_BACKOFF_SECONDS = 300.0
    MAX_FREE_SPACE_GB = 10_000_000.0
    MAX_BACKUP_SIZE_MB = 10_000_000.0

    def __init__(
        self,
        config_path: str | Path = "config/config.yaml",
    ) -> None:
        """Load and validate the supplied YAML configuration."""

        self.config_path = Path(config_path)

        self._raw_data = self._load_yaml()
        self.validate_schema()

    # ------------------------------------------------------------------
    # YAML loading
    # ------------------------------------------------------------------

    def _load_yaml(self) -> Dict[str, Any]:
        """Load YAML configuration using safe YAML parsing."""

        if not self.config_path.exists():
            raise ConfigurationError(
                f"Configuration file not found: {self.config_path}"
            )

        if not self.config_path.is_file():
            raise ConfigurationError(
                f"Configuration path is not a file: {self.config_path}"
            )

        try:
            with self.config_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = yaml.safe_load(file)

        except yaml.YAMLError as exc:
            raise ConfigurationError(
                "Failed to parse YAML configuration."
            ) from exc

        except OSError as exc:
            raise ConfigurationError(
                f"Unable to read configuration file: {self.config_path}"
            ) from exc

        if data is None:
            raise ConfigurationError(
                "Configuration file is empty."
            )

        if not isinstance(data, dict):
            raise ConfigurationError(
                "Configuration root must be a YAML mapping/object."
            )

        return data

    # ------------------------------------------------------------------
    # Schema validation
    # ------------------------------------------------------------------

    def validate_schema(self) -> None:
        """
        Validate required keys, strict datatypes, values, and
        cross-field constraints.
        """

        for path_keys, expected_type in self.REQUIRED_SCHEMA.items():
            current: Any = self._raw_data

            for key in path_keys:
                if (
                    not isinstance(current, dict)
                    or key not in current
                ):
                    raise ConfigurationError(
                        "Missing required configuration key: "
                        f"{' -> '.join(path_keys)}"
                    )

                current = current[key]

            self._validate_value_type(
                path_keys=path_keys,
                value=current,
                expected_type=expected_type,
            )

            self._validate_scalar_value(
                path_keys=path_keys,
                value=current,
            )

        self._validate_top_level_sections()
        self._validate_environment()
        self._validate_azure()
        self._validate_servers()
        self._validate_paths()
        self._validate_backup()
        self._validate_tsm()
        self._validate_security()

    @staticmethod
    def _validate_value_type(
        path_keys: tuple[str, ...],
        value: Any,
        expected_type: Any,
    ) -> None:
        """
        Validate datatype while treating bool separately from numbers.

        Python considers bool an int subclass, so a strict check is
        required for numeric configuration fields.
        """

        path = " -> ".join(path_keys)

        if expected_type is bool:
            if type(value) is not bool:
                raise ConfigurationError(
                    f"Invalid datatype for key: {path}"
                )
            return

        if expected_type is int:
            if type(value) is not int:
                raise ConfigurationError(
                    f"Invalid datatype for key: {path}"
                )
            return

        if expected_type == (int, float):
            if (
                type(value) not in (int, float)
                or isinstance(value, bool)
            ):
                raise ConfigurationError(
                    f"Invalid datatype for key: {path}"
                )
            return

        if not isinstance(value, expected_type):
            raise ConfigurationError(
                f"Invalid datatype for key: {path}"
            )

    @staticmethod
    def _validate_scalar_value(
        path_keys: tuple[str, ...],
        value: Any,
    ) -> None:
        """Validate generic scalar safety constraints."""

        path = " -> ".join(path_keys)

        if isinstance(value, str):
            if not value.strip():
                raise ConfigurationError(
                    f"Empty value for key: {path}"
                )

            # Configuration should never contain control characters.
            if any(
                ord(character) < 32
                or ord(character) == 127
                for character in value
            ):
                raise ConfigurationError(
                    f"Invalid control character in key: {path}"
                )

        elif isinstance(value, (int, float)):
            if isinstance(value, bool):
                return

            if not math.isfinite(float(value)):
                raise ConfigurationError(
                    f"Numeric value must be finite for key: {path}"
                )

            if value < 0:
                raise ConfigurationError(
                    "Numeric value cannot be negative for key: "
                    f"{path}"
                )

    def _validate_top_level_sections(self) -> None:
        """Ensure required top-level sections are mappings."""

        required_sections = (
            "environment",
            "azure",
            "servers",
            "paths",
            "backup",
            "tsm",
            "security",
        )

        for section in required_sections:
            value = self._raw_data.get(section)

            if not isinstance(value, dict):
                raise ConfigurationError(
                    f"Configuration section '{section}' "
                    "must be a YAML mapping/object."
                )

    # ------------------------------------------------------------------
    # Environment
    # ------------------------------------------------------------------

    def _validate_environment(self) -> None:
        """Validate environment metadata."""

        version = self.environment["version"].strip()

        if not version:
            raise ConfigurationError(
                "environment -> version cannot be empty."
            )

        if len(version) > 100:
            raise ConfigurationError(
                "environment -> version is too long."
            )

    # ------------------------------------------------------------------
    # Azure
    # ------------------------------------------------------------------

    def _validate_azure(self) -> None:
        """Validate Azure storage and retry configuration."""

        max_retries = self.azure["max_retries"]
        retry_backoff_factor = (
            self.azure["retry_backoff_factor"]
        )

        if type(max_retries) is not int:
            raise ConfigurationError(
                "azure -> max_retries must be an integer."
            )

        # AzureManager requires at least one retry attempt.
        if not 1 <= max_retries <= self.MAX_RETRIES_LIMIT:
            raise ConfigurationError(
                "azure -> max_retries must be between "
                f"1 and {self.MAX_RETRIES_LIMIT}."
            )

        if isinstance(
            retry_backoff_factor,
            bool,
        ):
            raise ConfigurationError(
                "azure -> retry_backoff_factor must be numeric."
            )

        if not math.isfinite(
            float(retry_backoff_factor)
        ):
            raise ConfigurationError(
                "azure -> retry_backoff_factor must be finite."
            )

        if not (
            0.0
            <= float(retry_backoff_factor)
            <= self.MAX_RETRY_BACKOFF_SECONDS
        ):
            raise ConfigurationError(
                "azure -> retry_backoff_factor is outside "
                "the allowed range."
            )

        self._validate_nonempty_string(
            self.azure["key_vault_name"],
            "azure -> key_vault_name",
        )

        self._validate_nonempty_string(
            self.azure["storage_account_name"],
            "azure -> storage_account_name",
        )

        self._validate_nonempty_string(
            self.azure["storage_container"],
            "azure -> storage_container",
        )

        self._validate_storage_name(
            self.azure["storage_account_name"],
            "azure -> storage_account_name",
        )

        self._validate_storage_container(
            self.azure["storage_container"],
        )

    # ------------------------------------------------------------------
    # Server configuration
    # ------------------------------------------------------------------

    def _validate_servers(self) -> None:
        """Validate production and DR server configuration."""

        production = self.servers["production"]
        disaster_recovery = (
            self.servers["disaster_recovery"]
        )

        if not isinstance(production, dict):
            raise ConfigurationError(
                "servers -> production must be a mapping."
            )

        if not isinstance(disaster_recovery, dict):
            raise ConfigurationError(
                "servers -> disaster_recovery must be a mapping."
            )

        prod_hostname = (
            production["hostname"]
            .strip()
            .casefold()
        )

        dr_hostname = (
            disaster_recovery["hostname"]
            .strip()
            .casefold()
        )

        if prod_hostname == dr_hostname:
            raise ConfigurationError(
                "Production and disaster recovery hostnames "
                "must be different."
            )

        prod_store = (
            production["identity_store"]
            .strip()
            .casefold()
        )

        dr_store = (
            disaster_recovery["identity_store"]
            .strip()
            .casefold()
        )

        if prod_store not in self.ALLOWED_IDENTITY_STORES:
            raise ConfigurationError(
                "Unsupported production identity store: "
                f"{prod_store}"
            )

        if dr_store not in self.ALLOWED_IDENTITY_STORES:
            raise ConfigurationError(
                "Unsupported DR identity store: "
                f"{dr_store}"
            )

        # DR must use the same identity-store type as production.
        if prod_store != dr_store:
            raise ConfigurationError(
                "Production and disaster recovery must use "
                "the same identity store."
            )

    # ------------------------------------------------------------------
    # Filesystem paths
    # ------------------------------------------------------------------

    def _validate_paths(self) -> None:
        """Validate required filesystem path configuration."""

        for name in (
            "backup_dir",
            "recovery_work_dir",
        ):
            value = self.paths[name]

            self._validate_nonempty_string(
                value,
                f"paths -> {name}",
            )

            path = Path(value)

            if path.is_file():
                raise ConfigurationError(
                    f"paths -> {name} points to an existing file."
                )

            # Reject obvious wildcard/path-template values.
            if any(
                character in value
                for character in ("*", "?", "\x00")
            ):
                raise ConfigurationError(
                    f"paths -> {name} contains invalid path characters."
                )

    # ------------------------------------------------------------------
    # Backup configuration
    # ------------------------------------------------------------------

    def _validate_backup(self) -> None:
        """Validate backup safety thresholds."""

        minimum_free_space = (
            self.backup["minimum_free_space_gb"]
        )

        minimum_backup_size = (
            self.backup["minimum_backup_size_mb"]
        )

        if isinstance(
            minimum_free_space,
            bool,
        ):
            raise ConfigurationError(
                "backup -> minimum_free_space_gb must be numeric."
            )

        if isinstance(
            minimum_backup_size,
            bool,
        ):
            raise ConfigurationError(
                "backup -> minimum_backup_size_mb must be numeric."
            )

        if not (
            0.0
            < float(minimum_free_space)
            <= self.MAX_FREE_SPACE_GB
        ):
            raise ConfigurationError(
                "backup -> minimum_free_space_gb is outside "
                "the allowed range."
            )

        if not (
            0.0
            < float(minimum_backup_size)
            <= self.MAX_BACKUP_SIZE_MB
        ):
            raise ConfigurationError(
                "backup -> minimum_backup_size_mb is outside "
                "the allowed range."
            )

        if type(
            self.backup[
                "verify_remote_content_sha256"
            ]
        ) is not bool:
            raise ConfigurationError(
                "backup -> verify_remote_content_sha256 "
                "must be boolean."
            )

    # ------------------------------------------------------------------
    # TSM configuration
    # ------------------------------------------------------------------

    def _validate_tsm(self) -> None:
        """
        Validate optional TSM configuration.

        The TSM executable may be omitted because TSMConnector supports
        environment/PATH based executable resolution.
        """

        executable = self.tsm.get(
            "executable"
        )

        if executable is None:
            return

        if not isinstance(
            executable,
            str,
        ):
            raise ConfigurationError(
                "tsm -> executable must be a string."
            )

        executable = executable.strip()

        if not executable:
            raise ConfigurationError(
                "tsm -> executable cannot be empty when configured."
            )

        if any(
            ord(character) < 32
            or ord(character) == 127
            for character in executable
        ):
            raise ConfigurationError(
                "tsm -> executable contains invalid characters."
            )

    # ------------------------------------------------------------------
    # Security configuration
    # ------------------------------------------------------------------

    def _validate_security(self) -> None:
        """
        Validate security controls.

        Fencing settings are optional at the schema level so older
        configurations can still be loaded, but if supplied they must
        use strict boolean values.
        """

        boolean_keys = (
            "production_fencing_enabled",
            "production_fencing_confirmed",
        )

        for key in boolean_keys:
            if key not in self.security:
                continue

            if type(
                self.security[key]
            ) is not bool:
                raise ConfigurationError(
                    f"security -> {key} must be boolean."
                )

        auth_code = self.security.get(
            "emergency_fencing_auth_code"
        )

        if auth_code is not None:
            if not isinstance(
                auth_code,
                str,
            ):
                raise ConfigurationError(
                    "security -> emergency_fencing_auth_code "
                    "must be a string."
                )

            normalized = auth_code.strip()

            if normalized:
                if len(normalized) > 256:
                    raise ConfigurationError(
                        "security -> emergency_fencing_auth_code "
                        "is too long."
                    )

                # The real secret should not be committed to source
                # control. The placeholder is permitted here so the
                # example configuration remains usable.
                if (
                    normalized
                    != "CHANGE_ME_IN_SECURE_VAULT"
                    and len(normalized) < 16
                ):
                    raise ConfigurationError(
                        "Configured emergency fencing authorization "
                        "must be at least 16 characters."
                    )

    # ------------------------------------------------------------------
    # Azure naming helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_storage_name(
        value: str,
        field_name: str,
    ) -> None:
        """Validate an Azure Storage Account name."""

        value = value.strip()

        if not (
            3 <= len(value) <= 24
        ):
            raise ConfigurationError(
                f"{field_name} must contain between "
                "3 and 24 characters."
            )

        if not value.islower():
            raise ConfigurationError(
                f"{field_name} must contain lowercase characters only."
            )

        if not value.isalnum():
            raise ConfigurationError(
                f"{field_name} must contain only letters and numbers."
            )

    @staticmethod
    def _validate_storage_container(
        value: str,
    ) -> None:
        """Validate an Azure Blob Storage container name."""

        value = value.strip()

        if not (
            3 <= len(value) <= 63
        ):
            raise ConfigurationError(
                "azure -> storage_container must contain "
                "between 3 and 63 characters."
            )

        if (
            value[0] == "-"
            or value[-1] == "-"
            or "--" in value
        ):
            raise ConfigurationError(
                "azure -> storage_container has invalid "
                "hyphen placement."
            )

        if not all(
            character.islower()
            or character.isdigit()
            or character == "-"
            for character in value
        ):
            raise ConfigurationError(
                "azure -> storage_container contains invalid characters."
            )

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_nonempty_string(
        value: Any,
        field_name: str,
    ) -> None:
        """Validate a required non-empty string."""

        if not isinstance(
            value,
            str,
        ):
            raise ConfigurationError(
                f"{field_name} must be a string."
            )

        if not value.strip():
            raise ConfigurationError(
                f"{field_name} cannot be empty."
            )

    # ------------------------------------------------------------------
    # Public configuration properties
    # ------------------------------------------------------------------

    @property
    def environment(self) -> Dict[str, Any]:
        """Return environment configuration."""

        return self._raw_data.get(
            "environment",
            {},
        )

    @property
    def azure(self) -> Dict[str, Any]:
        """Return Azure configuration."""

        return self._raw_data.get(
            "azure",
            {},
        )

    @property
    def servers(self) -> Dict[str, Any]:
        """Return server configuration."""

        return self._raw_data.get(
            "servers",
            {},
        )

    @property
    def paths(self) -> Dict[str, Any]:
        """Return filesystem path configuration."""

        return self._raw_data.get(
            "paths",
            {},
        )

    @property
    def backup(self) -> Dict[str, Any]:
        """Return backup configuration."""

        return self._raw_data.get(
            "backup",
            {},
        )

    @property
    def tsm(self) -> Dict[str, Any]:
        """Return TSM configuration."""

        return self._raw_data.get(
            "tsm",
            {},
        )

    @property
    def security(self) -> Dict[str, Any]:
        """Return security configuration."""

        return self._raw_data.get(
            "security",
            {},
        )