"""Enterprise YAML Configuration Parser with strict schema validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml

from tableau_dr.exceptions import ConfigurationError


class Config:
    """Parses and validates the YAML disaster recovery configuration."""

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

    def __init__(self, config_path: str | Path = "config/config.yaml"):
        self.config_path = Path(config_path)
        self._raw_data = self._load_yaml()
        self.validate_schema()

    def _load_yaml(self) -> Dict[str, Any]:
        """Load YAML configuration safely."""
        if not self.config_path.exists():
            raise ConfigurationError(
                f"Configuration file not found: {self.config_path}"
            )

        if not self.config_path.is_file():
            raise ConfigurationError(
                f"Configuration path is not a file: {self.config_path}"
            )

        try:
            with self.config_path.open("r", encoding="utf-8") as file:
                data = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            raise ConfigurationError(
                f"Failed to parse YAML configuration: {exc}"
            ) from exc
        except OSError as exc:
            raise ConfigurationError(
                f"Unable to read configuration file: {self.config_path}"
            ) from exc

        if data is None:
            return {}

        if not isinstance(data, dict):
            raise ConfigurationError(
                "Configuration root must be a YAML mapping/object."
            )

        return data

    def validate_schema(self) -> None:
        """Validate required keys, types, values, and cross-field constraints."""

        for path_keys, expected_type in self.REQUIRED_SCHEMA.items():
            current: Any = self._raw_data

            for key in path_keys:
                if not isinstance(current, dict) or key not in current:
                    raise ConfigurationError(
                        "Missing required configuration key: "
                        f"{' -> '.join(path_keys)}"
                    )

                current = current[key]

            if not isinstance(current, expected_type):
                raise ConfigurationError(
                    "Invalid datatype for key: "
                    f"{' -> '.join(path_keys)}"
                )

            if isinstance(current, str) and not current.strip():
                raise ConfigurationError(
                    "Empty value for key: "
                    f"{' -> '.join(path_keys)}"
                )

            if isinstance(current, bool):
                continue

            if isinstance(current, (int, float)):
                if current < 0:
                    raise ConfigurationError(
                        "Numeric value cannot be negative for key: "
                        f"{' -> '.join(path_keys)}"
                    )

        self._validate_azure()
        self._validate_servers()
        self._validate_paths()
        self._validate_backup()

    def _validate_azure(self) -> None:
        """Validate Azure retry configuration."""

        max_retries = self.azure["max_retries"]
        retry_backoff_factor = self.azure["retry_backoff_factor"]

        if max_retries < 0:
            raise ConfigurationError(
                "azure -> max_retries must be >= 0"
            )

        if retry_backoff_factor < 0:
            raise ConfigurationError(
                "azure -> retry_backoff_factor must be >= 0"
            )

    def _validate_servers(self) -> None:
        """Validate production and DR server configuration."""

        production = self.servers["production"]
        disaster_recovery = self.servers["disaster_recovery"]

        prod_hostname = production["hostname"].strip().lower()
        dr_hostname = disaster_recovery["hostname"].strip().lower()

        if prod_hostname == dr_hostname:
            raise ConfigurationError(
                "Production and disaster recovery hostnames "
                "must be different."
            )

        prod_store = production["identity_store"].strip().lower()
        dr_store = disaster_recovery["identity_store"].strip().lower()

        if prod_store not in self.ALLOWED_IDENTITY_STORES:
            raise ConfigurationError(
                f"Unsupported production identity store: {prod_store}"
            )

        if dr_store not in self.ALLOWED_IDENTITY_STORES:
            raise ConfigurationError(
                f"Unsupported DR identity store: {dr_store}"
            )

    def _validate_paths(self) -> None:
        """Validate required filesystem paths."""

        for name in ("backup_dir", "recovery_work_dir"):
            value = self.paths[name]

            if not value.strip():
                raise ConfigurationError(
                    f"paths -> {name} cannot be empty"
                )

    def _validate_backup(self) -> None:
        """Validate backup safety thresholds."""

        minimum_free_space = self.backup["minimum_free_space_gb"]
        minimum_backup_size = self.backup["minimum_backup_size_mb"]

        if minimum_free_space <= 0:
            raise ConfigurationError(
                "backup -> minimum_free_space_gb must be greater than 0"
            )

        if minimum_backup_size <= 0:
            raise ConfigurationError(
                "backup -> minimum_backup_size_mb must be greater than 0"
            )

    @property
    def environment(self) -> Dict[str, Any]:
        return self._raw_data.get("environment", {})

    @property
    def azure(self) -> Dict[str, Any]:
        return self._raw_data.get("azure", {})

    @property
    def servers(self) -> Dict[str, Any]:
        return self._raw_data.get("servers", {})

    @property
    def paths(self) -> Dict[str, Any]:
        return self._raw_data.get("paths", {})

    @property
    def backup(self) -> Dict[str, Any]:
        return self._raw_data.get("backup", {})

    @property
    def tsm(self) -> Dict[str, Any]:
        return self._raw_data.get("tsm", {})

    @property
    def security(self) -> Dict[str, Any]:
        return self._raw_data.get("security", {})