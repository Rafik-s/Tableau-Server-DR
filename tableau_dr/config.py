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

    ALLOWED_IDENTITY_STORES = {"activedirectory", "local", "ldap"}

    def __init__(self, config_path: str | Path = "config/config.yaml"):
        self.config_path = Path(config_path)
        self._raw_data = self._load_yaml()
        self.validate_schema()

    def _load_yaml(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            raise ConfigurationError(f"Configuration file not found: {self.config_path}")
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            raise ConfigurationError(f"Failed to parse YAML configuration: {e}") from e

    def validate_schema(self) -> None:
        """Validates nested dictionary structure and type constraints."""
        for path_keys, expected_type in self.REQUIRED_SCHEMA.items():
            curr = self._raw_data
            for key in path_keys:
                if not isinstance(curr, dict) or key not in curr:
                    raise ConfigurationError(
                        f"Missing required configuration key: {' -> '.join(path_keys)}"
                    )
                curr = curr[key]

            if not isinstance(curr, expected_type) or (isinstance(curr, str) and not curr.strip()):
                raise ConfigurationError(
                    f"Invalid datatype or empty value for key: {' -> '.join(path_keys)}"
                )

        prod_store = self.servers["production"]["identity_store"].lower()
        dr_store = self.servers["disaster_recovery"]["identity_store"].lower()
        if prod_store not in self.ALLOWED_IDENTITY_STORES:
            raise ConfigurationError(f"Unsupported production identity store: {prod_store}")
        if dr_store not in self.ALLOWED_IDENTITY_STORES:
            raise ConfigurationError(f"Unsupported DR identity store: {dr_store}")

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