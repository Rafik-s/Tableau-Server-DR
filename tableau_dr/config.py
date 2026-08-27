"""Enterprise Configuration parser with extended operational schema validation."""

from __future__ import annotations

import os
from pathlib import Path
import yaml
from tableau_dr.exceptions import ConfigurationError

class Config:
    """Parses, validates schema types, and exposes project parameters."""

    REQUIRED_SCHEMA = {
        ("environment", "version"): str,
        ("azure", "key_vault_name"): str,
        ("azure", "storage_account_name"): str,
        ("azure", "storage_container"): str,
        ("servers", "production", "hostname"): str,
        ("servers", "production", "identity_store"): str,
        ("servers", "disaster_recovery", "hostname"): str,
        ("servers", "disaster_recovery", "identity_store"): str,
        ("paths", "backup_dir"): str,
        ("backup", "minimum_free_space_gb"): (int, float),
        ("backup", "minimum_backup_size_mb"): (int, float),
    }

    ALLOWED_IDENTITY_STORES = {"activedirectory", "local", "ldap"}

    def __init__(self, config_path: str | Path = "config/config.yaml"):
        self.config_path = Path(config_path)
        self._raw_data = self._load_yaml()
        self.validate_schema()

    def _load_yaml(self) -> dict:
        if not self.config_path.exists():
            raise ConfigurationError(f"Configuration file not found: {self.config_path}")
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            raise ConfigurationError(f"Failed to parse YAML configuration: {e}") from e

    def validate_schema(self) -> None:
        """Validates key presence, data types, and value constraints."""
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
                    f"Invalid datatype or empty value for key: {' -> '.join(path_keys)}."
                )

        prod_store = self.servers["production"]["identity_store"].lower()
        dr_store = self.servers["disaster_recovery"]["identity_store"].lower()
        if prod_store not in self.ALLOWED_IDENTITY_STORES:
            raise ConfigurationError(f"Unsupported production identity store: {prod_store}")
        if dr_store not in self.ALLOWED_IDENTITY_STORES:
            raise ConfigurationError(f"Unsupported DR identity store: {dr_store}")

    @property
    def environment(self) -> dict:
        return self._raw_data.get("environment", {})

    @property
    def azure(self) -> dict:
        return self._raw_data.get("azure", {})

    @property
    def servers(self) -> dict:
        return self._raw_data.get("servers", {})

    @property
    def paths(self) -> dict:
        return self._raw_data.get("paths", {})

    @property
    def backup(self) -> dict:
        return self._raw_data.get("backup", {})

    @property
    def tsm(self) -> dict:
        return self._raw_data.get("tsm", {})

    @property
    def security(self) -> dict:
        return self._raw_data.get("security", {})