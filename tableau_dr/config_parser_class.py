import yaml
import os

class ConfigParser:
    def __init__(self, config_path):
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f).get("tableau_dr", {})

    def get_azure_config(self):
        return self.config.get("azure", {})

    def get_server_config(self, node_type="primary"):
        return self.config.get("servers", {}).get(node_type, {})

    def get_security_config(self):
        return self.config.get("security", {})