"""Safe subprocess-based TSM CLI interface."""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Sequence

from tableau_dr.exceptions import TSMError

logger = logging.getLogger(__name__)

@dataclass
class TSMResult:
    command: list[str]
    return_code: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        return self.return_code == 0


class TSMConnector:
    """Encapsulates execution of Tableau Services Manager (TSM) commands."""

    SENSITIVE_FLAGS = {
        "--password",
        "--passphrase",
        "--client-secret",
        "--token",
        "--key-file",
        "-p",
    }

    def __init__(self, executable: str | None = None):
        if executable:
            self.executable = executable
        elif "TSM_EXECUTABLE" in os.environ:
            self.executable = os.environ["TSM_EXECUTABLE"]
        else:
            self.executable = "tsm.cmd" if os.name == "nt" else "tsm"

    def run(
        self,
        args: Sequence[str],
        *,
        timeout: int = 3600,
        check: bool = True,
    ) -> TSMResult:
        """Executes a TSM command safely using argument sequences (shell=False)."""
        command = [self.executable, *args]
        safe_cmd_str = self._safe_command(command)
        
        logger.debug(f"Executing TSM Command: {safe_cmd_str}")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                check=False,
            )
        except Exception as e:
            sanitized_err = self._sanitize_text(str(e))
            raise TSMError(f"Failed to execute process '{safe_cmd_str}': {sanitized_err}") from e

        sanitized_stdout = self._sanitize_text(result.stdout.strip())
        sanitized_stderr = self._sanitize_text(result.stderr.strip())

        response = TSMResult(
            command=command,
            return_code=result.returncode,
            stdout=sanitized_stdout,
            stderr=sanitized_stderr,
        )

        if check and not response.success:
            logger.error(f"TSM Command Failed [{safe_cmd_str}] - STDERR: {response.stderr}")
            raise TSMError(
                f"TSM command execution failed.\n"
                f"Command: {safe_cmd_str}\n"
                f"Return code: {response.return_code}\n"
                f"Error: {response.stderr}"
            )

        return response

    @classmethod
    def _safe_command(cls, command: list[str]) -> str:
        """Redacts sensitive credentials from command logging strings."""
        safe = []
        hide_next = False

        for item in command:
            if hide_next:
                safe.append("***REDACTED***")
                hide_next = False
                continue

            if item in cls.SENSITIVE_FLAGS:
                safe.append(item)
                hide_next = True
            else:
                safe.append(item)

        return " ".join(safe)

    @staticmethod
    def _sanitize_text(text: str) -> str:
        """Sanitizes sensitive patterns inside stdout/stderr outputs before logging."""
        if not text:
            return ""
        # Scrub inline password or token patterns if present in output
        sanitized = re.sub(r'(?i)(password|passphrase|secret|token)\s*[:=]\s*\S+', r'\1=***REDACTED***', text)
        return sanitized

    def status(self) -> TSMResult:
        """Retrieves Tableau cluster detailed status."""
        return self.run(["status", "-v"], check=False)

    def version(self) -> TSMResult:
        """Retrieves TSM software version details."""
        return self.run(["version"])

    def stop(self) -> TSMResult:
        """Stops Tableau Server cluster services."""
        logger.info("Stopping Tableau Server cluster via TSM...")
        return self.run(["stop"])

    def start(self) -> TSMResult:
        """Starts Tableau Server cluster services."""
        logger.info("Starting Tableau Server cluster via TSM...")
        return self.run(["start"])

    def cleanup(self) -> TSMResult:
        """Executes app-data maintenance cleanup."""
        logger.info("Executing TSM app-data maintenance cleanup...")
        return self.run(["maintenance", "cleanup", "--app-data-only"])

    def apply_pending_changes(self) -> TSMResult:
        """Applies pending topology and configuration changes."""
        logger.info("Applying pending TSM configuration changes...")
        return self.run(["pending-changes", "apply", "--ignore-prompt"], timeout=1800)

    def create_backup(self, backup_file: str, append_date: bool = True) -> TSMResult:
        """Generates repository and File Store backup (.tsbak)."""
        logger.info(f"Creating Tableau repository backup: {backup_file}...")
        args = ["maintenance", "backup", "--file", backup_file]
        if append_date:
            args.append("-d")
        return self.run(args, timeout=7200)

    def export_settings(self, output_file: str) -> TSMResult:
        """Exports server topology and configuration settings."""
        logger.info(f"Exporting TSM settings configuration to {output_file}...")
        return self.run(
            ["settings", "export", "--output-config", output_file],
            timeout=1800,
        )

    def restore_backup(self, backup_file: str) -> TSMResult:
        """Restores repository and File Store data from backup (.tsbak)."""
        logger.info(f"Restoring Tableau repository backup from file: {backup_file}...")
        return self.run(
            ["maintenance", "restore", "--file", backup_file],
            timeout=7200,
        )

    def import_settings(self, input_file: str) -> TSMResult:
        """Imports topology and configuration settings."""
        logger.info(f"Importing TSM settings configuration from {input_file}...")
        return self.run(
            ["settings", "import", "--input-config", input_file],
            timeout=1800,
        )

    def configure_external_ssl(
        self,
        cert_file: str,
        key_file: str,
        chain_file: str | None = None,
        protocols: str | None = None,
    ) -> TSMResult:
        """Configures external SSL settings."""
        logger.info("Applying external SSL configuration...")
        cmd = [
            "security", "external-ssl", "enable",
            "--cert-file", cert_file,
            "--key-file", key_file,
        ]
        if protocols:
            cmd.extend(["--protocols", protocols])
        if chain_file:
            cmd.extend(["--chain-file", chain_file])
        return self.run(cmd)

    def configure_saml(
        self,
        entity_id: str,
        return_url: str,
        metadata_file: str,
        cert_file: str,
        key_file: str,
    ) -> TSMResult:
        """Configures SAML authentication settings."""
        logger.info("Applying SAML authentication configuration...")
        return self.run([
            "authentication", "saml", "enable",
            "--saml-entity-id", entity_id,
            "--saml-return-url", return_url,
            "--saml-metadata", metadata_file,
            "--saml-cert-file", cert_file,
            "--saml-key-file", key_file,
        ])