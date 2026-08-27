"""Safe subprocess-based TSM CLI interface with flexible path resolution."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence

from tableau_dr.exceptions import ConfigurationError, TSMError

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

    @property
    def safe_command_str(self) -> str:
        return " ".join(self.command)


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

    def __init__(self, executable: str | None = None, yaml_executable: str | None = None):
        self.executable = self._resolve_executable(executable, yaml_executable)

    def _resolve_executable(self, explicit: str | None, yaml_path: str | None) -> str:
        """
        Precedence:
        1. Constructor argument
        2. YAML configuration (tsm -> executable)
        3. TSM_EXECUTABLE environment variable
        4. OS default fallback ('tsm.cmd' or 'tsm')
        """
        candidates = [
            (explicit, "Explicit Constructor Argument"),
            (yaml_path, "YAML Configuration"),
            (os.environ.get("TSM_EXECUTABLE"), "TSM_EXECUTABLE Environment Variable"),
        ]

        for candidate, source in candidates:
            if candidate and candidate.strip():
                clean_path = candidate.strip()
                # Verify existence if an explicit absolute path is supplied
                if os.path.isabs(clean_path):
                    if not os.path.isfile(clean_path):
                        raise ConfigurationError(
                            f"Configured TSM executable from {source} does not exist: {clean_path}"
                        )
                    if not os.access(clean_path, os.X_OK):
                        raise ConfigurationError(
                            f"Configured TSM executable from {source} is not executable: {clean_path}"
                        )
                return clean_path

        default_exe = "tsm.cmd" if os.name == "nt" else "tsm"
        resolved = shutil.which(default_exe)
        if not resolved:
            logger.warning(f"Default '{default_exe}' not found in system PATH.")
            return default_exe
        return resolved

    def run(
        self,
        args: Sequence[str],
        *,
        timeout: int = 3600,
        check: bool = True,
    ) -> TSMResult:
        """Executes a TSM command safely using argument sequences (shell=False)."""
        raw_command = [self.executable, *args]
        safe_command_list = self._sanitize_command_list(raw_command)
        safe_cmd_str = " ".join(safe_command_list)

        try:
            result = subprocess.run(
                raw_command,
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                check=False,
            )
        except Exception as e:
            sanitized_err = self._sanitize_text(str(e))
            raise TSMError(f"Failed to execute process '{safe_cmd_str}': {sanitized_err}") from e

        response = TSMResult(
            command=safe_command_list,
            return_code=result.returncode,
            stdout=self._sanitize_text(result.stdout.strip()),
            stderr=self._sanitize_text(result.stderr.strip()),
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
    def _sanitize_command_list(cls, command: list[str]) -> list[str]:
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
        return safe

    @staticmethod
    def _sanitize_text(text: str) -> str:
        if not text:
            return ""
        return re.sub(r'(?i)(password|passphrase|secret|token)\s*[:=]\s*\S+', r'\1=***REDACTED***', text)

    def status(self) -> TSMResult:
        return self.run(["status", "-v"], check=False)

    def version(self) -> TSMResult:
        return self.run(["version"])

    def create_backup(self, backup_file: str, append_date: bool = False) -> TSMResult:
        """Generates repository backup. Passes absolute path directly to TSM CLI."""
        args = ["maintenance", "backup", "--file", backup_file]
        if append_date:
            args.append("-d")
        return self.run(args, timeout=7200)

    def export_settings(self, output_file: str) -> TSMResult:
        return self.run(["settings", "export", "--output-config", output_file], timeout=1800)