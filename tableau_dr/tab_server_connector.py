"""Safe subprocess execution interface for Tableau Services Manager (TSM) CLI."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Sequence

from tableau_dr.exceptions import ConfigurationError, TSMError


logger = logging.getLogger(__name__)

DEFAULT_WINDOWS_EXECUTABLE = "tsm.cmd"
DEFAULT_UNIX_EXECUTABLE = "tsm"

DEFAULT_TIMEOUT_SECONDS = 3600
BACKUP_TIMEOUT_SECONDS = 7200
SETTINGS_TIMEOUT_SECONDS = 1800

SENSITIVE_FLAGS = {
    "--password",
    "--passphrase",
    "--client-secret",
    "--token",
    "--access-token",
    "--sas-token",
    "--key-file",
    "-p",
}


@dataclass(frozen=True)
class TSMResult:
    """Result returned by a TSM CLI invocation."""

    command: List[str]
    return_code: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        """Return True when TSM completed successfully."""

        return self.return_code == 0


class TSMConnector:
    """Execute TSM commands safely without shell interpretation."""

    def __init__(
        self,
        executable: str | None = None,
        yaml_executable: str | None = None,
    ) -> None:
        """
        Resolve the TSM executable.

        Resolution order:
        1. Explicit constructor argument.
        2. YAML configuration.
        3. TSM_EXECUTABLE environment variable.
        4. TSM executable discovered through PATH.
        """

        self.executable = self._resolve_executable(
            explicit=executable,
            yaml_path=yaml_executable,
        )

    @staticmethod
    def _validate_timeout(timeout: int) -> None:
        """Validate subprocess timeout."""

        if isinstance(timeout, bool) or not isinstance(timeout, int):
            raise ValueError("timeout must be an integer.")

        if timeout <= 0:
            raise ValueError("timeout must be greater than zero.")

    @staticmethod
    def _validate_args(args: Sequence[str]) -> List[str]:
        """Validate and normalize a TSM argument vector."""

        if isinstance(args, (str, bytes)):
            raise TypeError(
                "TSM arguments must be provided as a sequence of strings, "
                "not as a single command string."
            )

        normalized: List[str] = []

        for argument in args:
            if not isinstance(argument, str):
                raise TypeError("Every TSM argument must be a string.")

            if not argument:
                raise ValueError("TSM arguments cannot contain empty strings.")

            normalized.append(argument)

        return normalized

    def _resolve_executable(
        self,
        explicit: str | None,
        yaml_path: str | None,
    ) -> str:
        """Resolve and validate the configured TSM executable."""

        candidates = (
            (explicit, "constructor"),
            (yaml_path, "YAML configuration"),
            (os.environ.get("TSM_EXECUTABLE"), "TSM_EXECUTABLE environment variable"),
        )

        for candidate, source in candidates:
            if candidate is None:
                continue

            if not isinstance(candidate, str) or not candidate.strip():
                raise ConfigurationError(
                    f"TSM executable configured via {source} must be a non-empty string."
                )

            clean_path = candidate.strip()

            if os.path.isabs(clean_path):
                executable_path = os.path.abspath(clean_path)

                if not os.path.isfile(executable_path):
                    raise ConfigurationError(
                        f"TSM executable configured via {source} was not found: "
                        f"{executable_path}"
                    )

                if not os.access(executable_path, os.X_OK):
                    raise ConfigurationError(
                        f"TSM executable configured via {source} is not executable: "
                        f"{executable_path}"
                    )

                return executable_path

            resolved = shutil.which(clean_path)

            if not resolved:
                raise ConfigurationError(
                    f"TSM executable configured via {source} was not found in PATH: "
                    f"{clean_path}"
                )

            return resolved

        default_executable = (
            DEFAULT_WINDOWS_EXECUTABLE
            if os.name == "nt"
            else DEFAULT_UNIX_EXECUTABLE
        )

        resolved = shutil.which(default_executable)

        if resolved:
            return resolved

        logger.warning(
            "Default TSM executable '%s' was not found in PATH. "
            "Execution will fail until TSM is installed or configured.",
            default_executable,
        )

        return default_executable

    def run(
        self,
        args: Sequence[str],
        *,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        check: bool = True,
    ) -> TSMResult:
        """
        Execute a TSM command securely.

        Security controls:
        - Argument-vector execution.
        - shell=False.
        - stdin detached.
        - Timeout enforcement.
        - Sensitive argument redaction.
        - Sensitive stdout/stderr redaction.
        """

        arguments = self._validate_args(args)
        self._validate_timeout(timeout)

        raw_command = [self.executable, *arguments]
        safe_command = self._sanitize_command_list(raw_command)
        safe_command_text = self._format_command(safe_command)

        logger.info("Executing TSM command: %s", safe_command_text)

        try:
            result = subprocess.run(
                raw_command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                stdin=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )

        except subprocess.TimeoutExpired as exc:
            message = (
                f"TSM command timed out after {timeout} seconds: "
                f"{safe_command_text}"
            )

            logger.error(message)
            raise TSMError(message) from exc

        except FileNotFoundError as exc:
            message = (
                f"TSM executable was not found while executing: "
                f"{safe_command_text}"
            )

            logger.error(message)
            raise TSMError(message) from exc

        except PermissionError as exc:
            message = (
                f"Permission denied while executing TSM command: "
                f"{safe_command_text}"
            )

            logger.error(message)
            raise TSMError(message) from exc

        except OSError as exc:
            message = (
                f"Operating system error while executing TSM command "
                f"'{safe_command_text}': {self._sanitize_text(str(exc))}"
            )

            logger.error(message)
            raise TSMError(message) from exc

        stdout = self._sanitize_text(result.stdout.strip())
        stderr = self._sanitize_text(result.stderr.strip())

        response = TSMResult(
            command=safe_command,
            return_code=result.returncode,
            stdout=stdout,
            stderr=stderr,
        )

        if not response.success:
            logger.error(
                "TSM command failed. return_code=%s command=%s stderr=%s",
                response.return_code,
                safe_command_text,
                response.stderr or "[empty]",
            )

            if check:
                raise TSMError(
                    "TSM command execution failed. "
                    f"Command: {safe_command_text} | "
                    f"Return Code: {response.return_code} | "
                    f"STDERR: {response.stderr or '[empty]'}"
                )

        else:
            logger.info(
                "TSM command completed successfully. command=%s",
                safe_command_text,
            )

        return response

    @classmethod
    def _sanitize_command_list(
        cls,
        command: Sequence[str],
    ) -> List[str]:
        """Redact values belonging to sensitive CLI flags."""

        safe: List[str] = []
        hide_next = False

        for item in command:
            if hide_next:
                safe.append("[REDACTED]")
                hide_next = False
                continue

            if item in SENSITIVE_FLAGS:
                safe.append(item)
                hide_next = True
                continue

            safe.append(cls._sanitize_text(item))

        return safe

    @staticmethod
    def _sanitize_text(text: str) -> str:
        """Redact common credential and token patterns from command output."""

        if not text:
            return ""

        patterns = (
            r"(?i)(password|passwd|passphrase|secret|token|access[-_ ]?token|"
            r"client[-_ ]?secret|sas[-_ ]?token)\s*[:=]\s*[^\s,;]+",
            r"(?i)(password|passwd|passphrase|secret|token|access[-_ ]?token|"
            r"client[-_ ]?secret|sas[-_ ]?token)\s+['\"]?[^\s,'\"]+['\"]?",
        )

        sanitized = text

        for pattern in patterns:
            sanitized = re.sub(
                pattern,
                lambda match: f"{match.group(1)}=[REDACTED]",
                sanitized,
            )

        return sanitized

    @staticmethod
    def _format_command(command: Sequence[str]) -> str:
        """Create a safe human-readable representation of a command."""

        return " ".join(
            f'"{argument}"' if any(char.isspace() for char in argument) else argument
            for argument in command
        )

    def status(self) -> TSMResult:
        """Return Tableau Server status without failing on non-zero status."""

        return self.run(
            ["status", "-v"],
            timeout=DEFAULT_TIMEOUT_SECONDS,
            check=False,
        )

    def create_backup(
        self,
        backup_file_path: str,
        append_date: bool = False,
    ) -> TSMResult:
        """Create a Tableau Server backup using TSM."""

        if not isinstance(backup_file_path, str) or not backup_file_path.strip():
            raise ValueError("backup_file_path must be a non-empty string.")

        args = [
            "maintenance",
            "backup",
            "--file",
            backup_file_path,
        ]

        if append_date:
            args.append("-d")

        return self.run(
            args,
            timeout=BACKUP_TIMEOUT_SECONDS,
            check=True,
        )

    def export_settings(self, output_file: str) -> TSMResult:
        """Export Tableau Server configuration settings."""

        if not isinstance(output_file, str) or not output_file.strip():
            raise ValueError("output_file must be a non-empty string.")

        return self.run(
            [
                "settings",
                "export",
                "--output-config",
                output_file,
            ],
            timeout=SETTINGS_TIMEOUT_SECONDS,
            check=True,
        )