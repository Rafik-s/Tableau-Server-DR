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

MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 24 * 60 * 60

SENSITIVE_FLAGS = {
    "--password",
    "--passphrase",
    "--client-secret",
    "--token",
    "--access-token",
    "--sas-token",
    "--key-file",
    "--cert-file",
    "-p",
}

# Prevent accidental control-character injection into executable paths
# and arguments while still allowing normal Windows/Linux paths.
CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Common secret-bearing output patterns.
SECRET_PATTERN = re.compile(
    r"(?i)\b("
    r"password|passwd|passphrase|secret|token|access[-_ ]?token|"
    r"client[-_ ]?secret|sas[-_ ]?token|private[-_ ]?key"
    r")\b\s*[:=]\s*"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)

SECRET_SPACE_PATTERN = re.compile(
    r"(?i)\b("
    r"password|passwd|passphrase|secret|token|access[-_ ]?token|"
    r"client[-_ ]?secret|sas[-_ ]?token|private[-_ ]?key"
    r")\b\s+"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)


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
        config=None,
        executable: str | None = None,
        yaml_executable: str | None = None,
        logger_instance: logging.Logger | None = None,
    ) -> None:
        """
        Initialize the TSM connector.

        Resolution order:

        1. Explicit constructor argument.
        2. YAML configuration argument.
        3. ``config.tsm["executable"]`` when supplied.
        4. ``TSM_EXECUTABLE`` environment variable.
        5. TSM executable discovered through PATH.
        """
        self.logger = logger_instance or logger

        configured_executable = yaml_executable

        if configured_executable is None and config is not None:
            try:
                configured_executable = config.tsm.get("executable")
            except AttributeError:
                raise ConfigurationError(
                    "TSM configuration is invalid."
                ) from None

        self.executable = self._resolve_executable(
            explicit=executable,
            yaml_path=configured_executable,
        )

    @staticmethod
    def _validate_timeout(timeout: int) -> None:
        """Validate subprocess timeout."""
        if isinstance(timeout, bool) or not isinstance(timeout, int):
            raise ValueError("timeout must be an integer.")

        if not MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError(
                f"timeout must be between {MIN_TIMEOUT_SECONDS} and "
                f"{MAX_TIMEOUT_SECONDS} seconds."
            )

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

            if CONTROL_CHARACTER_PATTERN.search(argument):
                raise ValueError(
                    "TSM arguments cannot contain control characters."
                )

            normalized.append(argument)

        return normalized

    @staticmethod
    def _validate_executable_value(value: str, source: str) -> str:
        """Validate a configured executable value."""
        if not isinstance(value, str) or not value.strip():
            raise ConfigurationError(
                f"TSM executable configured via {source} "
                "must be a non-empty string."
            )

        clean_path = value.strip()

        if CONTROL_CHARACTER_PATTERN.search(clean_path):
            raise ConfigurationError(
                f"TSM executable configured via {source} "
                "contains invalid control characters."
            )

        return clean_path

    def _resolve_executable(
        self,
        explicit: str | None,
        yaml_path: str | None,
    ) -> str:
        """Resolve and validate the configured TSM executable."""
        candidates = (
            (explicit, "constructor"),
            (yaml_path, "YAML configuration"),
            (
                os.environ.get("TSM_EXECUTABLE"),
                "TSM_EXECUTABLE environment variable",
            ),
        )

        for candidate, source in candidates:
            if candidate is None:
                continue

            clean_path = self._validate_executable_value(
                candidate,
                source,
            )

            if os.path.isabs(clean_path):
                executable_path = os.path.abspath(clean_path)

                if not os.path.isfile(executable_path):
                    raise ConfigurationError(
                        f"TSM executable configured via {source} "
                        f"was not found: {executable_path}"
                    )

                # Windows .cmd files are executable through the Windows
                # command interpreter and do not normally have POSIX
                # executable permissions.
                if os.name != "nt" and not os.access(
                    executable_path,
                    os.X_OK,
                ):
                    raise ConfigurationError(
                        f"TSM executable configured via {source} "
                        f"is not executable: {executable_path}"
                    )

                return executable_path

            resolved = shutil.which(clean_path)

            if not resolved:
                raise ConfigurationError(
                    f"TSM executable configured via {source} "
                    f"was not found in PATH: {clean_path}"
                )

            return os.path.abspath(resolved)

        default_executable = (
            DEFAULT_WINDOWS_EXECUTABLE
            if os.name == "nt"
            else DEFAULT_UNIX_EXECUTABLE
        )

        resolved = shutil.which(default_executable)

        if resolved:
            return os.path.abspath(resolved)

        self.logger.warning(
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
        - ``shell=False``.
        - stdin detached.
        - Timeout enforcement.
        - Sensitive argument redaction.
        - Sensitive stdout/stderr redaction.
        - Control-character rejection.
        """
        arguments = self._validate_args(args)
        self._validate_timeout(timeout)

        raw_command = [self.executable, *arguments]
        safe_command = self._sanitize_command_list(raw_command)
        safe_command_text = self._format_command(safe_command)

        self.logger.info(
            "Executing TSM command: %s",
            safe_command_text,
        )

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
            self.logger.error(message)
            raise TSMError(message) from exc

        except FileNotFoundError as exc:
            message = (
                "TSM executable was not found while executing: "
                f"{safe_command_text}"
            )
            self.logger.error(message)
            raise TSMError(message) from exc

        except PermissionError as exc:
            message = (
                "Permission denied while executing TSM command: "
                f"{safe_command_text}"
            )
            self.logger.error(message)
            raise TSMError(message) from exc

        except OSError as exc:
            message = (
                "Operating system error while executing TSM command "
                f"'{safe_command_text}': "
                f"{self._sanitize_text(str(exc))}"
            )
            self.logger.error(message)
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
            self.logger.error(
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
            self.logger.info(
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

            # Also redact --flag=value forms.
            lowered = item.lower()

            for flag in SENSITIVE_FLAGS:
                if lowered.startswith(f"{flag}="):
                    safe.append(f"{flag}=[REDACTED]")
                    break
            else:
                safe.append(cls._sanitize_text(item))

        return safe

    @staticmethod
    def _sanitize_text(text: str) -> str:
        """Redact common credential and token patterns from command output."""
        if not text:
            return ""

        sanitized = SECRET_PATTERN.sub(
            lambda match: f"{match.group(1)}=[REDACTED]",
            text,
        )

        sanitized = SECRET_SPACE_PATTERN.sub(
            lambda match: f"{match.group(1)} [REDACTED]",
            sanitized,
        )

        return sanitized

    @staticmethod
    def _format_command(command: Sequence[str]) -> str:
        """Create a safe human-readable representation of a command."""
        formatted: List[str] = []

        for argument in command:
            if any(char.isspace() for char in argument):
                escaped = argument.replace('"', '\\"')
                formatted.append(f'"{escaped}"')
            else:
                formatted.append(argument)

        return " ".join(formatted)

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
        self._validate_file_path_argument(
            backup_file_path,
            "backup_file_path",
        )

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
        self._validate_file_path_argument(
            output_file,
            "output_file",
        )

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

    def restore_backup(self, backup_file: str) -> TSMResult:
        """Restore the Tableau Server repository from a TSBak file."""
        self._validate_file_path_argument(
            backup_file,
            "backup_file",
        )

        return self.run(
            [
                "maintenance",
                "restore",
                "--file",
                backup_file,
            ],
            timeout=BACKUP_TIMEOUT_SECONDS,
            check=True,
        )

    def import_settings(self, input_file: str) -> TSMResult:
        """Import Tableau Server configuration settings."""
        self._validate_file_path_argument(
            input_file,
            "input_file",
        )

        return self.run(
            [
                "settings",
                "import",
                "--input-config",
                input_file,
            ],
            timeout=SETTINGS_TIMEOUT_SECONDS,
            check=True,
        )

    def configure_external_ssl(
        self,
        cert_file: str,
        key_file: str,
        chain_file: str | None = None,
        protocols: str | None = None,
    ) -> TSMResult:
        """
        Configure Tableau Server external SSL.

        File paths are passed as separate subprocess arguments and are
        never interpreted by a shell.
        """
        self._validate_file_path_argument(cert_file, "cert_file")
        self._validate_file_path_argument(key_file, "key_file")

        args = [
            "security",
            "external-ssl",
            "enable",
            "--cert-file",
            cert_file,
            "--key-file",
            key_file,
        ]

        if chain_file is not None:
            self._validate_file_path_argument(
                chain_file,
                "chain_file",
            )
            args.extend(
                [
                    "--chain-file",
                    chain_file,
                ]
            )

        if protocols is not None:
            if not isinstance(protocols, str) or not protocols.strip():
                raise ValueError(
                    "protocols must be a non-empty string when provided."
                )

            if CONTROL_CHARACTER_PATTERN.search(protocols):
                raise ValueError(
                    "protocols cannot contain control characters."
                )

            args.extend(
                [
                    "--protocols",
                    protocols.strip(),
                ]
            )

        return self.run(
            args,
            timeout=SETTINGS_TIMEOUT_SECONDS,
            check=True,
        )

    def configure_saml(
        self,
        identity_provider_entity_id: str,
        certificate_file: str,
    ) -> TSMResult:
        """
        Configure Tableau Server SAML settings.

        This method intentionally accepts only explicit argument values.
        It does not accept secrets directly.
        """
        if (
            not isinstance(identity_provider_entity_id, str)
            or not identity_provider_entity_id.strip()
        ):
            raise ValueError(
                "identity_provider_entity_id must be a non-empty string."
            )

        self._validate_file_path_argument(
            certificate_file,
            "certificate_file",
        )

        return self.run(
            [
                "authentication",
                "saml",
                "configure",
                "--idp-entity-id",
                identity_provider_entity_id.strip(),
                "--idp-certificate",
                certificate_file,
            ],
            timeout=SETTINGS_TIMEOUT_SECONDS,
            check=True,
        )

    def apply_pending_changes(self) -> TSMResult:
        """Apply pending Tableau Server configuration changes."""
        return self.run(
            ["pending-changes", "apply"],
            timeout=SETTINGS_TIMEOUT_SECONDS,
            check=True,
        )

    @staticmethod
    def _validate_file_path_argument(
        path_value: str,
        argument_name: str,
    ) -> None:
        """Validate a path argument before passing it to TSM."""
        if not isinstance(path_value, str) or not path_value.strip():
            raise ValueError(
                f"{argument_name} must be a non-empty string."
            )

        if CONTROL_CHARACTER_PATTERN.search(path_value):
            raise ValueError(
                f"{argument_name} contains invalid control characters."
            )