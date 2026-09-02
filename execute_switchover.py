"""CLI entry point for executing Tableau Server DR failover."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import uuid
from pathlib import Path
from typing import Optional

from tableau_dr.config import Config
from tableau_dr.exceptions import TableauDRError
from tableau_dr.logger import get_logger
from tableau_dr.recovery_manager import RecoveryManager


DEFAULT_CONFIG_PATH = "config/config.yaml"
CONFIRMATION_TEXT = "CONFIRM-FAILOVER"
EMERGENCY_AUTH_ENV = "TABLEAU_DR_EMERGENCY_AUTH_CODE"

MAX_CONFIG_PATH_LENGTH = 4096
MAX_MANIFEST_BLOB_LENGTH = 1024
MAX_OPERATOR_REASON_LENGTH = 1000
CONTROL_CHARACTER_TRANSLATION = str.maketrans(
    "",
    "",
    "".join(
        chr(code)
        for code in list(range(0, 9))
        + list(range(11, 13))
        + list(range(14, 32))
        + [127]
    ),
)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Execute the Tableau Server Disaster Recovery failover."
    )

    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=(
            "Path to YAML configuration file "
            f"(default: {DEFAULT_CONFIG_PATH})"
        ),
    )

    parser.add_argument(
        "--manifest-blob",
        help=(
            "Explicit Azure Blob path to the target recovery manifest. "
            "If omitted, the recovery manager resolves the latest valid manifest."
        ),
    )

    parser.add_argument(
        "--operator-reason",
        help=(
            "Audited justification for the emergency fencing override. "
            "Required when an emergency authorization code is supplied."
        ),
    )

    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help=(
            "Run without interactive confirmation or secret prompts. "
            f"The emergency authorization code must then be supplied "
            f"through {EMERGENCY_AUTH_ENV} if required."
        ),
    )

    return parser.parse_args()


def _contains_control_characters(value: str) -> bool:
    """Return True when a string contains unsafe control characters."""
    return value.translate(CONTROL_CHARACTER_TRANSLATION) != value


def _validate_config_path(config_path: str) -> Path:
    """Validate and normalize the configuration file path."""
    if not isinstance(config_path, str):
        raise ValueError("Configuration path must be a string.")

    normalized = config_path.strip()

    if not normalized:
        raise ValueError("Configuration path cannot be empty.")

    if len(normalized) > MAX_CONFIG_PATH_LENGTH:
        raise ValueError("Configuration path exceeds the maximum length.")

    if _contains_control_characters(normalized):
        raise ValueError(
            "Configuration path contains unsupported control characters."
        )

    return Path(normalized).expanduser()


def _validate_manifest_blob(
    manifest_blob: Optional[str],
) -> Optional[str]:
    """Validate an explicitly supplied manifest blob reference."""
    if manifest_blob is None:
        return None

    normalized = manifest_blob.strip()

    if not normalized:
        raise ValueError("Manifest blob path cannot be empty.")

    if len(normalized) > MAX_MANIFEST_BLOB_LENGTH:
        raise ValueError(
            "Manifest blob path exceeds the maximum allowed length."
        )

    if _contains_control_characters(normalized):
        raise ValueError(
            "Manifest blob path contains unsupported control characters."
        )

    return normalized


def _validate_operator_reason(
    operator_reason: Optional[str],
) -> Optional[str]:
    """Validate and normalize the operator justification."""
    if operator_reason is None:
        return None

    normalized = operator_reason.strip()

    if not normalized:
        raise ValueError("Operator reason cannot be empty.")

    if len(normalized) > MAX_OPERATOR_REASON_LENGTH:
        raise ValueError(
            "Operator reason exceeds the maximum allowed length."
        )

    if _contains_control_characters(normalized):
        raise ValueError(
            "Operator reason contains unsupported control characters."
        )

    return normalized


def _get_emergency_auth_code(
    *,
    non_interactive: bool,
) -> Optional[str]:
    """
    Obtain the emergency authorization code without exposing it through
    command-line arguments.
    """
    environment_code = os.environ.get(EMERGENCY_AUTH_ENV)

    if environment_code:
        return environment_code

    if non_interactive:
        return None

    try:
        code = getpass.getpass(
            "Emergency fencing authorization code "
            "(press Enter if not required): "
        )
    except (EOFError, KeyboardInterrupt):
        print()
        raise

    return code.strip() or None


def _confirm_interactive_failover() -> bool:
    """Require explicit operator confirmation before destructive recovery."""
    print()
    print("[WARNING] DISASTER RECOVERY FAILOVER")
    print("[WARNING] This operation may overwrite data on the DR server.")
    print(
        "[WARNING] Production must be safely fenced before recovery continues."
    )
    print()

    confirmation = input(
        f"Type '{CONFIRMATION_TEXT}' to proceed: "
    ).strip()

    return confirmation == CONFIRMATION_TEXT


def main() -> int:
    """Execute the Tableau DR failover workflow."""
    args = parse_args()

    run_id = uuid.uuid4().hex.upper()

    logger = get_logger(
        "TableauDR-Switchover",
        run_id=run_id,
        operation="FAILOVER",
    )

    logger.warning(
        "======================================================================="
    )
    logger.warning(
        "              DISASTER RECOVERY FAILOVER INITIATED"
    )
    logger.warning(
        "======================================================================="
    )

    try:
        config_path = _validate_config_path(args.config)
        manifest_blob = _validate_manifest_blob(args.manifest_blob)
        operator_reason = _validate_operator_reason(args.operator_reason)

        if not args.non_interactive:
            if not _confirm_interactive_failover():
                logger.info("Failover operation cancelled by operator.")
                return 0

        emergency_auth_code = _get_emergency_auth_code(
            non_interactive=args.non_interactive,
        )

        logger.warning("Loading and validating DR configuration.")

        config = Config(config_path=config_path)

        manager = RecoveryManager(
            config=config,
            run_id=run_id,
        )

        logger.warning("Starting failover state machine.")

        result = manager.execute_failover(
            emergency_auth_code=emergency_auth_code,
            operator_reason=operator_reason,
            target_manifest_blob=manifest_blob,
        )

        logger.info(
            "Recovery completed. status=%s",
            result.status,
        )

        if result.measured_backup_age_rpo_seconds is not None:
            logger.info(
                "Measured backup-age RPO: %.2f seconds",
                result.measured_backup_age_rpo_seconds,
            )

        if result.total_rto_seconds is not None:
            logger.info(
                "Total recovery RTO: %.2f seconds",
                result.total_rto_seconds,
            )

        if result.status == "SUCCESS":
            logger.info(
                "Tableau DR failover completed successfully."
            )
            return 0

        failed_step = (
            result.failed_step.value
            if result.failed_step is not None
            else "UNKNOWN"
        )

        logger.error(
            "Tableau DR failover failed. state=%s failed_step=%s",
            result.current_state.value,
            failed_step,
        )

        logger.error(
            "Recovery workspace has been preserved for investigation."
        )

        return 1

    except KeyboardInterrupt:
        logger.critical(
            "Failover execution interrupted by operator."
        )
        return 130

    except TableauDRError:
        logger.critical(
            "Failover execution failed due to a controlled DR framework error."
        )
        return 1

    except (ValueError, OSError):
        logger.critical(
            "Failover execution failed during input or environment validation."
        )
        return 1

    except Exception:
        logger.critical(
            "FATAL: Failover execution terminated unexpectedly."
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())