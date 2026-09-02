"""CLI entry point for executing the Tableau DR backup pipeline."""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

from tableau_dr.backup_manager import BackupManager
from tableau_dr.config import Config
from tableau_dr.logger import get_logger


DEFAULT_CONFIG_PATH = "config/config.yaml"


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Execute the Tableau Server Disaster Recovery "
            "backup pipeline."
        )
    )

    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=(
            "Path to the YAML configuration file "
            f"(default: {DEFAULT_CONFIG_PATH})"
        ),
    )

    parser.add_argument(
        "--run-id",
        help=(
            "Optional execution identifier. If omitted, "
            "a secure random identifier is generated."
        ),
    )

    return parser.parse_args()


def main() -> int:
    """Execute the backup pipeline and return an appropriate exit code."""

    args = parse_args()

    run_id = (
        args.run_id.strip()
        if isinstance(args.run_id, str)
        and args.run_id.strip()
        else uuid.uuid4().hex.upper()
    )

    logger = get_logger(
        "TableauDR-Backup",
        run_id=run_id,
        operation="BACKUP",
    )

    try:
        config_path = Path(args.config).expanduser()

        logger.info(
            "Initializing Tableau DR backup execution."
        )

        config = Config(
            config_path=config_path
        )

        manager = BackupManager(
            config=config,
            run_id=run_id,
        )

        result = manager.execute_backup_pipeline()

        logger.info(
            "DR backup pipeline completed. "
            "status=%s remote_verified=%s cleanup_status=%s",
            result.status,
            result.remote_verified,
            result.cleanup_status,
        )

        if result.status != "SUCCESS":
            logger.error(
                "Backup pipeline reported unsuccessful status."
            )
            return 1

        # Remote verification is the authoritative safety gate.
        if not result.remote_verified:
            logger.critical(
                "Backup completed without successful remote integrity "
                "verification. Refusing successful exit."
            )
            return 1

        # Cleanup failure does not invalidate the verified remote backup.
        # It does, however, require operator attention.
        if result.cleanup_status == "FAILED":
            logger.warning(
                "Remote backup is verified, but local staging cleanup "
                "failed. Manual cleanup may be required."
            )

        logger.info(
            "DR Backup Pipeline Completed Successfully."
        )

        return 0

    except KeyboardInterrupt:
        logger.critical(
            "Backup execution interrupted by operator."
        )
        return 130

    except Exception:
        # Detailed exception content is intentionally not exposed at the
        # CLI boundary because lower-level components already sanitize logs.
        logger.critical(
            "FATAL: Backup execution failed."
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())