"""CLI Entry point for driving scheduled Tableau DR backups."""

from __future__ import annotations

import argparse
import sys
import uuid
from tableau_dr.config import Config
from tableau_dr.logger import get_logger
from tableau_dr.backup_manager import BackupManager


def parse_args():
    parser = argparse.ArgumentParser(description="Tableau Server Enterprise DR Backup Driver")
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to YAML configuration file",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    run_id = uuid.uuid4().hex[:8].upper()
    logger = get_logger("TableauDR-Backup", run_id=run_id)

    try:
        config = Config(args.config)
        manager = BackupManager(config=config, run_id=run_id)
        result = manager.execute_backup_pipeline()

        if result.status != "SUCCESS":
        logger.error("Backup pipeline returned a non-success status.")
        sys.exit(1)

        if not result.remote_verified:
        logger.error("Backup completed but remote verification did not pass.")
        sys.exit(1)
        
        if result.cleanup_status == "FAILED":
            logger.warning("Backup complete and verified remotely, but local staging cleanup failed.")
            sys.exit(0)

        logger.info("DR Backup Pipeline Completed Successfully.")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"FATAL: Backup Execution Failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()