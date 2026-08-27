"""CLI entry point script for scheduled Tableau DR backups."""

from __future__ import annotations

import argparse
import sys
import uuid
from tableau_dr.config import Config
from tableau_dr.logger import get_logger
from tableau_dr.backup_manager import BackupManager

def parse_args():
    parser = argparse.ArgumentParser(description="Tableau Server Enterprise DR Backup Engine")
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

        if result.cleanup_status == "FAILED":
            logger.warning("DR Backup completed with remote verification, but local workspace cleanup failed.")
            sys.exit(0)  # Remote backup succeeded, so scheduler exit code remains 0 with warning

        logger.info("DR Backup Pipeline Completed Successfully.")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"FATAL: Backup Execution Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()