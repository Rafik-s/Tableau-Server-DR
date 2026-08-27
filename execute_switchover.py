"""CLI Switchover Entry Point for Disaster Recovery Failover Operations."""

from __future__ import annotations

import argparse
import sys
import uuid
from tableau_dr.config import Config
from tableau_dr.logger import get_logger
from tableau_dr.recovery_manager import RecoveryManager, RecoveryState

def parse_args():
    parser = argparse.ArgumentParser(description="Tableau Server Disaster Recovery Failover Orchestrator")
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--manifest-blob",
        help="Explicit Azure Blob path to target backup manifest.json. Defaults to latest.",
    )
    parser.add_argument(
        "--emergency-auth-code",
        help="Authorized secret code required to force fencing override.",
    )
    parser.add_argument(
        "--operator-reason",
        help="Mandatory audited operator justification required if emergency code is provided.",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Bypass interactive terminal confirmation prompt (for automated DR systems).",
    )
    return parser.parse_args()

def main():
    args = parse_args()
    run_id = uuid.uuid4().hex[:8].upper()
    logger = get_logger("TableauDR-Failover", run_id=run_id)

    logger.warning("=========================================================================")
    logger.warning("               DISASTER RECOVERY FAILOVER INITIATED                      ")
    logger.warning("=========================================================================")

    # Interactive Confirmation Gate
    if not args.non_interactive:
        print("\n[WARNING] You are about to initiate DR restoration and failover!")
        print("This will overwrite configuration and data on the target DR node.")
        confirm = input("Type 'CONFIRM-FAILOVER' to proceed: ").strip()
        if confirm != "CONFIRM-FAILOVER":
            logger.info("Failover operation cancelled by operator.")
            sys.exit(0)

    try:
        config = Config(args.config)
        manager = RecoveryManager(config=config, run_id=run_id)
        
        result = manager.execute_failover(
            emergency_auth_code=args.emergency_auth_code,
            operator_reason=args.operator_reason,
            target_manifest_blob=args.manifest_blob,
        )

        logger.info(f"Recovery Run Complete. Final Status: {result.status}")
        logger.info(f"Measured Backup-Age RPO: {result.measured_backup_age_rpo_seconds} seconds")
        logger.info(f"Total Recovery RTO: {result.total_rto_seconds} seconds")

        if result.status == "SUCCESS":
            sys.exit(0)
        else:
            logger.error(f"Failover failed at stage: {result.failed_step}")
            sys.exit(1)

    except Exception as e:
        logger.critical(f"FATAL: Failover Process Terminated Unexpectedly: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()