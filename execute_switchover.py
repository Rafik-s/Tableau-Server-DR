"""CLI entry point for executing Tableau DR failover switchover."""

from __future__ import annotations

import argparse
import sys
import uuid

from tableau_dr.config import Config
from tableau_dr.logger import get_logger
from tableau_dr.recovery_manager import RecoveryManager


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Tableau Server Disaster Recovery Failover Driver"
    )

    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to YAML configuration file",
    )

    parser.add_argument(
        "--manifest-blob",
        help="Explicit Azure Blob path to target manifest.json",
    )

    parser.add_argument(
        "--emergency-auth-code",
        help="Authorized secret code required for emergency fencing override",
    )

    parser.add_argument(
        "--operator-reason",
        help="Audited justification required if emergency override code is provided",
    )

    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Bypass interactive terminal prompt for automated executions",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    run_id = uuid.uuid4().hex[:8].upper()

    logger = get_logger(
        "TableauDR-Switchover",
        run_id=run_id,
    )

    logger.warning(
        "========================================================================="
    )
    logger.warning(
        "               DISASTER RECOVERY FAILOVER INITIATED"
    )
    logger.warning(
        "========================================================================="
    )

    # Emergency override requires an audited reason.
    if args.emergency_auth_code and not args.operator_reason:
        logger.error(
            "Emergency authentication code requires an operator reason."
        )
        return 2

    # Interactive safety gate.
    if not args.non_interactive:
        print(
            "\n[WARNING] Initiating DR restoration will overwrite "
            "data on the target DR node!"
        )

        confirm = input(
            "Type 'CONFIRM-FAILOVER' to proceed: "
        ).strip()

        if confirm != "CONFIRM-FAILOVER":
            logger.info(
                "Failover operation cancelled by operator."
            )
            return 0

    try:
        logger.info(
            "Loading DR configuration."
        )

        config = Config(args.config)

        logger.info(
            "Initializing recovery manager."
        )

        manager = RecoveryManager(
            config=config,
            run_id=run_id,
        )

        logger.warning(
            "Executing DR failover workflow."
        )

        result = manager.execute_failover(
            emergency_auth_code=args.emergency_auth_code,
            operator_reason=args.operator_reason,
            target_manifest_blob=args.manifest_blob,
        )

        logger.info(
            f"Recovery completed with status: {result.status}"
        )

        logger.info(
            f"Measured Backup-Age RPO: "
            f"{result.measured_backup_age_rpo_seconds} s"
        )

        logger.info(
            f"Total Recovery RTO: "
            f"{result.total_rto_seconds} s"
        )

        if result.status == "SUCCESS":
            logger.info(
                "DR failover completed successfully."
            )
            return 0

        logger.error(
            f"Failover failed at stage: {result.failed_step}"
        )
        return 1

    except Exception:
        # Do not expose raw exception text because it may contain
        # credentials, connection strings, command output, or paths.
        logger.critical(
            "FATAL: Failover process terminated unexpectedly."
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())