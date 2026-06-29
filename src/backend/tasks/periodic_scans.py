"""
Background task for periodic scan execution.
"""

import logging
from datetime import datetime
from sqlalchemy.orm import Session

from src.backend.db.session import SessionLocal
from src.backend.services.scheduler_service import SchedulerService
from src.backend.services.scan_executor import ScanExecutor
from src.backend.services.digest_service import DigestService
from src.backend.services.trend_service import TrendService
from src.backend.services.policy_service import PolicyService

logger = logging.getLogger(__name__)


async def run_periodic_scans():
    """Execute all due scheduled scans and generate digests."""
    db = SessionLocal()
    try:
        executor = ScanExecutor(db)
        scheduler = SchedulerService(db)
        digest_service = DigestService(db)
        trend_service = TrendService(db)
        policy_service = PolicyService(db)

        # Execute due scans
        results = await executor.execute_all_due_scans()
        logger.info(f"Executed {len(results)} scheduled scans")

        # Record daily snapshots for users with completed scans
        for scan_run in results:
            try:
                await trend_service.record_daily_snapshot(scan_run.user_id)
            except Exception as e:
                logger.error(
                    f"Failed to record snapshot for user {scan_run.user_id}: {e}"
                )

        logger.info("Periodic scan cycle complete")

    except Exception as e:
        logger.error(f"Periodic scan error: {e}")
    finally:
        db.close()
