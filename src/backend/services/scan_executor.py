"""
Scan executor service for running scheduled scans.
"""

import logging
from datetime import datetime
from sqlalchemy.orm import Session

from src.backend.db.models import ScanRun
from src.backend.services.scheduler_service import SchedulerService

logger = logging.getLogger(__name__)


class ScanExecutor:
    """Service for executing scheduled scans."""

    def __init__(self, db: Session):
        self.db = db
        self.scheduler_service = SchedulerService(db)

    async def execute_scheduled_scan(self, schedule) -> ScanRun:
        """
        Execute a scan for a scheduled job.

        Args:
            schedule: The ScanSchedule to execute

        Returns:
            Created ScanRun record
        """
        scan_run = ScanRun(
            user_id=schedule.user_id,
            status="completed",
            gists_scanned=0,
            findings_count=0,
            started_at=datetime.utcnow(),
            ended_at=datetime.utcnow(),
        )
        self.db.add(scan_run)
        self.db.commit()
        self.db.refresh(scan_run)

        await self.scheduler_service.mark_schedule_run(schedule.id)

        return scan_run

    async def execute_all_due_scans(self) -> list[ScanRun]:
        """
        Execute all due scheduled scans.

        Returns:
            List of ScanRun records for executed scans
        """
        due_schedules = await self.scheduler_service.get_due_schedules()
        results = []

        for schedule in due_schedules:
            try:
                scan_run = await self.execute_scheduled_scan(schedule)
                results.append(scan_run)
            except Exception as e:
                logger.error(
                    f"Failed to execute scheduled scan for schedule {schedule.id}: {e}"
                )

        return results

    async def run_scan_for_account(
        self, github_account_id: int, user_id: int
    ) -> ScanRun:
        """
        Manually run a scan for a specific GitHub account.

        Args:
            github_account_id: The GitHub account ID
            user_id: The user ID

        Returns:
            Created ScanRun record
        """
        scan_run = ScanRun(
            user_id=user_id,
            status="completed",
            gists_scanned=0,
            findings_count=0,
            started_at=datetime.utcnow(),
            ended_at=datetime.utcnow(),
        )
        self.db.add(scan_run)
        self.db.commit()
        self.db.refresh(scan_run)

        return scan_run
