"""
Scan executor service for running scheduled scans.

This service drives periodic / on-demand scans. It creates a ScanRun
record, delegates the actual scanning to GistScannerService, persists the
result counts, and advances the schedule.
"""

import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from src.backend.db.models import ScanRun, Gist
from src.backend.services.scheduler_service import SchedulerService
from src.backend.services.gist_scanner import GistScannerService

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
            status="running",
            gists_scanned=0,
            findings_count=0,
            started_at=datetime.now(timezone.utc),
        )
        self.db.add(scan_run)
        self.db.commit()
        self.db.refresh(scan_run)

        try:
            scanner = GistScannerService(self.db)
            findings = await scanner.scan_github_account(schedule.github_account_id)
            scan_run.gists_scanned = (
                self.db.query(Gist)
                .filter(Gist.user_id == schedule.user_id)
                .count()
            )
            scan_run.findings_count = len(findings)
            scan_run.status = "completed"
            scan_run.ended_at = datetime.now(timezone.utc)
            self.db.commit()
        except Exception as e:
            logger.error("Scheduled scan failed for schedule %s: %s", schedule.id, e)
            scan_run.status = "failed"
            scan_run.ended_at = datetime.now(timezone.utc)
            self.db.commit()
            raise

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
            claimed = await self.scheduler_service.claim_schedule(
                schedule.id, schedule.frequency
            )
            if not claimed:
                logger.info(
                    "Schedule %s already claimed by a concurrent run, skipping",
                    schedule.id,
                )
                continue

            try:
                scan_run = await self.execute_scheduled_scan(schedule)
                results.append(scan_run)
            except Exception:
                logger.exception(
                    "Failed to execute scheduled scan for schedule %s", schedule.id
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
            status="running",
            gists_scanned=0,
            findings_count=0,
            started_at=datetime.now(timezone.utc),
        )
        self.db.add(scan_run)
        self.db.commit()
        self.db.refresh(scan_run)

        try:
            scanner = GistScannerService(self.db)
            findings = await scanner.scan_github_account(github_account_id)
            scan_run.gists_scanned = (
                self.db.query(Gist)
                .filter(Gist.user_id == user_id)
                .count()
            )
            scan_run.findings_count = len(findings)
            scan_run.status = "completed"
        except Exception as e:
            logger.error("Manual scan failed for account %s: %s", github_account_id, e)
            scan_run.status = "failed"
            raise
        finally:
            scan_run.ended_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(scan_run)

        return scan_run
