"""
Scheduler service for managing periodic scan schedules.
"""

from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session

from src.backend.db.models import ScanSchedule
from src.backend.services.audit_service import AuditService


class SchedulerService:
    """Service for creating and managing scan schedules."""

    def __init__(self, db: Session):
        self.db = db
        self.audit_service = AuditService(db)

    def _calculate_next_run(self, frequency: str) -> datetime:
        """Calculate next run time based on frequency."""
        now = datetime.utcnow()
        if frequency == "daily":
            return now + timedelta(days=1)
        elif frequency == "weekly":
            return now + timedelta(weeks=1)
        else:
            # custom or unknown — default to 1 day
            return now + timedelta(days=1)

    async def create_schedule(
        self,
        user_id: int,
        github_account_id: int,
        frequency: str,
        cron_expression: Optional[str] = None,
    ) -> ScanSchedule:
        """
        Create a new scan schedule.

        Args:
            user_id: The user who owns the schedule
            github_account_id: The GitHub account to scan
            frequency: Scan frequency ("daily", "weekly", "custom")
            cron_expression: Optional cron expression for custom schedules

        Returns:
            Created ScanSchedule record
        """
        schedule = ScanSchedule(
            user_id=user_id,
            github_account_id=github_account_id,
            frequency=frequency,
            cron_expression=cron_expression,
            enabled=True,
            next_run_at=self._calculate_next_run(frequency),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.db.add(schedule)
        self.db.commit()
        self.db.refresh(schedule)

        await self.audit_service.log_event(
            user_id=user_id,
            event_type="schedule_created",
            event_description=f"Created {frequency} scan schedule",
            details={"schedule_id": schedule.id, "frequency": frequency},
        )

        return schedule

    async def update_schedule(self, schedule_id: int, **kwargs) -> ScanSchedule:
        """
        Update an existing scan schedule.

        Args:
            schedule_id: The schedule ID to update
            **kwargs: Fields to update

        Returns:
            Updated ScanSchedule record
        """
        schedule = self.db.query(ScanSchedule).filter(
            ScanSchedule.id == schedule_id
        ).first()
        if not schedule:
            raise ValueError(f"Schedule {schedule_id} not found")

        frequency_changed = False
        for key, value in kwargs.items():
            if hasattr(schedule, key):
                if key == "frequency" and value != schedule.frequency:
                    frequency_changed = True
                setattr(schedule, key, value)

        if frequency_changed:
            schedule.next_run_at = self._calculate_next_run(schedule.frequency)

        schedule.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(schedule)

        await self.audit_service.log_event(
            user_id=schedule.user_id,
            event_type="schedule_updated",
            event_description=f"Updated scan schedule {schedule_id}",
            details={"schedule_id": schedule_id, "updated_fields": list(kwargs.keys())},
        )

        return schedule

    async def delete_schedule(self, schedule_id: int) -> bool:
        """
        Delete a scan schedule.

        Args:
            schedule_id: The schedule ID to delete

        Returns:
            True if deleted, False if not found
        """
        schedule = self.db.query(ScanSchedule).filter(
            ScanSchedule.id == schedule_id
        ).first()
        if not schedule:
            return False

        self.db.delete(schedule)
        self.db.commit()
        return True

    async def get_user_schedules(self, user_id: int) -> list[ScanSchedule]:
        """
        Get all schedules for a user.

        Args:
            user_id: The user ID

        Returns:
            List of ScanSchedule records
        """
        return (
            self.db.query(ScanSchedule)
            .filter(ScanSchedule.user_id == user_id)
            .order_by(ScanSchedule.created_at)
            .all()
        )

    async def get_due_schedules(self) -> list[ScanSchedule]:
        """
        Get all schedules that are due for execution.

        Returns:
            List of due ScanSchedule records
        """
        now = datetime.utcnow()
        return (
            self.db.query(ScanSchedule)
            .filter(
                ScanSchedule.enabled == True,
                ScanSchedule.next_run_at <= now,
            )
            .all()
        )

    async def mark_schedule_run(self, schedule_id: int) -> ScanSchedule:
        """
        Mark a schedule as having been run and calculate next run time.

        Args:
            schedule_id: The schedule ID

        Returns:
            Updated ScanSchedule record
        """
        schedule = self.db.query(ScanSchedule).filter(
            ScanSchedule.id == schedule_id
        ).first()
        if not schedule:
            raise ValueError(f"Schedule {schedule_id} not found")

        schedule.last_run_at = datetime.utcnow()
        schedule.next_run_at = self._calculate_next_run(schedule.frequency)
        schedule.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(schedule)

        return schedule
