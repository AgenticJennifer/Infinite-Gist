"""
Scheduler service for managing periodic scan schedules.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from croniter import croniter
from sqlalchemy.orm import Session

from src.backend.db.models import ScanSchedule
from src.backend.services.audit_service import AuditService


class SchedulerService:
    """Service for creating and managing scan schedules."""

    def __init__(self, db: Session):
        self.db = db
        self.audit_service = AuditService(db)

    def _calculate_next_run(
        self, frequency: str, cron_expression: Optional[str] = None
    ) -> datetime:
        """Calculate next run time based on frequency."""
        now = datetime.now(timezone.utc)
        if frequency == "daily":
            return now + timedelta(days=1)
        elif frequency == "weekly":
            return now + timedelta(weeks=1)
        elif frequency == "custom":
            if not cron_expression or not croniter.is_valid(cron_expression):
                raise ValueError("A valid five-field cron expression is required")
            return croniter(cron_expression, now).get_next(datetime)
        raise ValueError("Frequency must be daily, weekly, or custom")

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
            next_run_at=self._calculate_next_run(frequency, cron_expression),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
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

    async def update_schedule(
        self, schedule_id: int, user_id: int, **kwargs
    ) -> ScanSchedule:
        """
        Update an existing scan schedule owned by the given user.

        Args:
            schedule_id: The schedule ID to update
            user_id: The owning user's ID; the update is rejected if the schedule
                belongs to a different user
            **kwargs: Fields to update

        Returns:
            Updated ScanSchedule record
        """
        schedule = (
            self.db.query(ScanSchedule)
            .filter(
                ScanSchedule.id == schedule_id,
                ScanSchedule.user_id == user_id,
            )
            .first()
        )
        if not schedule:
            raise ValueError(f"Schedule {schedule_id} not found")

        allowed_fields = {"frequency", "cron_expression", "enabled"}
        schedule_changed = False
        for key, value in kwargs.items():
            if key in allowed_fields:
                if key in {"frequency", "cron_expression"} and value != getattr(
                    schedule, key
                ):
                    schedule_changed = True
                setattr(schedule, key, value)

        if schedule_changed:
            schedule.next_run_at = self._calculate_next_run(
                schedule.frequency, schedule.cron_expression
            )

        schedule.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(schedule)

        await self.audit_service.log_event(
            user_id=schedule.user_id,
            event_type="schedule_updated",
            event_description=f"Updated scan schedule {schedule_id}",
            details={"schedule_id": schedule_id, "updated_fields": list(kwargs.keys())},
        )

        return schedule

    async def delete_schedule(self, schedule_id: int, user_id: int) -> bool:
        """
        Delete a scan schedule owned by the given user.

        Args:
            schedule_id: The schedule ID to delete
            user_id: The owning user's ID; deletion is rejected if the schedule
                belongs to a different user

        Returns:
            True if deleted, False if not found (or not owned by user_id)
        """
        schedule = (
            self.db.query(ScanSchedule)
            .filter(
                ScanSchedule.id == schedule_id,
                ScanSchedule.user_id == user_id,
            )
            .first()
        )
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
        now = datetime.now(timezone.utc)
        return (
            self.db.query(ScanSchedule)
            .filter(
                ScanSchedule.enabled.is_(True),
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
        schedule = (
            self.db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
        )
        if not schedule:
            raise ValueError(f"Schedule {schedule_id} not found")

        schedule.last_run_at = datetime.now(timezone.utc)
        schedule.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(schedule)

        return schedule

    async def claim_schedule(
        self,
        schedule_id: int,
        frequency: str,
        cron_expression: Optional[str] = None,
    ) -> bool:
        """
        Atomically claim a due schedule for execution.

        Advances next_run_at in a single UPDATE guarded by the same due-condition
        used by get_due_schedules, so only one concurrent caller can "win" the
        claim for a given schedule.

        Args:
            schedule_id: The schedule ID to claim
            frequency: The schedule's frequency, used to compute the new next_run_at

        Returns:
            True if this call claimed the schedule, False if it was already
            claimed (or disabled/not yet due) by the time this ran.
        """
        now = datetime.now(timezone.utc)
        rows_updated = (
            self.db.query(ScanSchedule)
            .filter(
                ScanSchedule.id == schedule_id,
                ScanSchedule.enabled.is_(True),
                ScanSchedule.next_run_at <= now,
            )
            .update(
                {"next_run_at": self._calculate_next_run(frequency, cron_expression)},
                synchronize_session=False,
            )
        )
        self.db.commit()
        return rows_updated == 1
