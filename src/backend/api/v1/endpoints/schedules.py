"""
Endpoints for managing scan schedules.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.backend.api.deps import get_current_active_user
from src.backend.db.session import get_db
from src.backend.db.models import User, ScanSchedule
from src.backend.services.scheduler_service import SchedulerService
from src.backend.services.scan_executor import ScanExecutor

logger = logging.getLogger(__name__)

router = APIRouter()


def _schedule_to_response(schedule: ScanSchedule) -> dict:
    return {
        "id": schedule.id,
        "user_id": schedule.user_id,
        "github_account_id": schedule.github_account_id,
        "frequency": schedule.frequency,
        "cron_expression": schedule.cron_expression,
        "enabled": schedule.enabled,
        "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else None,
        "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        "created_at": schedule.created_at.isoformat() if schedule.created_at else None,
    }


@router.post("/")
async def create_schedule(
    github_account_id: int,
    frequency: str,
    cron_expression: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = SchedulerService(db)

    try:
        schedule = await service.create_schedule(
            user_id=current_user.id,
            github_account_id=github_account_id,
            frequency=frequency,
            cron_expression=cron_expression,
        )
        return _schedule_to_response(schedule)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create schedule: {str(e)}",
        )


@router.get("/")
async def list_schedules(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = SchedulerService(db)
    schedules = await service.get_user_schedules(current_user.id)
    return [_schedule_to_response(s) for s in schedules]


@router.get("/{schedule_id}")
async def get_schedule(
    schedule_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = SchedulerService(db)
    schedules = await service.get_user_schedules(current_user.id)

    for schedule in schedules:
        if schedule.id == schedule_id:
            return _schedule_to_response(schedule)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Schedule not found or access denied",
    )


@router.put("/{schedule_id}")
async def update_schedule(
    schedule_id: int,
    frequency: Optional[str] = None,
    cron_expression: Optional[str] = None,
    enabled: Optional[bool] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = SchedulerService(db)

    updates = {}
    if frequency is not None:
        updates["frequency"] = frequency
    if cron_expression is not None:
        updates["cron_expression"] = cron_expression
    if enabled is not None:
        updates["enabled"] = enabled

    try:
        schedule = await service.update_schedule(schedule_id, **updates)
        if schedule.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied",
            )
        return _schedule_to_response(schedule)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.delete("/{schedule_id}")
async def delete_schedule(
    schedule_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = SchedulerService(db)
    deleted = await service.delete_schedule(schedule_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule not found",
        )

    return {"detail": "Schedule deleted"}


@router.post("/execute")
async def execute_due_scans(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    executor = ScanExecutor(db)
    results = await executor.execute_all_due_scans()

    return {
        "executed_count": len(results),
        "scan_runs": [
            {
                "id": r.id,
                "status": r.status,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "ended_at": r.ended_at.isoformat() if r.ended_at else None,
            }
            for r in results
        ],
    }
