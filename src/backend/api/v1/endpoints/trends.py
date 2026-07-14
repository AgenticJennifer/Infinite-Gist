"""
Endpoints for security posture trends.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.backend.api.deps import get_current_active_user
from src.backend.db.session import get_db
from src.backend.db.models import User
from src.backend.services.trend_service import TrendService

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/")
async def get_trends(
    days: int = 30,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = TrendService(db)
    trends = await service.get_trends(current_user.id, days=days)

    return [
        {
            "id": t.id,
            "date": t.date.isoformat() if t.date else None,
            "total_findings": t.total_findings,
            "critical_findings": t.critical_findings,
            "high_findings": t.high_findings,
            "medium_findings": t.medium_findings,
            "low_findings": t.low_findings,
            "gists_scanned": t.gists_scanned,
            "remediated_count": t.remediated_count,
        }
        for t in trends
    ]


@router.get("/summary")
async def get_posture_summary(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = TrendService(db)
    summary = await service.get_posture_summary(current_user.id)
    return summary


@router.post("/snapshot")
async def record_snapshot(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = TrendService(db)

    try:
        trend = await service.record_daily_snapshot(current_user.id)
        return {
            "id": trend.id,
            "date": trend.date.isoformat() if trend.date else None,
            "total_findings": trend.total_findings,
            "critical_findings": trend.critical_findings,
            "high_findings": trend.high_findings,
            "medium_findings": trend.medium_findings,
            "low_findings": trend.low_findings,
            "remediated_count": trend.remediated_count,
        }
    except Exception:
        logger.exception("Failed to record trend snapshot for user %s", current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record snapshot.",
        )
