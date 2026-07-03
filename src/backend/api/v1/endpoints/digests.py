"""
Endpoints for managing digest reports.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.backend.api.deps import get_current_active_user
from src.backend.db.session import get_db
from src.backend.db.models import User, DigestReport
from src.backend.services.digest_service import DigestService


router = APIRouter()


def _digest_to_response(report: DigestReport) -> dict:
    return {
        "id": report.id,
        "user_id": report.user_id,
        "report_type": report.report_type,
        "period_start": report.period_start.isoformat() if report.period_start else None,
        "period_end": report.period_end.isoformat() if report.period_end else None,
        "summary": report.summary,
        "sent_at": report.sent_at.isoformat() if report.sent_at else None,
        "created_at": report.created_at.isoformat() if report.created_at else None,
    }


@router.get("/")
async def list_digests(
    limit: int = 30,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = DigestService(db)
    digests = await service.get_user_digests(current_user.id, limit=limit)
    return [_digest_to_response(d) for d in digests]


@router.get("/{digest_id}")
async def get_digest(
    digest_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = DigestService(db)
    digests = await service.get_user_digests(current_user.id, limit=1000)

    for report in digests:
        if report.id == digest_id:
            return _digest_to_response(report)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Digest report not found or access denied",
    )


@router.post("/generate")
async def generate_digest(
    report_type: str = "daily",
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = DigestService(db)

    try:
        if report_type == "weekly":
            report = await service.generate_weekly_digest(current_user.id)
        else:
            report = await service.generate_daily_digest(current_user.id)

        return _digest_to_response(report)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate digest: {str(e)}",
        )
