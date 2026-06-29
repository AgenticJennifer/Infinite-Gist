"""
Endpoints for remediation actions on findings.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.backend.api.deps import get_current_active_user
from src.backend.db.session import get_db
from src.backend.db.models import User, Finding, Gist, RemediationAction
from src.backend.schemas.gists import FindingResponse
from src.backend.services.remediation_service import RemediationService
from src.backend.services.remediation_verifier import RemediationVerifier
from src.backend.services.notification_service import NotificationService


router = APIRouter()


class RemediationRequest:
    def __init__(self, finding_id: int):
        self.finding_id = finding_id


class RemediationResponse:
    def __init__(
        self,
        id: int,
        action_type: str,
        status: str,
        finding_id: int,
        requested_at,
        executed_at=None,
        completed_at=None,
        verified: bool = False,
        error_message: str = None,
    ):
        self.id = id
        self.action_type = action_type
        self.status = status
        self.finding_id = finding_id
        self.requested_at = requested_at
        self.executed_at = executed_at
        self.completed_at = completed_at
        self.verified = verified
        self.error_message = error_message


def _action_to_response(action: RemediationAction) -> dict:
    return {
        "id": action.id,
        "action_type": action.action_type,
        "status": action.status,
        "finding_id": action.finding_id,
        "requested_at": action.requested_at.isoformat() if action.requested_at else None,
        "executed_at": action.executed_at.isoformat() if action.executed_at else None,
        "completed_at": action.completed_at.isoformat() if action.completed_at else None,
        "verified": action.verified,
        "error_message": action.error_message,
    }


@router.post("/make-private")
async def make_gist_private(
    finding_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    finding = (
        db.query(Finding)
        .join(Gist)
        .filter(Finding.id == finding_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found or access denied",
        )

    service = RemediationService(db)
    verifier = RemediationVerifier(db)
    notifier = NotificationService(db)

    try:
        action = await service.make_private(finding_id, current_user.id)
        await verifier.verify_action(action)
        await notifier.notify_remediation_complete(action)
        return _action_to_response(action)
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Remediation failed: {str(e)}",
        )


@router.post("/delete")
async def delete_gist(
    finding_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    finding = (
        db.query(Finding)
        .join(Gist)
        .filter(Finding.id == finding_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found or access denied",
        )

    service = RemediationService(db)
    verifier = RemediationVerifier(db)
    notifier = NotificationService(db)

    try:
        action = await service.delete_gist(finding_id, current_user.id)
        await verifier.verify_action(action)
        await notifier.notify_remediation_complete(action)
        return _action_to_response(action)
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Remediation failed: {str(e)}",
        )


@router.post("/rotate")
async def rotate_secret(
    finding_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    finding = (
        db.query(Finding)
        .join(Gist)
        .filter(Finding.id == finding_id)
        .filter(Gist.user_id == current_user.id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found or access denied",
        )

    service = RemediationService(db)

    try:
        action = await service.rotate_secret(finding_id, current_user.id)
        return _action_to_response(action)
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/{action_id}")
async def get_action_status(
    action_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = RemediationService(db)
    action = await service.get_action_status(action_id)

    if not action or action.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Action not found or access denied",
        )

    return _action_to_response(action)


@router.get("/")
async def get_action_history(
    skip: int = 0,
    limit: int = 50,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = RemediationService(db)
    actions = await service.get_user_actions(current_user.id, limit=limit, offset=skip)
    return [_action_to_response(a) for a in actions]
