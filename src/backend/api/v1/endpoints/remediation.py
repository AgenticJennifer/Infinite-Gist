"""
Endpoints for remediation actions on findings.
"""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.backend.api.deps import get_current_active_user
from src.backend.core.rate_limit import enforce_remediation_rate_limit
from src.backend.db.session import get_db
from src.backend.db.models import User, Finding, Gist, RemediationAction
from src.backend.services.remediation_service import RemediationService
from src.backend.services.remediation_verifier import RemediationVerifier
from src.backend.services.notification_service import NotificationService

logger = logging.getLogger(__name__)

router = APIRouter()


class RemediationRequest(BaseModel):
    finding_id: int


class SecretReplacementRequest(RemediationRequest):
    confirm_url_and_history_change: bool


def _action_to_response(action: RemediationAction) -> dict:
    return {
        "id": action.id,
        "action_type": action.action_type,
        "status": action.status,
        "finding_id": action.finding_id,
        "requested_at": action.requested_at.isoformat()
        if action.requested_at
        else None,
        "executed_at": action.executed_at.isoformat() if action.executed_at else None,
        "completed_at": action.completed_at.isoformat()
        if action.completed_at
        else None,
        "verified": action.verified,
        "error_message": action.error_message,
        "details": json.loads(action.verification_details)
        if action.verification_details
        else None,
    }


@router.post(
    "/replace-with-secret", dependencies=[Depends(enforce_remediation_rate_limit)]
)
async def replace_gist_with_secret(
    request: SecretReplacementRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    if not request.confirm_url_and_history_change:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm that replacement changes the Gist URL and drops history",
        )

    finding_id = request.finding_id
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
        action = await service.replace_with_secret(finding_id, current_user.id)
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
    except Exception:
        logger.exception("secret replacement failed for finding %s", finding_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Remediation failed.",
        )


@router.post("/delete", dependencies=[Depends(enforce_remediation_rate_limit)])
async def delete_gist(
    request: RemediationRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    finding_id = request.finding_id
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
    except Exception:
        logger.exception("delete remediation failed for finding %s", finding_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Remediation failed.",
        )


@router.post("/rotate", dependencies=[Depends(enforce_remediation_rate_limit)])
async def rotate_secret(
    request: RemediationRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    finding_id = request.finding_id
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
    action = await service.get_action_status(action_id, user_id=current_user.id)

    if not action:
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
