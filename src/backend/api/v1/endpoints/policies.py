"""
Endpoints for managing account-level security policies.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.backend.api.deps import get_current_active_user
from src.backend.db.session import get_db
from src.backend.db.models import User, AccountPolicy
from src.backend.services.policy_service import PolicyService


router = APIRouter()


def _policy_to_response(policy: AccountPolicy) -> dict:
    return {
        "id": policy.id,
        "user_id": policy.user_id,
        "auto_remediate": policy.auto_remediate,
        "auto_remediate_types": policy.auto_remediate_types,
        "notify_on_scan": policy.notify_on_scan,
        "notify_on_finding": policy.notify_on_finding,
        "digest_frequency": policy.digest_frequency,
    }


@router.get("/")
async def get_policy(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = PolicyService(db)
    policy = await service.get_user_policy(current_user.id)
    return _policy_to_response(policy)


@router.put("/")
async def update_policy(
    auto_remediate: Optional[bool] = None,
    auto_remediate_types: Optional[str] = None,
    notify_on_scan: Optional[bool] = None,
    notify_on_finding: Optional[bool] = None,
    digest_frequency: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = PolicyService(db)

    updates = {}
    if auto_remediate is not None:
        updates["auto_remediate"] = auto_remediate
    if auto_remediate_types is not None:
        updates["auto_remediate_types"] = auto_remediate_types
    if notify_on_scan is not None:
        updates["notify_on_scan"] = notify_on_scan
    if notify_on_finding is not None:
        updates["notify_on_finding"] = notify_on_finding
    if digest_frequency is not None:
        updates["digest_frequency"] = digest_frequency

    try:
        policy = await service.update_policy(current_user.id, **updates)
        return _policy_to_response(policy)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update policy: {str(e)}",
        )
