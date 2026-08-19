"""
Endpoints for managing account-level security policies.
"""

import logging
import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.backend.api.deps import get_current_active_user
from src.backend.db.session import get_db
from src.backend.db.models import User, AccountPolicy
from src.backend.services.policy_service import PolicyService

logger = logging.getLogger(__name__)

router = APIRouter()


class PolicyUpdateRequest(BaseModel):
    auto_remediate: Optional[bool] = None
    auto_remediate_types: Optional[list[str]] = None
    notify_on_scan: Optional[bool] = None
    notify_on_finding: Optional[bool] = None
    digest_frequency: Optional[str] = None


def _policy_to_response(policy: AccountPolicy) -> dict:
    return {
        "id": policy.id,
        "user_id": policy.user_id,
        "auto_remediate": policy.auto_remediate,
        "auto_remediate_types": json.loads(policy.auto_remediate_types or "[]"),
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
    request: PolicyUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    service = PolicyService(db)

    updates = request.model_dump(exclude_unset=True)
    if "auto_remediate_types" in updates:
        updates["auto_remediate_types"] = json.dumps(updates["auto_remediate_types"])
    if updates.get("digest_frequency") not in {None, "daily", "weekly", "never"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="digest_frequency must be daily, weekly, or never",
        )

    try:
        policy = await service.update_policy(current_user.id, **updates)
        return _policy_to_response(policy)
    except Exception:
        logger.exception("Failed to update policy for user %s", current_user.id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update policy.",
        )
