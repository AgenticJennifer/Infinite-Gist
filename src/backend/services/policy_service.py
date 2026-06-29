"""
Policy service for managing account-level security policies.
"""

import json
import logging
from sqlalchemy.orm import Session

from src.backend.db.models import AccountPolicy

logger = logging.getLogger(__name__)


class PolicyService:
    """Service for managing user security policies."""

    def __init__(self, db: Session):
        self.db = db

    async def get_user_policy(self, user_id: int) -> AccountPolicy:
        """
        Get or create a user's security policy.

        Args:
            user_id: The user ID

        Returns:
            AccountPolicy record
        """
        policy = self.db.query(AccountPolicy).filter(
            AccountPolicy.user_id == user_id
        ).first()

        if not policy:
            policy = AccountPolicy(
                user_id=user_id,
                auto_remediate=False,
                auto_remediate_types="[]",
                notify_on_scan=True,
                notify_on_finding=True,
                digest_frequency="weekly",
            )
            self.db.add(policy)
            self.db.commit()
            self.db.refresh(policy)

        return policy

    async def update_policy(self, user_id: int, **kwargs) -> AccountPolicy:
        """
        Update a user's security policy.

        Args:
            user_id: The user ID
            **kwargs: Fields to update

        Returns:
            Updated AccountPolicy record
        """
        policy = await self.get_user_policy(user_id)

        for key, value in kwargs.items():
            if hasattr(policy, key):
                setattr(policy, key, value)

        self.db.commit()
        self.db.refresh(policy)

        return policy

    async def should_auto_remediate(self, user_id: int, finding_type: str) -> bool:
        """
        Check if a finding should be auto-remediated based on policy.

        Args:
            user_id: The user ID
            finding_type: The type of finding (e.g., "aws_key", "password")

        Returns:
            True if auto-remediation is allowed for this finding type
        """
        policy = await self.get_user_policy(user_id)

        if not policy.auto_remediate:
            return False

        try:
            types = json.loads(policy.auto_remediate_types or "[]")
        except (json.JSONDecodeError, TypeError):
            types = []

        # Empty list means all types are allowed
        if not types:
            return True

        return finding_type in types

    async def should_notify(self, user_id: int, event_type: str) -> bool:
        """
        Check if a notification should be sent based on policy.

        Args:
            user_id: The user ID
            event_type: The event type ("scan" or "finding")

        Returns:
            True if notification is enabled for this event type
        """
        policy = await self.get_user_policy(user_id)

        if event_type == "scan":
            return policy.notify_on_scan
        elif event_type == "finding":
            return policy.notify_on_finding

        return True
