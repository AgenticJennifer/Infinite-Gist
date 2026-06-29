"""
Remediation service for handling Gist remediation actions.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from src.backend.db.models import (
    Finding,
    Gist,
    GitHubAccount,
    RemediationAction,
    AuditEvent,
    User,
)
from src.backend.services.github_service import GitHubService, get_github_service_for_account
from src.backend.services.audit_service import AuditService


class RemediationService:
    """Service for executing and tracking remediation actions."""

    def __init__(self, db: Session):
        self.db = db
        self.audit_service = AuditService(db)

    async def make_private(self, finding_id: int, user_id: int) -> RemediationAction:
        """
        Make a Gist private.

        Args:
            finding_id: The ID of the finding to remediate
            user_id: The ID of the user requesting the action

        Returns:
            RemediationAction with execution details
        """
        # 1. Get finding and validate ownership
        finding = self.db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        gist = finding.gist
        if gist.user_id != user_id:
            raise PermissionError("You can only remediate your own findings")

        # 2. Create RemediationAction record
        action = RemediationAction(
            finding_id=finding_id,
            user_id=user_id,
            action_type="make_private",
            status="pending",
            requested_at=datetime.utcnow(),
        )
        self.db.add(action)
        self.db.commit()
        self.db.refresh(action)

        # 3. Log audit event
        await self.audit_service.log_event(
            user_id=user_id,
            event_type="remediation_requested",
            event_description=f"User requested make_private for gist {gist.github_id}",
            details={"action_id": action.id, "gist_id": gist.github_id},
        )

        try:
            # 4. Update status to executing
            action.status = "executing"
            self.db.commit()

            # 5. Get GitHub service
            github_account = self.db.query(GitHubAccount).filter(
                GitHubAccount.user_id == user_id
            ).first()
            if not github_account:
                raise ValueError("No GitHub account linked")

            github_service = get_github_service_for_account(github_account)

            # 6. Call GitHub API to make gist private
            response = await github_service.make_gist_private(gist.github_id)

            # 7. Update action with response
            action.status = "completed"
            action.executed_at = datetime.utcnow()
            action.completed_at = datetime.utcnow()
            action.github_response = str(response)

            # 8. Update gist in database
            gist.public = False
            gist.updated_at = datetime.utcnow()

            self.db.commit()

            # 9. Log completion
            await self.audit_service.log_event(
                user_id=user_id,
                event_type="remediation_completed",
                event_description=f"Successfully made gist {gist.github_id} private",
                details={"action_id": action.id, "gist_id": gist.github_id},
            )

            return action

        except Exception as e:
            # Handle failure
            action.status = "failed"
            action.error_message = str(e)
            action.completed_at = datetime.utcnow()
            self.db.commit()

            await self.audit_service.log_event(
                user_id=user_id,
                event_type="remediation_failed",
                event_description=f"Failed to make gist {gist.github_id} private: {str(e)}",
                details={"action_id": action.id, "gist_id": gist.github_id, "error": str(e)},
            )

            raise

    async def delete_gist(self, finding_id: int, user_id: int) -> RemediationAction:
        """
        Delete a Gist permanently.

        Args:
            finding_id: The ID of the finding to remediate
            user_id: The ID of the user requesting the action

        Returns:
            RemediationAction with execution details
        """
        # 1. Get finding and validate ownership
        finding = self.db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        gist = finding.gist
        if gist.user_id != user_id:
            raise PermissionError("You can only remediate your own findings")

        # 2. Create RemediationAction record
        action = RemediationAction(
            finding_id=finding_id,
            user_id=user_id,
            action_type="delete",
            status="pending",
            requested_at=datetime.utcnow(),
        )
        self.db.add(action)
        self.db.commit()
        self.db.refresh(action)

        # 3. Log audit event
        await self.audit_service.log_event(
            user_id=user_id,
            event_type="remediation_requested",
            event_description=f"User requested delete for gist {gist.github_id}",
            details={"action_id": action.id, "gist_id": gist.github_id},
        )

        try:
            # 4. Update status to executing
            action.status = "executing"
            self.db.commit()

            # 5. Get GitHub service
            github_account = self.db.query(GitHubAccount).filter(
                GitHubAccount.user_id == user_id
            ).first()
            if not github_account:
                raise ValueError("No GitHub account linked")

            github_service = get_github_service_for_account(github_account)

            # 6. Call GitHub API to delete gist
            response = await github_service.delete_gist(gist.github_id)

            # 7. Update action with response
            action.status = "completed"
            action.executed_at = datetime.utcnow()
            action.completed_at = datetime.utcnow()
            action.github_response = str(response)

            # 8. Mark gist as deleted in database (don't actually delete the record)
            gist.public = False
            gist.updated_at = datetime.utcnow()

            self.db.commit()

            # 9. Log completion
            await self.audit_service.log_event(
                user_id=user_id,
                event_type="remediation_completed",
                event_description=f"Successfully deleted gist {gist.github_id}",
                details={"action_id": action.id, "gist_id": gist.github_id},
            )

            return action

        except Exception as e:
            # Handle failure
            action.status = "failed"
            action.error_message = str(e)
            action.completed_at = datetime.utcnow()
            self.db.commit()

            await self.audit_service.log_event(
                user_id=user_id,
                event_type="remediation_failed",
                event_description=f"Failed to delete gist {gist.github_id}: {str(e)}",
                details={"action_id": action.id, "gist_id": gist.github_id, "error": str(e)},
            )

            raise

    async def rotate_secret(self, finding_id: int, user_id: int) -> RemediationAction:
        """
        Initiate secret rotation (stub for future implementation).

        Args:
            finding_id: The ID of the finding to remediate
            user_id: The ID of the user requesting the action

        Returns:
            RemediationAction with status
        """
        # 1. Get finding and validate ownership
        finding = self.db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        gist = finding.gist
        if gist.user_id != user_id:
            raise PermissionError("You can only remediate your own findings")

        # 2. Create RemediationAction record
        action = RemediationAction(
            finding_id=finding_id,
            user_id=user_id,
            action_type="rotate",
            status="failed",  # Not implemented yet
            requested_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            error_message="Secret rotation not yet implemented. Please rotate manually.",
        )
        self.db.add(action)
        self.db.commit()
        self.db.refresh(action)

        # 3. Log audit event
        await self.audit_service.log_event(
            user_id=user_id,
            event_type="remediation_requested",
            event_description=f"User requested secret rotation for finding {finding_id} (not implemented)",
            details={"action_id": action.id, "finding_id": finding_id},
        )

        return action

    async def get_action_status(self, action_id: int) -> Optional[RemediationAction]:
        """
        Get current status of a remediation action.

        Args:
            action_id: The ID of the action

        Returns:
            RemediationAction or None if not found
        """
        return self.db.query(RemediationAction).filter(RemediationAction.id == action_id).first()

    async def get_user_actions(
        self, user_id: int, limit: int = 50, offset: int = 0
    ) -> list[RemediationAction]:
        """
        Get remediation action history for a user.

        Args:
            user_id: The user ID
            limit: Maximum number of actions to return
            offset: Offset for pagination

        Returns:
            List of RemediationAction records
        """
        return (
            self.db.query(RemediationAction)
            .filter(RemediationAction.user_id == user_id)
            .order_by(RemediationAction.requested_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
