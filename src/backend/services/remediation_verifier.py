"""
Remediation verification service for proof-of-fix confirmation.
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
)
from src.backend.services.github_service import GitHubService, get_github_service_for_account
from src.backend.services.audit_service import AuditService


class RemediationVerifier:
    """Service for verifying remediation actions were successful."""

    def __init__(self, db: Session):
        self.db = db
        self.audit_service = AuditService(db)

    async def verify_make_private(self, action: RemediationAction) -> bool:
        """
        Verify a Gist is now private.

        Args:
            action: The remediation action to verify

        Returns:
            True if verification passed, False otherwise
        """
        finding = action.finding
        gist = finding.gist

        try:
            github_account = self.db.query(GitHubAccount).filter(
                GitHubAccount.user_id == action.user_id
            ).first()
            if not github_account:
                return False

            github_service = get_github_service_for_account(github_account)
            gist_data = await github_service.get_gist(gist.github_id)

            is_private = not gist_data.get("public", True)

            action.verified = is_private
            action.verified_at = datetime.utcnow()
            action.verification_details = str({
                "gist_id": gist.github_id,
                "public": gist_data.get("public"),
                "verified_at": datetime.utcnow().isoformat(),
            })
            self.db.commit()

            if is_private:
                await self.audit_service.log_event(
                    user_id=action.user_id,
                    event_type="remediation_verified",
                    event_description=f"Verified gist {gist.github_id} is now private",
                    details={"action_id": action.id, "gist_id": gist.github_id},
                )

            return is_private

        except Exception as e:
            action.verified = False
            action.verified_at = datetime.utcnow()
            action.verification_details = str({"error": str(e)})
            self.db.commit()
            return False

    async def verify_delete(self, action: RemediationAction) -> bool:
        """
        Verify a Gist was deleted.

        Args:
            action: The remediation action to verify

        Returns:
            True if verification passed (gist not found), False otherwise
        """
        finding = action.finding
        gist = finding.gist

        try:
            github_account = self.db.query(GitHubAccount).filter(
                GitHubAccount.user_id == action.user_id
            ).first()
            if not github_account:
                return False

            github_service = get_github_service_for_account(github_account)

            try:
                await github_service.get_gist(gist.github_id)
                gist_exists = True
            except Exception:
                gist_exists = False

            is_deleted = not gist_exists

            action.verified = is_deleted
            action.verified_at = datetime.utcnow()
            action.verification_details = str({
                "gist_id": gist.github_id,
                "exists": gist_exists,
                "verified_at": datetime.utcnow().isoformat(),
            })
            self.db.commit()

            if is_deleted:
                await self.audit_service.log_event(
                    user_id=action.user_id,
                    event_type="remediation_verified",
                    event_description=f"Verified gist {gist.github_id} was deleted",
                    details={"action_id": action.id, "gist_id": gist.github_id},
                )

            return is_deleted

        except Exception as e:
            action.verified = False
            action.verified_at = datetime.utcnow()
            action.verification_details = str({"error": str(e)})
            self.db.commit()
            return False

    async def verify_rotation(self, action: RemediationAction) -> bool:
        """Verify secret rotation (stub)."""
        action.verified = False
        action.verified_at = datetime.utcnow()
        action.verification_details = str({"error": "Rotation verification not implemented"})
        self.db.commit()
        return False

    async def verify_action(self, action: RemediationAction) -> bool:
        """
        Verify a remediation action based on its type.

        Args:
            action: The remediation action to verify

        Returns:
            True if verification passed, False otherwise
        """
        if action.action_type == "make_private":
            return await self.verify_make_private(action)
        elif action.action_type == "delete":
            return await self.verify_delete(action)
        elif action.action_type == "rotate":
            return await self.verify_rotation(action)
        else:
            return False
