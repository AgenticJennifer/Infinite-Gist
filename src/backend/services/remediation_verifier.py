"""
Remediation verification service for proof-of-fix confirmation.
"""

from datetime import datetime, timezone
import json

import httpx
from sqlalchemy.orm import Session

from src.backend.db.models import (
    GitHubAccount,
    RemediationAction,
)
from src.backend.services.github_service import get_github_service_for_account
from src.backend.services.audit_service import AuditService


class RemediationVerifier:
    """Service for verifying remediation actions were successful."""

    def __init__(self, db: Session):
        self.db = db
        self.audit_service = AuditService(db)

    def _github_account_for_action(self, action: RemediationAction):
        gist = action.finding.gist
        criteria = [GitHubAccount.user_id == action.user_id]
        if isinstance(gist.github_account_id, int):
            criteria.append(GitHubAccount.id == gist.github_account_id)
        return self.db.query(GitHubAccount).filter(*criteria).first()

    async def verify_secret_replacement(self, action: RemediationAction) -> bool:
        """
        Verify the original Gist is gone and its replacement is secret.

        Args:
            action: The remediation action to verify

        Returns:
            True if verification passed, False otherwise
        """
        finding = action.finding
        gist = finding.gist

        try:
            github_account = self._github_account_for_action(action)
            if not github_account:
                return False

            github_service = get_github_service_for_account(github_account)
            response = json.loads(action.github_response or "{}")
            replacement_id = response.get("replacement_gist_id")
            if not replacement_id:
                return False

            original_deleted = False
            try:
                await github_service.get_gist(gist.github_id)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    original_deleted = True
                else:
                    raise

            replacement = await github_service.get_gist(replacement_id)
            replacement_is_secret = not replacement.get("public", True)
            verified = original_deleted and replacement_is_secret

            action.verified = verified
            action.verified_at = datetime.now(timezone.utc)
            action.verification_details = json.dumps(
                {
                    "gist_id": gist.github_id,
                    "original_deleted": original_deleted,
                    "replacement_gist_id": replacement_id,
                    "replacement_is_secret": replacement_is_secret,
                    "verified_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            self.db.commit()

            if verified:
                await self.audit_service.log_event(
                    user_id=action.user_id,
                    event_type="remediation_verified",
                    event_description=(
                        f"Verified secret replacement for gist {gist.github_id}"
                    ),
                    details={"action_id": action.id, "gist_id": gist.github_id},
                )

            return verified

        except Exception as e:
            action.verified = False
            action.verified_at = datetime.now(timezone.utc)
            action.verification_details = json.dumps({"error": str(e)})
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
            github_account = self._github_account_for_action(action)
            if not github_account:
                return False

            github_service = get_github_service_for_account(github_account)

            try:
                await github_service.get_gist(gist.github_id)
                gist_exists = True
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 404:
                    raise
                gist_exists = False

            is_deleted = not gist_exists

            action.verified = is_deleted
            action.verified_at = datetime.now(timezone.utc)
            action.verification_details = json.dumps(
                {
                    "gist_id": gist.github_id,
                    "exists": gist_exists,
                    "verified_at": datetime.now(timezone.utc).isoformat(),
                }
            )
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
            action.verified_at = datetime.now(timezone.utc)
            action.verification_details = json.dumps({"error": str(e)})
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
        if action.action_type == "replace_with_secret":
            return await self.verify_secret_replacement(action)
        elif action.action_type == "delete":
            return await self.verify_delete(action)
        elif action.action_type == "rotate":
            # Rotation is intentionally a manual checklist; preserve its
            # instructions instead of claiming automated proof-of-fix.
            return False
        else:
            return False
