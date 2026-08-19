"""
Auto-remediation service for opt-in automatic remediation of findings.
"""

import logging
from sqlalchemy.orm import Session

from src.backend.db.models import Finding
from src.backend.services.policy_service import PolicyService
from src.backend.services.remediation_service import RemediationService
from src.backend.services.audit_service import AuditService
from src.backend.services.notification_service import NotificationService

logger = logging.getLogger(__name__)


class AutoRemediationService:
    """Service for opt-in automatic remediation of findings."""

    def __init__(self, db: Session):
        self.db = db
        self.policy_service = PolicyService(db)
        self.remediation_service = RemediationService(db)
        self.audit_service = AuditService(db)
        self.notification_service = NotificationService(db)

    async def check_and_remediate(self, finding: Finding, user_id: int):
        """
        Check policy and auto-remediate a finding if allowed.

        Args:
            finding: The Finding to potentially remediate
            user_id: The user ID

        Returns:
            RemediationAction if auto-remediated, None if not
        """
        finding_type = finding.finding_type or finding.secret_type or "unknown"

        should_remediate = await self.policy_service.should_auto_remediate(
            user_id, finding_type
        )

        if not should_remediate:
            return None

        try:
            action = await self.remediation_service.replace_with_secret(
                finding.id, user_id
            )

            await self.audit_service.log_event(
                user_id=user_id,
                event_type="auto_remediation_executed",
                event_description=(
                    f"Auto-remediated finding {finding.id} "
                    f"(type: {finding_type}) by replacing it with a secret Gist"
                ),
                details={"finding_id": finding.id, "finding_type": finding_type},
            )

            await self.notification_service.notify_remediation_complete(action)

            return action

        except Exception as e:
            logger.error(f"Auto-remediation failed for finding {finding.id}: {e}")
            await self.audit_service.log_event(
                user_id=user_id,
                event_type="auto_remediation_failed",
                event_description=(
                    f"Auto-remediation failed for finding {finding.id}: {str(e)}"
                ),
                details={"finding_id": finding.id, "error": str(e)},
            )
            return None

    async def batch_check_and_remediate(
        self, findings: list[Finding], user_id: int
    ) -> list[tuple]:
        """
        Check and auto-remediate a batch of findings.

        Args:
            findings: List of Findings to process
            user_id: The user ID

        Returns:
            List of (finding, action) tuples where action was taken
        """
        results = []

        processed_gists: set[int] = set()
        for finding in findings:
            if finding.gist_id in processed_gists:
                continue
            try:
                action = await self.check_and_remediate(finding, user_id)
                if action is not None:
                    results.append((finding, action))
                    processed_gists.add(finding.gist_id)
            except Exception as e:
                logger.error(
                    f"Batch auto-remediation failed for finding {finding.id}: {e}"
                )

        return results
