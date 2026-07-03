"""
Notification service for sending alerts about remediation actions.
"""

from sqlalchemy.orm import Session

from src.backend.db.models import (
    RemediationAction,
)


class NotificationService:
    """Service for sending notifications about remediation events."""

    def __init__(self, db: Session):
        self.db = db

    async def send_email(self, to: str, subject: str, body: str) -> bool:
        """
        Send email notification (stub).

        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body

        Returns:
            True if sent successfully
        """
        print(f"[NOTIFICATION] Email to {to}: {subject}")
        return True

    async def send_webhook(self, url: str, payload: dict) -> bool:
        """
        Send webhook notification (stub).

        Args:
            url: Webhook URL
            payload: JSON payload to send

        Returns:
            True if sent successfully
        """
        print(f"[NOTIFICATION] Webhook to {url}: {payload}")
        return True

    async def notify_remediation_complete(self, action: RemediationAction) -> bool:
        """
        Send notification when remediation completes.

        Args:
            action: The completed remediation action

        Returns:
            True if notification sent successfully
        """
        user = action.user
        finding = action.finding
        gist = finding.gist

        subject = f"Infinite Gist: Remediation {action.status}"
        body = f"""
Remediation action {action.status}.

Action Type: {action.action_type}
Gist: {gist.github_id}
Finding: {finding.id}
Severity: {finding.severity}
Time: {action.completed_at}
"""

        if user.email:
            await self.send_email(user.email, subject, body)

        return True

    async def notify_remediation_failed(self, action: RemediationAction) -> bool:
        """
        Send notification when remediation fails.

        Args:
            action: The failed remediation action

        Returns:
            True if notification sent successfully
        """
        user = action.user
        finding = action.finding
        gist = finding.gist

        subject = "Infinite Gist: Remediation Failed"
        body = f"""
Remediation action failed.

Action Type: {action.action_type}
Gist: {gist.github_id}
Finding: {finding.id}
Error: {action.error_message}
Time: {action.completed_at}
"""

        if user.email:
            await self.send_email(user.email, subject, body)

        return True
