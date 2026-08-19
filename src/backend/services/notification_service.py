"""Notification delivery for remediation actions and security digests."""

import asyncio
import ipaddress
import logging
import smtplib
import socket
import ssl
from email.message import EmailMessage
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from src.backend.core.config import settings
from src.backend.db.models import Finding, RemediationAction, ScanRun, User

logger = logging.getLogger(__name__)


class NotificationService:
    """Service for sending notifications about remediation events."""

    def __init__(self, db: Session):
        self.db = db

    async def send_email(self, to: str, subject: str, body: str) -> bool:
        """Deliver an email through configured SMTP, returning actual outcome."""
        if not settings.SMTP_HOST or not settings.SMTP_FROM_EMAIL:
            logger.warning("SMTP is not configured; notification was not delivered")
            return False

        message = EmailMessage()
        message["From"] = settings.SMTP_FROM_EMAIL
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)

        try:
            await asyncio.to_thread(self._send_smtp, message)
            return True
        except (OSError, smtplib.SMTPException):
            logger.exception("SMTP delivery failed for %s", to)
            return False

    @staticmethod
    def _send_smtp(message: EmailMessage) -> None:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as client:
            client.ehlo()
            if settings.SMTP_STARTTLS:
                client.starttls(context=ssl.create_default_context())
                client.ehlo()
            if settings.SMTP_USERNAME:
                client.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            client.send_message(message)

    async def send_webhook(self, url: str, payload: dict) -> bool:
        """POST to a public HTTPS webhook without following redirects."""
        try:
            await self._validate_webhook_url(url)
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
            return True
        except (ValueError, OSError, httpx.HTTPError):
            logger.exception("Webhook delivery failed")
            return False

    @staticmethod
    async def _validate_webhook_url(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username:
            raise ValueError("Webhook URL must be an unauthenticated HTTPS URL")

        loop = asyncio.get_running_loop()
        addresses = await loop.getaddrinfo(
            parsed.hostname,
            parsed.port or 443,
            type=socket.SOCK_STREAM,
        )
        if not addresses:
            raise ValueError("Webhook host did not resolve")
        for address in addresses:
            if not ipaddress.ip_address(address[4][0]).is_global:
                raise ValueError("Webhook URL resolves to a non-public address")

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

        if not user.email:
            return False
        return await self.send_email(user.email, subject, body)

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

        if not user.email:
            return False
        return await self.send_email(user.email, subject, body)

    async def notify_scan_complete(self, user: User, scan_run: ScanRun) -> bool:
        """Notify a user that a scan finished without including finding evidence."""
        if not user.email:
            return False
        subject = "Infinite Gist: Scan Complete"
        body = (
            f"Scan #{scan_run.id} completed.\n\n"
            f"Gists scanned: {scan_run.gists_scanned}\n"
            f"Findings detected: {scan_run.findings_count}\n"
        )
        return await self.send_email(user.email, subject, body)

    async def notify_new_findings(self, user: User, findings: list[Finding]) -> bool:
        """Send one aggregate alert for newly persisted findings."""
        if not user.email or not findings:
            return False
        severity_counts: dict[str, int] = {}
        for finding in findings:
            severity = getattr(finding.severity, "value", finding.severity)
            severity_counts[str(severity)] = severity_counts.get(str(severity), 0) + 1
        breakdown = ", ".join(
            f"{severity}: {count}"
            for severity, count in sorted(severity_counts.items())
        )
        subject = f"Infinite Gist: {len(findings)} New Finding(s)"
        body = (
            f"A scan detected {len(findings)} new finding(s).\n\n"
            f"Severity counts: {breakdown}\n"
            "Open Infinite Gist to review masked evidence and remediation options.\n"
        )
        return await self.send_email(user.email, subject, body)
