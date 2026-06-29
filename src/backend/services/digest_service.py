"""
Digest service for generating security scan reports.
"""

import json
import logging
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from src.backend.db.models import Finding, DigestReport, User, RemediationAction, ScanRun
from src.backend.services.notification_service import NotificationService

logger = logging.getLogger(__name__)


class DigestService:
    """Service for generating and sending digest reports."""

    def __init__(self, db: Session):
        self.db = db
        self.notification_service = NotificationService(db)

    async def generate_daily_digest(self, user_id: int) -> DigestReport:
        """
        Generate a daily digest report.

        Args:
            user_id: The user ID

        Returns:
            Created DigestReport record
        """
        now = datetime.utcnow()
        period_start = now - timedelta(days=1)

        new_findings = (
            self.db.query(Finding)
            .filter(Finding.detected_at >= period_start)
            .count()
        )

        remediated = (
            self.db.query(RemediationAction)
            .filter(
                RemediationAction.user_id == user_id,
                RemediationAction.completed_at >= period_start,
                RemediationAction.status == "completed",
            )
            .count()
        )

        critical = (
            self.db.query(Finding)
            .filter(
                Finding.detected_at >= period_start,
                Finding.severity == "critical",
            )
            .count()
        )

        scanned = (
            self.db.query(ScanRun)
            .filter(
                ScanRun.user_id == user_id,
                ScanRun.started_at >= period_start,
                ScanRun.status == "completed",
            )
            .count()
        )

        summary = json.dumps({
            "period": f"{period_start.isoformat()} to {now.isoformat()}",
            "new_findings": new_findings,
            "remediated_findings": remediated,
            "critical_findings": critical,
            "gists_scanned": scanned,
        })

        report = DigestReport(
            user_id=user_id,
            report_type="daily",
            period_start=period_start,
            period_end=now,
            summary=summary,
            created_at=now,
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)

        return report

    async def generate_weekly_digest(self, user_id: int) -> DigestReport:
        """
        Generate a weekly digest report.

        Args:
            user_id: The user ID

        Returns:
            Created DigestReport record
        """
        now = datetime.utcnow()
        period_start = now - timedelta(days=7)

        new_findings = (
            self.db.query(Finding)
            .filter(Finding.detected_at >= period_start)
            .count()
        )

        remediated = (
            self.db.query(RemediationAction)
            .filter(
                RemediationAction.user_id == user_id,
                RemediationAction.completed_at >= period_start,
                RemediationAction.status == "completed",
            )
            .count()
        )

        critical = (
            self.db.query(Finding)
            .filter(
                Finding.detected_at >= period_start,
                Finding.severity == "critical",
            )
            .count()
        )

        scanned = (
            self.db.query(ScanRun)
            .filter(
                ScanRun.user_id == user_id,
                ScanRun.started_at >= period_start,
                ScanRun.status == "completed",
            )
            .count()
        )

        summary = json.dumps({
            "period": f"{period_start.isoformat()} to {now.isoformat()}",
            "new_findings": new_findings,
            "remediated_findings": remediated,
            "critical_findings": critical,
            "gists_scanned": scanned,
        })

        report = DigestReport(
            user_id=user_id,
            report_type="weekly",
            period_start=period_start,
            period_end=now,
            summary=summary,
            created_at=now,
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)

        return report

    async def send_digest(self, report: DigestReport, user_email: str) -> bool:
        """
        Send a digest report via email.

        Args:
            report: The DigestReport to send
            user_email: Recipient email address

        Returns:
            True if sent successfully
        """
        subject = f"Infinite Gist: {report.report_type.capitalize()} Security Digest"
        body = f"Security digest for period {report.period_start} to {report.period_end}.\n\n{report.summary}"

        await self.notification_service.send_email(user_email, subject, body)

        report.sent_at = datetime.utcnow()
        self.db.commit()

        return True

    async def get_user_digests(self, user_id: int, limit: int = 30) -> list[DigestReport]:
        """
        Get recent digest reports for a user.

        Args:
            user_id: The user ID
            limit: Maximum number of reports to return

        Returns:
            List of DigestReport records
        """
        return (
            self.db.query(DigestReport)
            .filter(DigestReport.user_id == user_id)
            .order_by(DigestReport.created_at.desc())
            .limit(limit)
            .all()
        )
