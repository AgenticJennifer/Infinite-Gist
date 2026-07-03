"""
Trend service for tracking security posture over time.
"""

import logging
from datetime import datetime, date, timedelta
from sqlalchemy.orm import Session

from src.backend.db.models import Finding, SecurityTrend, RemediationAction

logger = logging.getLogger(__name__)


class TrendService:
    """Service for recording and analyzing security posture trends."""

    def __init__(self, db: Session):
        self.db = db

    async def record_daily_snapshot(self, user_id: int) -> SecurityTrend:
        """
        Record a daily security snapshot for a user.

        Args:
            user_id: The user ID

        Returns:
            Created SecurityTrend record
        """
        today = date.today()

        total_findings = self.db.query(Finding).filter(
            Finding.gist.has(user_id=user_id)
        ).count()

        critical_findings = self.db.query(Finding).filter(
            Finding.gist.has(user_id=user_id),
            Finding.severity == "critical",
        ).count()

        high_findings = self.db.query(Finding).filter(
            Finding.gist.has(user_id=user_id),
            Finding.severity == "high",
        ).count()

        medium_findings = self.db.query(Finding).filter(
            Finding.gist.has(user_id=user_id),
            Finding.severity == "medium",
        ).count()

        low_findings = self.db.query(Finding).filter(
            Finding.gist.has(user_id=user_id),
            Finding.severity == "low",
        ).count()

        remediated = self.db.query(RemediationAction).filter(
            RemediationAction.user_id == user_id,
            RemediationAction.status == "completed",
        ).count()

        trend = SecurityTrend(
            user_id=user_id,
            date=today,
            total_findings=total_findings,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            remediated_count=remediated,
            created_at=datetime.utcnow(),
        )
        self.db.add(trend)
        self.db.commit()
        self.db.refresh(trend)

        return trend

    async def get_trends(self, user_id: int, days: int = 30) -> list[SecurityTrend]:
        """
        Get security trends for a user over the last N days.

        Args:
            user_id: The user ID
            days: Number of days to look back

        Returns:
            List of SecurityTrend records ordered by date
        """
        cutoff = date.today() - timedelta(days=days)
        return (
            self.db.query(SecurityTrend)
            .filter(
                SecurityTrend.user_id == user_id,
                SecurityTrend.date >= cutoff,
            )
            .order_by(SecurityTrend.date)
            .all()
        )

    async def get_posture_summary(self, user_id: int) -> dict:
        """
        Get a summary of the user's current security posture.

        Args:
            user_id: The user ID

        Returns:
            Dict with current counts and trend direction
        """
        trends = await self.get_trends(user_id, days=30)

        if not trends:
            direction = "stable"
            latest = {
                "total_findings": 0,
                "critical_findings": 0,
                "high_findings": 0,
                "medium_findings": 0,
                "low_findings": 0,
            }
        else:
            latest_trend = trends[-1]
            latest = {
                "total_findings": latest_trend.total_findings,
                "critical_findings": latest_trend.critical_findings,
                "high_findings": latest_trend.high_findings,
                "medium_findings": latest_trend.medium_findings,
                "low_findings": latest_trend.low_findings,
            }
            direction = await self.calculate_trend_direction(user_id)

        return {
            "current_total": latest["total_findings"],
            "critical": latest["critical_findings"],
            "high": latest["high_findings"],
            "medium": latest["medium_findings"],
            "low": latest["low_findings"],
            "direction": direction,
        }

    async def calculate_trend_direction(self, user_id: int) -> str:
        """
        Calculate whether the user's security posture is improving, stable, or degrading.

        Compares the average findings in the last 7 days vs the 7 days before that.

        Args:
            user_id: The user ID

        Returns:
            "improving", "stable", or "degrading"
        """
        today = date.today()

        recent_start = today - timedelta(days=7)
        older_start = today - timedelta(days=14)

        recent_trends = (
            self.db.query(SecurityTrend)
            .filter(
                SecurityTrend.user_id == user_id,
                SecurityTrend.date >= recent_start,
            )
            .all()
        )

        older_trends = (
            self.db.query(SecurityTrend)
            .filter(
                SecurityTrend.user_id == user_id,
                SecurityTrend.date >= older_start,
                SecurityTrend.date < recent_start,
            )
            .all()
        )

        if not recent_trends and not older_trends:
            return "stable"

        recent_avg = (
            sum(t.total_findings for t in recent_trends) / len(recent_trends)
            if recent_trends
            else 0
        )

        older_avg = (
            sum(t.total_findings for t in older_trends) / len(older_trends)
            if older_trends
            else 0
        )

        if recent_avg < older_avg:
            return "improving"
        elif recent_avg > older_avg:
            return "degrading"
        else:
            return "stable"
