"""
Audit service for logging user and system events.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from src.backend.db.models import AuditEvent


class AuditService:
    """Service for creating and querying audit events."""

    def __init__(self, db: Session):
        self.db = db

    async def log_event(
        self,
        user_id: int,
        event_type: str,
        event_description: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> AuditEvent:
        """
        Log an audit event.

        Args:
            user_id: The user who triggered the event
            event_type: Type of event (e.g., "login", "scan_start", "remediation_requested")
            event_description: Human-readable description
            ip_address: Optional IP address
            user_agent: Optional user agent string
            details: Optional additional details as JSON

        Returns:
            Created AuditEvent record
        """
        event = AuditEvent(
            user_id=user_id,
            event_type=event_type,
            event_description=event_description,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=datetime.utcnow(),
        )

        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)

        return event

    async def get_user_events(
        self, user_id: int, limit: int = 100, offset: int = 0
    ) -> list[AuditEvent]:
        """
        Get audit events for a user.

        Args:
            user_id: The user ID
            limit: Maximum number of events to return
            offset: Offset for pagination

        Returns:
            List of AuditEvent records
        """
        return (
            self.db.query(AuditEvent)
            .filter(AuditEvent.user_id == user_id)
            .order_by(AuditEvent.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    async def get_events_by_type(
        self, event_type: str, limit: int = 100, offset: int = 0
    ) -> list[AuditEvent]:
        """
        Get audit events by type.

        Args:
            event_type: The event type to filter by
            limit: Maximum number of events to return
            offset: Offset for pagination

        Returns:
            List of AuditEvent records
        """
        return (
            self.db.query(AuditEvent)
            .filter(AuditEvent.event_type == event_type)
            .order_by(AuditEvent.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
