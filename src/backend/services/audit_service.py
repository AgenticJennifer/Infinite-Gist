"""
Audit service for logging user and system events.

Audit logs are critical for security compliance and incident response.
This service ensures events are persisted reliably with error handling
to prevent silent data loss.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session

from src.backend.db.models import AuditEvent

logger = logging.getLogger(__name__)


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
            details=json.dumps(details) if details is not None else None,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=datetime.now(timezone.utc),
        )

        self.db.add(event)
        
        # Flush to ensure the event is written to the DB session before commit.
        # This catches constraint violations and other DB errors early.
        try:
            self.db.flush()
        except Exception as e:
            logger.error(f"Failed to flush audit event: {e}")
            # Re-raise to let caller handle the failure
            raise

        try:
            self.db.commit()
            self.db.refresh(event)
        except Exception as e:
            logger.error(f"Failed to commit audit event: {e}")
            # Attempt rollback to maintain DB consistency
            try:
                self.db.rollback()
            except Exception:
                logger.error("Rollback also failed after audit commit error")
            raise

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
