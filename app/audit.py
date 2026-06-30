from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditEvent, AuditEventType


def write_audit_event(
    db: Session,
    event_type: AuditEventType,
    summary: str,
    *,
    user_id: int | None = None,
    github_account_id: int | None = None,
    finding_id: int | None = None,
    actor: str = "system",
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        user_id=user_id,
        github_account_id=github_account_id,
        finding_id=finding_id,
        event_type=event_type,
        actor=actor,
        summary=summary,
        metadata_json=metadata or {},
    )
    db.add(event)
    return event
