from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class FindingStatus(str, enum.Enum):
    open = "open"
    triaged = "triaged"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"
    remediation_recommended = "remediation_recommended"
    remediation_in_progress = "remediation_in_progress"
    fixed_pending_verification = "fixed_pending_verification"
    verified_fixed = "verified_fixed"
    partially_fixed = "partially_fixed"
    suppressed_by_policy = "suppressed_by_policy"
    reopened = "reopened"


class Presence(str, enum.Enum):
    current = "current"
    history_only = "history_only"
    current_and_history = "current_and_history"
    absent = "absent"


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    partial = "partial"


class AuditEventType(str, enum.Enum):
    user_created = "user_created"
    github_account_connected = "github_account_connected"
    scan_started = "scan_started"
    scan_completed = "scan_completed"
    scan_failed = "scan_failed"
    finding_created = "finding_created"
    finding_updated = "finding_updated"
    finding_status_changed = "finding_status_changed"
    evidence_revealed = "evidence_revealed"
    verification_started = "verification_started"
    verification_completed = "verification_completed"
    export_created = "export_created"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    display_name: Mapped[str] = mapped_column(String(255), default="Local User")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    github_accounts: Mapped[list[GitHubAccount]] = relationship(back_populates="user")


class GitHubAccount(Base):
    __tablename__ = "github_accounts"
    __table_args__ = (UniqueConstraint("user_id", "github_login", name="uq_github_account_user_login"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    github_login: Mapped[str] = mapped_column(String(255), index=True)
    github_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    token_encrypted: Mapped[str] = mapped_column(Text)
    scopes: Mapped[str] = mapped_column(String(512), default="")
    connected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_authenticated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="github_accounts")
    gists: Mapped[list[Gist]] = relationship(back_populates="github_account")
    scan_runs: Mapped[list[ScanRun]] = relationship(back_populates="github_account")


class Gist(Base):
    __tablename__ = "gists"
    __table_args__ = (UniqueConstraint("github_account_id", "github_gist_id", name="uq_gist_account_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    github_account_id: Mapped[int] = mapped_column(ForeignKey("github_accounts.id"), index=True)
    github_gist_id: Mapped[str] = mapped_column(String(128), index=True)
    owner_login: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    html_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    public: Mapped[bool] = mapped_column(Boolean, default=False)
    files_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at_remote: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at_remote: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    github_account: Mapped[GitHubAccount] = relationship(back_populates="gists")
    revisions: Mapped[list[GistRevision]] = relationship(back_populates="gist")
    findings: Mapped[list[Finding]] = relationship(back_populates="gist")


class GistRevision(Base):
    __tablename__ = "gist_revisions"
    __table_args__ = (UniqueConstraint("gist_id", "revision_sha", name="uq_gist_revision"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    gist_id: Mapped[int] = mapped_column(ForeignKey("gists.id"), index=True)
    revision_sha: Mapped[str] = mapped_column(String(128), index=True)
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    files_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    gist: Mapped[Gist] = relationship(back_populates="revisions")


class DetectorRule(Base):
    __tablename__ = "detector_rules"
    __table_args__ = (UniqueConstraint("detector_id", "version", name="uq_detector_rule_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    detector_id: Mapped[str] = mapped_column(String(128), index=True)
    version: Mapped[str] = mapped_column(String(64))
    finding_type: Mapped[str] = mapped_column(String(128))
    default_severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.medium)
    description: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SecretFingerprint(Base):
    __tablename__ = "secret_fingerprints"
    __table_args__ = (UniqueConstraint("hmac_sha256", name="uq_secret_fingerprint_hmac"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hmac_sha256: Mapped[str] = mapped_column(String(64), index=True)
    secret_family: Mapped[str] = mapped_column(String(128))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    findings: Mapped[list[Finding]] = relationship(back_populates="fingerprint")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "github_account_id",
            "gist_id",
            "file_path",
            "detector_id",
            "fingerprint_id",
            name="uq_finding_identity",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    stable_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    github_account_id: Mapped[int] = mapped_column(ForeignKey("github_accounts.id"), index=True)
    gist_id: Mapped[int] = mapped_column(ForeignKey("gists.id"), index=True)
    fingerprint_id: Mapped[int] = mapped_column(ForeignKey("secret_fingerprints.id"), index=True)
    detector_id: Mapped[str] = mapped_column(String(128), index=True)
    detector_version: Mapped[str] = mapped_column(String(64))
    finding_type: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), index=True)
    confidence: Mapped[int] = mapped_column(Integer)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.open, index=True)
    presence: Mapped[Presence] = mapped_column(Enum(Presence), default=Presence.current, index=True)
    file_path: Mapped[str] = mapped_column(Text)
    line_start: Mapped[int] = mapped_column(Integer, default=1)
    line_end: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_result: Mapped[str | None] = mapped_column(String(128), nullable=True)
    remediation_recommendation: Mapped[str] = mapped_column(Text)
    residual_risk: Mapped[str | None] = mapped_column(Text, nullable=True)
    validity_state: Mapped[str] = mapped_column(String(128), default="unverified")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    gist: Mapped[Gist] = relationship(back_populates="findings")
    fingerprint: Mapped[SecretFingerprint] = relationship(back_populates="findings")
    evidences: Mapped[list[FindingEvidence]] = relationship(back_populates="finding", cascade="all, delete-orphan")
    transitions: Mapped[list[FindingStateTransition]] = relationship(back_populates="finding", cascade="all, delete-orphan")
    verification_attempts: Mapped[list[VerificationAttempt]] = relationship(back_populates="finding")


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "revision_sha",
            "file_path",
            "line_start",
            "line_end",
            "masked_preview",
            name="uq_finding_evidence_location",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    gist_revision_id: Mapped[int | None] = mapped_column(ForeignKey("gist_revisions.id"), nullable=True, index=True)
    revision_sha: Mapped[str] = mapped_column(String(128), index=True)
    file_path: Mapped[str] = mapped_column(Text)
    line_start: Mapped[int] = mapped_column(Integer)
    line_end: Mapped[int] = mapped_column(Integer)
    masked_preview: Mapped[str] = mapped_column(Text)
    context_excerpt: Mapped[str] = mapped_column(Text)
    explanation: Mapped[str] = mapped_column(Text)
    is_current: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="evidences")


class FindingStateTransition(Base):
    __tablename__ = "finding_state_transitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    from_status: Mapped[str | None] = mapped_column(String(128), nullable=True)
    to_status: Mapped[str] = mapped_column(String(128))
    actor: Mapped[str] = mapped_column(String(255), default="system")
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="transitions")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    github_account_id: Mapped[int] = mapped_column(ForeignKey("github_accounts.id"), index=True)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.queued, index=True)
    scan_type: Mapped[str] = mapped_column(String(64), default="manual")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    gists_seen: Mapped[int] = mapped_column(Integer, default=0)
    revisions_seen: Mapped[int] = mapped_column(Integer, default=0)
    findings_created: Mapped[int] = mapped_column(Integer, default=0)
    findings_updated: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    github_account: Mapped[GitHubAccount] = relationship(back_populates="scan_runs")


class VerificationAttempt(Base):
    __tablename__ = "verification_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    scan_run_id: Mapped[int | None] = mapped_column(ForeignKey("scan_runs.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(128), default="started")
    result: Mapped[str | None] = mapped_column(String(128), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    verifier_version: Mapped[str] = mapped_column(String(64), default="v1")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    finding: Mapped[Finding] = relationship(back_populates="verification_attempts")


class NotificationEvent(Base):
    __tablename__ = "notification_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    channel: Mapped[str] = mapped_column(String(64))
    destination_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload_summary: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(64), default="queued")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    github_account_id: Mapped[int | None] = mapped_column(ForeignKey("github_accounts.id"), nullable=True, index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True, index=True)
    event_type: Mapped[AuditEventType] = mapped_column(Enum(AuditEventType), index=True)
    actor: Mapped[str] = mapped_column(String(255), default="system")
    summary: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class EvidenceAccessEvent(Base):
    __tablename__ = "evidence_access_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    actor: Mapped[str] = mapped_column(String(255), default="user")
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    revealed_raw_secret: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExportJob(Base):
    __tablename__ = "export_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    format: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(64), default="completed")
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
