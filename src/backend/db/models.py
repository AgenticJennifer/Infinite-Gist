"""Database models for Infinite Gist application."""

from __future__ import annotations

import enum
from datetime import date, datetime, timezone

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    """Return a timezone-aware timestamp for SQLAlchemy column defaults."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"


class FindingStatus(str, enum.Enum):
    NEW = "new"
    REVIEWING = "reviewing"
    ACCEPTED = "accepted"
    ESCALATED = "escalated"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(
        String, unique=True, index=True, nullable=False
    )
    full_name: Mapped[str | None] = mapped_column(String)
    hashed_password: Mapped[str | None] = mapped_column(String)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=True)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole), default=UserRole.USER, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_now, onupdate=_now, nullable=True
    )


class GitHubAccount(Base):
    __tablename__ = "github_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    github_id: Mapped[str] = mapped_column(
        String, unique=True, index=True, nullable=False
    )
    username: Mapped[str] = mapped_column(String, nullable=False)
    access_token_encrypted: Mapped[str] = mapped_column(String, nullable=False)
    refresh_token_encrypted: Mapped[str | None] = mapped_column(String)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    scope: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_now, onupdate=_now, nullable=True
    )

    user: Mapped[User] = relationship(backref="github_accounts")


class Gist(Base):
    __tablename__ = "gists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    github_id: Mapped[str] = mapped_column(
        String, unique=True, index=True, nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False, index=True
    )
    github_account_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("github_accounts.id"), index=True
    )
    description: Mapped[str | None] = mapped_column(Text)
    public: Mapped[bool] = mapped_column(Boolean, default=False, nullable=True)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(DateTime)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime)
    pushed_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_synced_at: Mapped[datetime] = mapped_column(
        DateTime, default=_now, nullable=True
    )

    user: Mapped[User] = relationship(backref="gists")
    github_account: Mapped[GitHubAccount | None] = relationship(backref="gists")


class GistFile(Base):
    __tablename__ = "gist_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    gist_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("gists.id"), nullable=False
    )
    filename: Mapped[str] = mapped_column(String, nullable=False)
    language: Mapped[str | None] = mapped_column(String)
    size: Mapped[int | None] = mapped_column(Integer)

    gist: Mapped[Gist] = relationship(backref="files")


class GistRevision(Base):
    __tablename__ = "gist_revisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    gist_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("gists.id"), nullable=False
    )
    version: Mapped[str] = mapped_column(String, nullable=False)
    committed_at: Mapped[datetime | None] = mapped_column(DateTime)

    gist: Mapped[Gist] = relationship(backref="revisions")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    gist_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("gists.id"), nullable=False, index=True
    )
    gist_file_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("gist_files.id")
    )
    gist_revision_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("gist_revisions.id")
    )

    file_path: Mapped[str | None] = mapped_column(String)
    line_start: Mapped[int | None] = mapped_column(Integer)
    line_end: Mapped[int | None] = mapped_column(Integer)
    content_snippet: Mapped[str | None] = mapped_column(Text)
    finding_type: Mapped[str | None] = mapped_column(String)
    secret_type: Mapped[str | None] = mapped_column(String)

    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), nullable=False)
    confidence: Mapped[int | None] = mapped_column(Integer)

    masked_value: Mapped[str | None] = mapped_column(String)
    value_hash: Mapped[str | None] = mapped_column(String, index=True)

    detected_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=True)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus), default=FindingStatus.NEW, nullable=True
    )

    gist: Mapped[Gist] = relationship(backref="findings")
    gist_file: Mapped[GistFile | None] = relationship(backref="findings")
    gist_revision: Mapped[GistRevision | None] = relationship(backref="findings")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str | None] = mapped_column(String)
    gists_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=True)

    user: Mapped[User] = relationship(backref="scan_runs")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    gist_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("gists.id"), nullable=False
    )
    scan_type: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, default="pending", nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    secrets_found: Mapped[int] = mapped_column(Integer, default=0, nullable=True)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text)

    gist: Mapped[Gist] = relationship(backref="scan_results")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), index=True
    )
    event_type: Mapped[str] = mapped_column(String, nullable=False, index=True)
    event_description: Mapped[str | None] = mapped_column(Text)
    details: Mapped[str | None] = mapped_column(Text)
    ip_address: Mapped[str | None] = mapped_column(String)
    user_agent: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=True)

    user: Mapped[User | None] = relationship(backref="audit_events")


class RemediationAction(Base):
    __tablename__ = "remediation_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    finding_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("findings.id"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    action_type: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(
        String, default="pending", index=True, nullable=True
    )

    requested_at: Mapped[datetime] = mapped_column(
        DateTime, default=_now, nullable=True
    )
    executed_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    github_response: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)

    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime)
    verification_details: Mapped[str | None] = mapped_column(Text)

    finding: Mapped[Finding] = relationship(backref="remediation_actions")
    user: Mapped[User] = relationship(backref="remediation_actions")


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    github_account_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("github_accounts.id"), nullable=False
    )
    frequency: Mapped[str] = mapped_column(String, nullable=False)
    cron_expression: Mapped[str | None] = mapped_column(String)
    enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, index=True, nullable=True
    )
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_now, onupdate=_now, nullable=True
    )

    user: Mapped[User] = relationship(backref="scan_schedules")
    github_account: Mapped[GitHubAccount] = relationship(backref="scan_schedules")


class AccountPolicy(Base):
    __tablename__ = "account_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False, unique=True
    )
    auto_remediate: Mapped[bool] = mapped_column(Boolean, default=False, nullable=True)
    auto_remediate_types: Mapped[str | None] = mapped_column(Text)
    notify_on_scan: Mapped[bool] = mapped_column(Boolean, default=True, nullable=True)
    notify_on_finding: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=True
    )
    digest_frequency: Mapped[str] = mapped_column(
        String, default="weekly", nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_now, onupdate=_now, nullable=True
    )

    user: Mapped[User] = relationship(backref="account_policies")


class SecurityTrend(Base):
    __tablename__ = "security_trends"
    __table_args__ = (UniqueConstraint("user_id", "date", name="uq_trend_user_date"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    date: Mapped[date] = mapped_column(Date, nullable=False)
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=True)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=True)
    high_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=True)
    medium_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=True)
    low_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=True)
    gists_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=True)
    remediated_count: Mapped[int] = mapped_column(Integer, default=0, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=True)

    user: Mapped[User] = relationship(backref="security_trends")


class DigestReport(Base):
    __tablename__ = "digest_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )
    report_type: Mapped[str] = mapped_column(String, nullable=False)
    period_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=True)

    user: Mapped[User] = relationship(backref="digest_reports")
