"""
Database models for Infinite Gist application.
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Date, Time, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import enum


Base = declarative_base()


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

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    role = Column(Enum(UserRole), default=UserRole.USER)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class GitHubAccount(Base):
    __tablename__ = "github_accounts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    github_id = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, nullable=False)
    access_token_encrypted = Column(String, nullable=False)  # Encrypted access token
    refresh_token_encrypted = Column(String)  # Encrypted refresh token
    token_expires_at = Column(DateTime)
    scope = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user = relationship("User", backref="github_accounts")


class Gist(Base):
    __tablename__ = "gists"

    id = Column(Integer, primary_key=True, index=True)
    github_id = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    description = Column(Text)
    public = Column(Boolean, default=False)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    pushed_at = Column(DateTime)
    last_synced_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    user = relationship("User", backref="gists")


class GistFile(Base):
    __tablename__ = "gist_files"

    id = Column(Integer, primary_key=True, index=True)
    gist_id = Column(Integer, ForeignKey("gists.id"), nullable=False)
    filename = Column(String, nullable=False)
    content = Column(Text)
    language = Column(String)
    size = Column(Integer)
    
    # Relationship
    gist = relationship("Gist", backref="files")


class GistRevision(Base):
    __tablename__ = "gist_revisions"

    id = Column(Integer, primary_key=True, index=True)
    gist_id = Column(Integer, ForeignKey("gists.id"), nullable=False)
    version = Column(String, nullable=False)  # GitHub uses SHA for versions
    committed_at = Column(DateTime)
    # We'll store file contents for each revision or just reference them
    
    # Relationship
    gist = relationship("Gist", backref="revisions")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    gist_id = Column(Integer, ForeignKey("gists.id"), nullable=False)
    gist_file_id = Column(Integer, ForeignKey("gist_files.id"))
    gist_revision_id = Column(Integer, ForeignKey("gist_revisions.id"))
    
    # Finding details
    file_path = Column(String)
    line_start = Column(Integer)
    line_end = Column(Integer)
    content_snippet = Column(Text)  # Limited excerpt for context
    finding_type = Column(String)  # e.g., "aws_key", "private_key", "password"
    secret_type = Column(String)  # More specific categorization
    
    # Risk assessment
    severity = Column(Enum(SeverityLevel), nullable=False)
    confidence = Column(Integer)  # 0-100
    
    # Evidence (masked for security)
    masked_value = Column(String)  # First/last chars with asterisks in middle
    value_hash = Column(String, unique=True, index=True)  # Hash of original for deduplication
    
    # Metadata
    detected_at = Column(DateTime, default=datetime.utcnow)
    status = Column(Enum(FindingStatus), default=FindingStatus.NEW)
    
    # Relationships
    gist = relationship("Gist", backref="findings")
    gist_file = relationship("GistFile", backref="findings")
    gist_revision = relationship("GistRevision", backref="findings")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime)
    status = Column(String)  # "running", "completed", "failed"
    gists_scanned = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    
    # Relationship
    user = relationship("User", backref="scan_runs")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    gist_id = Column(Integer, ForeignKey("gists.id"), nullable=False)
    scan_type = Column(String, nullable=False)
    status = Column(String, default="pending")
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    secrets_found = Column(Integer, default=0)
    files_scanned = Column(Integer, default=0)
    error_message = Column(Text)

    # Relationship
    gist = relationship("Gist", backref="scan_results")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    event_type = Column(String, nullable=False)
    event_description = Column(Text)
    ip_address = Column(String)
    user_agent = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", backref="audit_events")


class RemediationAction(Base):
    __tablename__ = "remediation_actions"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action_type = Column(String, nullable=False)
    status = Column(String, default="pending")

    requested_at = Column(DateTime, default=datetime.utcnow)
    executed_at = Column(DateTime)
    completed_at = Column(DateTime)

    github_response = Column(Text)
    error_message = Column(Text)

    verified = Column(Boolean, default=False)
    verified_at = Column(DateTime)
    verification_details = Column(Text)

    finding = relationship("Finding", backref="remediation_actions")
    user = relationship("User", backref="remediation_actions")


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    github_account_id = Column(Integer, ForeignKey("github_accounts.id"), nullable=False)
    frequency = Column(String, nullable=False)  # "daily", "weekly", "custom"
    cron_expression = Column(String)
    enabled = Column(Boolean, default=True)
    last_run_at = Column(DateTime)
    next_run_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", backref="scan_schedules")
    github_account = relationship("GitHubAccount", backref="scan_schedules")


class AccountPolicy(Base):
    __tablename__ = "account_policies"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True)
    auto_remediate = Column(Boolean, default=False)
    auto_remediate_types = Column(Text)  # JSON array of finding types
    notify_on_scan = Column(Boolean, default=True)
    notify_on_finding = Column(Boolean, default=True)
    digest_frequency = Column(String, default="weekly")  # "daily", "weekly", "none"
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", backref="account_policies")


class SecurityTrend(Base):
    __tablename__ = "security_trends"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    date = Column(Date, nullable=False)
    total_findings = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    gists_scanned = Column(Integer, default=0)
    remediated_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", backref="security_trends")


class DigestReport(Base):
    __tablename__ = "digest_reports"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    report_type = Column(String, nullable=False)  # "daily", "weekly"
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    summary = Column(Text)  # JSON summary string
    sent_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", backref="digest_reports")