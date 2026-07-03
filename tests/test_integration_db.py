"""
Integration tests — database operations with a real SQLite DB.
"""

import sys
import os
import pytest
from datetime import datetime

# Ensure project root is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from src.backend.db.models import (
    Base, User, GitHubAccount, Gist, GistFile, Finding,
    SeverityLevel, FindingStatus, UserRole,
)
from src.backend.services.secret_scanner import SecretScanner, scan_content
from src.backend.services.severity_scorer import SeverityScorer
from src.backend.services.evidence_masker import EvidenceMasker


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def engine():
    """Create an in-memory SQLite engine for the test module."""
    eng = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    """Yield a transactional session that rolls back after each test."""
    connection = engine.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection)()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


# ── User & Auth Tests ──────────────────────────────────────────────────────

class TestUserOperations:
    def test_create_user(self, db):
        user = User(
            email="test@example.com",
            username="testuser",
            full_name="Test User",
            is_active=True,
            role=UserRole.USER,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        assert user.id is not None
        assert user.email == "test@example.com"
        assert user.role == UserRole.USER

    def test_user_unique_constraints(self, db):
        u1 = User(email="dup@test.com", username="user1", is_active=True)
        u2 = User(email="dup@test.com", username="user2", is_active=True)
        db.add(u1)
        db.commit()

        db.add(u2)
        with pytest.raises(Exception):  # IntegrityError
            db.commit()

    def test_github_account_link(self, db):
        user = User(email="gh@test.com", username="ghuser", is_active=True)
        db.add(user)
        db.commit()

        account = GitHubAccount(
            user_id=user.id,
            github_id="12345",
            username="ghuser",
            access_token_encrypted="encrypted_token",
        )
        db.add(account)
        db.commit()
        db.refresh(account)

        assert account.id is not None
        assert account.user_id == user.id


# ── Gist & Finding Tests ───────────────────────────────────────────────────

class TestGistAndFindingOperations:
    def _make_user(self, db):
        user = User(email="gist@test.com", username="gistuser", is_active=True)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    def test_create_gist(self, db):
        user = self._make_user(db)
        gist = Gist(
            github_id="gist_001",
            user_id=user.id,
            description="Test gist",
            public=True,
        )
        db.add(gist)
        db.commit()
        db.refresh(gist)

        assert gist.id is not None
        assert gist.github_id == "gist_001"

    def test_create_finding_with_severity(self, db):
        user = self._make_user(db)
        gist = Gist(github_id="gist_002", user_id=user.id, public=True)
        db.add(gist)
        db.commit()
        db.refresh(gist)

        finding = Finding(
            gist_id=gist.id,
            file_path="config.py",
            line_start=10,
            line_end=10,
            content_snippet="API_KEY = \"sk-...\"",
            finding_type="api_key",
            secret_type="api_key",
            severity=SeverityLevel.HIGH,
            confidence=85,
            masked_value="sk-****",
            value_hash="abc123hash",
            detected_at=datetime.utcnow(),
            status=FindingStatus.NEW,
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)

        assert finding.id is not None
        assert finding.severity == SeverityLevel.HIGH
        assert finding.status == FindingStatus.NEW

    def test_finding_status_transitions(self, db):
        user = self._make_user(db)
        gist = Gist(github_id="gist_003", user_id=user.id, public=True)
        db.add(gist)
        db.commit()
        db.refresh(gist)

        finding = Finding(
            gist_id=gist.id,
            severity=SeverityLevel.CRITICAL,
            confidence=95,
            value_hash="transition_hash",
            detected_at=datetime.utcnow(),
            status=FindingStatus.NEW,
        )
        db.add(finding)
        db.commit()

        # Simulate triage workflow
        finding.status = FindingStatus.REVIEWING
        db.commit()
        assert finding.status == FindingStatus.REVIEWING

        finding.status = FindingStatus.FIXED
        db.commit()
        assert finding.status == FindingStatus.FIXED


# ── Scanner Integration Tests ──────────────────────────────────────────────

class TestScannerIntegration:
    def test_secret_scanner_detects_aws_key(self):
        content = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\nAWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        matches = scan_content(content, "config.py")

        assert len(matches) > 0
        types = [m["type"] for m in matches]
        assert "aws_access_key" in types

    def test_secret_scanner_detects_github_token(self):
        content = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12"'
        matches = scan_content(content, ".env")

        types = [m["type"] for m in matches]
        assert "github_token" in types

    def test_secret_scanner_masks_values(self):
        content = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12"'
        matches = scan_content(content, ".env")

        for m in matches:
            # Raw value should never appear in output
            assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12" not in m["value"]
            # Masked value should contain asterisks
            assert "****" in m["value"]

    def test_secret_scanner_skips_examples(self):
        content = 'example_key = "AKIAIOSFODNN7EXAMPLE"'
        matches = scan_content(content, "README.md")

        # Example/sample keys should be filtered out
        # (The ignore pattern checks for "example" in matched text)
        aws_matches = [m for m in matches if m["type"] == "aws_access_key"]
        assert len(aws_matches) == 0


# ── Evidence Masker Tests ──────────────────────────────────────────────────

class TestEvidenceMasker:
    def test_mask_preserves_format(self):
        masker = EvidenceMasker()
        secret = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
        masked = masker.mask_value(secret)

        assert masked != secret
        assert "****" in masked
        # Should preserve prefix pattern
        assert masked.startswith("sk-")

    def test_mask_short_secret(self):
        masker = EvidenceMasker()
        secret = "key123"
        masked = masker.mask_value(secret)

        assert "****" in masked
        assert len(masked) < len(secret) + 10  # Reasonable length


# ── Severity Scorer Tests ──────────────────────────────────────────────────

class TestSeverityScorer:
    def test_private_key_is_critical(self):
        scorer = SeverityScorer()
        from src.backend.services.secret_scanner import SecretMatch, SecretType

        match = SecretMatch(
            type=SecretType.PRIVATE_KEY,
            value="-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
            file_path="server.key",
            line_number=1,
            column_start=0,
            column_end=31,
            confidence=0.95,
            matched_text="-----BEGIN RSA PRIVATE KEY-----",
            context="-----BEGIN RSA PRIVATE KEY-----",
        )
        severity, conf = scorer.score(match)
        assert severity.value == "critical"

    def test_email_is_low(self):
        scorer = SeverityScorer()
        from src.backend.services.secret_scanner import SecretMatch, SecretType

        match = SecretMatch(
            type=SecretType.EMAIL,
            value="user@example.com",
            file_path="README.md",
            line_number=5,
            column_start=0,
            column_end=16,
            confidence=0.8,
            matched_text="user@example.com",
            context="Contact: user@example.com",
        )
        severity, conf = scorer.score(match)
        assert severity.value == "low"


# ── Audit Trail Tests ──────────────────────────────────────────────────────

class TestAuditTrail:
    def test_create_audit_event(self, db):
        from src.backend.db.models import AuditEvent

        user = User(email="audit@test.com", username="audituser", is_active=True)
        db.add(user)
        db.commit()

        event = AuditEvent(
            user_id=user.id,
            event_type="finding.status_changed",
            event_description="Finding marked as fixed",
            details='{"finding_id": 1, "old_status": "new", "new_status": "fixed"}',
            ip_address="127.0.0.1",
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        assert event.id is not None
        assert event.event_type == "finding.status_changed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
