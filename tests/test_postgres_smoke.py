"""PostgreSQL-only schema smoke test run by the migration CI job."""

import os
from uuid import uuid4

import pytest

from src.backend.db.models import Finding, Gist, SeverityLevel, User
from src.backend.db.session import SessionLocal


pytestmark = pytest.mark.skipif(
    not os.getenv("DATABASE_URL", "").startswith("postgresql"),
    reason="PostgreSQL smoke test",
)


def test_postgres_schema_supports_cross_gist_fingerprints():
    db = SessionLocal()
    suffix = uuid4().hex
    try:
        user = User(email=f"ci-{suffix}@example.test", username=f"ci-{suffix}")
        db.add(user)
        db.flush()

        first = Gist(github_id=f"gist-a-{suffix}", user_id=user.id, public=True)
        second = Gist(github_id=f"gist-b-{suffix}", user_id=user.id, public=True)
        db.add_all([first, second])
        db.flush()

        db.add_all(
            [
                Finding(
                    gist_id=first.id,
                    severity=SeverityLevel.HIGH,
                    value_hash=f"fingerprint-{suffix}",
                ),
                Finding(
                    gist_id=second.id,
                    severity=SeverityLevel.HIGH,
                    value_hash=f"fingerprint-{suffix}",
                ),
            ]
        )
        db.commit()
    finally:
        db.rollback()
        db.close()
