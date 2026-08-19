"""Regression tests for real GitHub, browser, API, and persistence contracts."""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.backend.api.deps import get_current_active_user
from src.backend.api.v1.endpoints.auth import github_callback
from src.backend.core.config import Settings
from src.backend.core.security import create_access_token
from src.backend.db.models import (
    AccountPolicy,
    Base,
    DigestReport,
    Gist,
    GistFile,
    GistRevision,
    GitHubAccount,
    Finding,
    FindingStatus,
    ScanRun,
    SeverityLevel,
    User,
)
from src.backend.db.session import get_db
from src.backend.main import app
from src.backend.services.gist_scanner import GistScannerService
from src.backend.services.github_service import GitHubService
from src.backend.services.digest_service import DigestService
from src.backend.services.notification_service import NotificationService
from src.backend.services.scan_executor import ScanExecutor


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)


def test_account_scan_fetches_full_gist_and_real_revision_without_plaintext(db):
    token = "ghp_" + "R" * 36
    user = User(email="scan@example.test", username="scanner")
    db.add(user)
    db.flush()
    account = GitHubAccount(
        user_id=user.id,
        github_id="github-user-1",
        username="scanner",
        access_token_encrypted="unused-in-test",
    )
    db.add(account)
    db.commit()

    github = Mock()
    github.get_user_gists = AsyncMock(
        return_value=[
            {
                "id": "gist-1",
                "files": {"config.py": {"filename": "config.py", "size": 12}},
            }
        ]
    )
    github.get_gist = AsyncMock(
        return_value={
            "id": "gist-1",
            "public": True,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
            "files": {
                "config.py": {
                    "filename": "config.py",
                    "size": 15,
                    "content": "print('clean')",
                    "truncated": False,
                }
            },
        }
    )
    github.get_gist_commits = AsyncMock(
        return_value=[{"version": "old-sha", "committed_at": "2026-01-01T00:00:00Z"}]
    )
    github.get_gist_revision = AsyncMock(
        return_value={
            "files": {
                "config.py": {
                    "filename": "config.py",
                    "content": f'github_token = "{token}"',
                    "truncated": False,
                }
            }
        }
    )
    github.get_complete_files = AsyncMock(
        side_effect=lambda gist_data, revision=None: gist_data.get("files", {})
    )

    with (
        patch(
            "src.backend.services.gist_scanner.get_github_service_for_account",
            return_value=github,
        ),
        patch("src.backend.services.gist_scanner.settings.ENABLE_TRUFFLEHOG", False),
    ):
        findings = asyncio.run(GistScannerService(db).scan_github_account(account.id))

    assert github.get_gist.await_args.args == ("gist-1",)
    assert github.get_gist_revision.await_args.args == ("gist-1", "old-sha")
    assert len(findings) == 1
    assert findings[0].gist_revision_id is not None
    assert token not in (findings[0].content_snippet or "")
    assert token not in (findings[0].masked_value or "")
    assert not hasattr(db.query(GistFile).one(), "content")
    assert db.query(GistRevision).one().version == "old-sha"


def test_gist_routes_serialize_the_persisted_model(db):
    user = User(email="api@example.test", username="api-user")
    db.add(user)
    db.flush()
    db.add(Gist(github_id="gist-route", user_id=user.id, public=True))
    db.commit()

    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_active_user] = lambda: user
    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/gists/gists")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()[0]["github_id"] == "gist-route"
    assert response.json()[0]["deleted"] is False


def test_browser_workflows_match_backend_contracts_with_cookie_auth(db):
    user = User(
        email="workflow@example.test",
        username="workflow-user",
        is_active=True,
    )
    db.add(user)
    db.flush()
    account = GitHubAccount(
        user_id=user.id,
        github_id="workflow-github-id",
        username="workflow-user",
        access_token_encrypted="encrypted-token-must-not-leak",
        scope="gist,user:email",
    )
    gist = Gist(github_id="workflow-gist", user_id=user.id, public=True)
    db.add_all([account, gist])
    db.flush()
    finding = Finding(
        gist_id=gist.id,
        finding_type="github_token",
        secret_type="github_token",
        severity=SeverityLevel.HIGH,
        confidence=95,
        masked_value="ghp_****test",
        value_hash="workflow-hash",
        status=FindingStatus.NEW,
    )
    db.add(finding)
    db.commit()

    app.dependency_overrides[get_db] = lambda: db
    try:
        with TestClient(app) as client:
            client.cookies.set(
                "session_token", create_access_token({"sub": user.username})
            )
            client.cookies.set("csrf_token", "workflow-csrf")
            headers = {"X-CSRF-Token": "workflow-csrf"}

            accounts = client.get("/api/v1/auth/github/accounts")
            assert accounts.status_code == 200
            assert accounts.json() == [
                {
                    "id": account.id,
                    "github_id": "workflow-github-id",
                    "username": "workflow-user",
                    "scope": "gist,user:email",
                }
            ]
            assert "encrypted" not in accounts.text

            blocked = client.post(
                "/api/v1/schedules/",
                json={"github_account_id": account.id, "frequency": "daily"},
            )
            assert blocked.status_code == 403

            schedule = client.post(
                "/api/v1/schedules/",
                headers=headers,
                json={"github_account_id": account.id, "frequency": "daily"},
            )
            assert schedule.status_code == 200
            assert schedule.json()["github_account_id"] == account.id
            assert schedule.json()["frequency"] == "daily"

            policy = client.put(
                "/api/v1/policies/",
                headers=headers,
                json={
                    "auto_remediate": False,
                    "auto_remediate_types": ["github_token"],
                    "notify_on_scan": True,
                    "notify_on_finding": True,
                    "digest_frequency": "daily",
                },
            )
            assert policy.status_code == 200
            assert policy.json()["auto_remediate_types"] == ["github_token"]

            digest = client.post("/api/v1/digests/generate", headers=headers)
            assert digest.status_code == 200
            assert digest.json()["report_type"] == "daily"
            assert digest.json()["period_start"]

            trend = client.post("/api/v1/trends/snapshot", headers=headers)
            assert trend.status_code == 200
            assert trend.json()["total_findings"] == 1

            unconfirmed = client.post(
                "/api/v1/remediation/replace-with-secret",
                headers=headers,
                json={
                    "finding_id": finding.id,
                    "confirm_url_and_history_change": False,
                },
            )
            assert unconfirmed.status_code == 400

            rotation = client.post(
                "/api/v1/remediation/rotate",
                headers=headers,
                json={"finding_id": finding.id},
            )
            assert rotation.status_code == 200
            assert rotation.json()["status"] == "manual_action_required"
            assert len(rotation.json()["details"]["instructions"]) == 3
    finally:
        app.dependency_overrides.clear()


def test_post_scan_policies_send_aggregate_notifications(db):
    user = User(email="policy@example.test", username="policy-user")
    db.add(user)
    db.flush()
    db.add(
        AccountPolicy(
            user_id=user.id,
            auto_remediate=False,
            auto_remediate_types="[]",
            notify_on_scan=True,
            notify_on_finding=True,
            digest_frequency="never",
        )
    )
    scan_run = ScanRun(
        user_id=user.id,
        status="completed",
        gists_scanned=1,
        findings_count=1,
    )
    db.add(scan_run)
    db.commit()
    finding = Mock(severity="high", gist_id=1)

    with (
        patch.object(
            NotificationService,
            "notify_new_findings",
            new=AsyncMock(return_value=True),
        ) as finding_notice,
        patch.object(
            NotificationService,
            "notify_scan_complete",
            new=AsyncMock(return_value=True),
        ) as scan_notice,
    ):
        asyncio.run(
            ScanExecutor(db)._apply_post_scan_policies(user.id, [finding], scan_run)
        )

    finding_notice.assert_awaited_once()
    scan_notice.assert_awaited_once()


def test_due_digest_is_delivered_once_per_policy_interval(db):
    user = User(email="digest@example.test", username="digest-user")
    db.add(user)
    db.flush()
    db.add(
        AccountPolicy(
            user_id=user.id,
            auto_remediate=False,
            auto_remediate_types="[]",
            notify_on_scan=False,
            notify_on_finding=False,
            digest_frequency="daily",
        )
    )
    db.commit()
    service = DigestService(db)
    service.notification_service.send_email = AsyncMock(return_value=True)

    first = asyncio.run(service.send_due_digests())
    second = asyncio.run(service.send_due_digests())

    assert len(first) == 1
    assert second == []
    assert db.query(DigestReport).count() == 1
    assert db.query(DigestReport).one().sent_at is not None


def test_oauth_callback_sets_an_httponly_session_cookie(db):
    token_response = Mock(status_code=200)
    token_response.json.return_value = {
        "access_token": "github-token",
        "scope": "gist,user:email",
    }
    user_response = Mock(status_code=200)
    user_response.json.return_value = {"id": 1, "login": "octocat"}
    email_response = Mock(status_code=200)
    email_response.json.return_value = [
        {"email": "octocat@example.test", "primary": True, "verified": True}
    ]

    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.post.return_value = token_response
    client.get.side_effect = [user_response, email_response]

    with (
        patch(
            "src.backend.api.v1.endpoints.auth.httpx.AsyncClient", return_value=client
        ),
        patch(
            "src.backend.api.v1.endpoints.auth.verify_oauth_state_token",
            return_value=True,
        ),
        patch(
            "src.backend.api.v1.endpoints.auth.encrypt_token", return_value="encrypted"
        ),
        patch(
            "src.backend.api.v1.endpoints.auth.create_access_token",
            return_value="session-token",
        ),
    ):
        response = asyncio.run(github_callback(code="code", state="state", db=db))

    assert response.status_code == 303
    assert response.headers["location"].endswith("/#/dashboard")
    cookies = response.headers.getlist("set-cookie")
    assert any("session_token=session-token" in cookie for cookie in cookies)
    assert any("HttpOnly" in cookie for cookie in cookies if "session_token" in cookie)
    assert all("session-token" not in response.headers["location"] for _ in [0])
    assert db.query(GitHubAccount).one().scope == "gist,user:email"


def test_secret_replacement_returns_only_allowlisted_metadata():
    raw_secret = "ghp_" + "S" * 36
    service = GitHubService("token")
    service.get_gist = AsyncMock(
        return_value={
            "description": "example",
            "files": {"config.py": {"content": raw_secret}},
        }
    )
    service.get_file_content = AsyncMock(return_value=raw_secret)
    service.delete_gist = AsyncMock(return_value={"status": "deleted"})

    create_response = Mock()
    create_response.raise_for_status.return_value = None
    create_response.json.return_value = {
        "id": "secret-gist",
        "html_url": "https://gist.github.com/secret-gist",
        "public": False,
        "files": {"config.py": {"content": raw_secret}},
    }
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.post.return_value = create_response

    with patch(
        "src.backend.services.github_service.httpx.AsyncClient", return_value=client
    ):
        result = asyncio.run(service.replace_public_gist_with_secret("public-gist"))

    assert result["replacement_gist_id"] == "secret-gist"
    assert result["public"] is False
    assert raw_secret not in repr(result)
    service.delete_gist.assert_awaited_once_with("public-gist")


def test_raw_gist_fetch_rejects_untrusted_hosts():
    service = GitHubService("token")
    with pytest.raises(ValueError, match="untrusted"):
        asyncio.run(
            service.get_file_content(
                {
                    "content": "partial",
                    "truncated": True,
                    "raw_url": "https://attacker.example/secret",
                }
            )
        )


def test_truncated_gist_uses_authenticated_clone_fallback():
    service = GitHubService("token")
    service._clone_gist_files = AsyncMock(
        return_value={"large.txt": {"content": "complete", "truncated": False}}
    )

    result = asyncio.run(
        service.get_complete_files(
            {
                "truncated": True,
                "git_pull_url": "https://gist.github.com/example.git",
            },
            revision="deadbeef",
        )
    )

    assert result["large.txt"]["content"] == "complete"
    service._clone_gist_files.assert_awaited_once()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("SECRET_KEY", "change-this-to-a-random-secret-key"),
        ("ENCRYPTION_KEY", "not-a-fernet-key"),
    ],
)
def test_security_configuration_rejects_placeholders(field, value):
    valid = {
        "SECRET_KEY": "s" * 48,
        "ENCRYPTION_KEY": "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
    }
    valid[field] = value
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **valid)
