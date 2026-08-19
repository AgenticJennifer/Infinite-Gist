"""
Phase 3 Remediation Service Tests
"""

import asyncio
import json
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime

import httpx
import pytest
from sqlalchemy.orm import Session

from src.backend.db.models import (
    SeverityLevel,
    FindingStatus,
)
from src.backend.services.remediation_service import RemediationService
from src.backend.services.remediation_verifier import RemediationVerifier
from src.backend.services.notification_service import NotificationService
from src.backend.services.audit_service import AuditService
from src.backend.core.config import settings


def _http_status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://api.github.com/gists/abc123")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError(
        f"HTTP {status_code}", request=request, response=response
    )


@pytest.fixture
def mock_db():
    return Mock(spec=Session)


@pytest.fixture
def mock_user():
    user = Mock()
    user.id = 1
    user.email = "test@example.com"
    user.username = "testuser"
    return user


@pytest.fixture
def mock_gist():
    gist = Mock()
    gist.id = 1
    gist.github_id = "abc123"
    gist.user_id = 1
    gist.public = True
    return gist


@pytest.fixture
def mock_finding(mock_gist):
    finding = Mock()
    finding.id = 1
    finding.gist_id = 1
    finding.gist = mock_gist
    finding.severity = SeverityLevel.HIGH
    finding.status = FindingStatus.NEW
    return finding


@pytest.fixture
def mock_github_account():
    account = Mock()
    account.id = 1
    account.user_id = 1
    account.access_token = "test_token"
    return account


class TestRemediationService:
    def test_replace_with_secret_success(
        self, mock_db, mock_user, mock_finding, mock_github_account
    ):
        mock_db.query.return_value.filter.return_value.first.side_effect = [
            mock_finding,
            mock_github_account,
        ]

        with patch(
            "src.backend.services.remediation_service.get_github_service_for_account"
        ) as mock_get_service:
            mock_github = AsyncMock()
            mock_github.replace_public_gist_with_secret.return_value = {
                "status": "replaced",
                "original_gist_id": "abc123",
                "replacement_gist_id": "secret123",
                "replacement_url": "https://gist.github.com/secret123",
                "public": False,
            }
            mock_get_service.return_value = mock_github

            service = RemediationService(mock_db)
            action = asyncio.run(service.replace_with_secret(finding_id=1, user_id=1))

            assert action.status == "completed"
            assert action.action_type == "replace_with_secret"
            assert "secret123" in action.github_response
            mock_github.replace_public_gist_with_secret.assert_called_once_with(
                "abc123"
            )

    def test_replace_with_secret_not_found(self, mock_db, mock_user):
        mock_db.query.return_value.filter.return_value.first.return_value = None

        service = RemediationService(mock_db)

        with pytest.raises(ValueError, match="Finding 999 not found"):
            asyncio.run(service.replace_with_secret(finding_id=999, user_id=1))

    def test_replace_with_secret_wrong_user(self, mock_db, mock_finding):
        mock_db.query.return_value.filter.return_value.first.return_value = mock_finding

        service = RemediationService(mock_db)

        with pytest.raises(PermissionError):
            asyncio.run(service.replace_with_secret(finding_id=1, user_id=999))

    def test_delete_gist_success(
        self, mock_db, mock_user, mock_finding, mock_github_account
    ):
        mock_db.query.return_value.filter.return_value.first.side_effect = [
            mock_finding,
            mock_github_account,
        ]

        with patch(
            "src.backend.services.remediation_service.get_github_service_for_account"
        ) as mock_get_service:
            mock_github = AsyncMock()
            mock_github.delete_gist.return_value = {"status": "deleted"}
            mock_get_service.return_value = mock_github

            service = RemediationService(mock_db)
            action = asyncio.run(service.delete_gist(finding_id=1, user_id=1))

            assert action.status == "completed"
            assert action.action_type == "delete"
            mock_github.delete_gist.assert_called_once_with("abc123")

    def test_rotate_secret_returns_manual_checklist(
        self, mock_db, mock_user, mock_finding
    ):
        mock_db.query.return_value.filter.return_value.first.return_value = mock_finding

        service = RemediationService(mock_db)
        action = asyncio.run(service.rotate_secret(finding_id=1, user_id=1))

        assert action.status == "manual_action_required"
        assert len(json.loads(action.verification_details)["instructions"]) == 3

    def test_get_action_status(self, mock_db):
        mock_action = Mock()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_action

        service = RemediationService(mock_db)
        result = asyncio.run(service.get_action_status(action_id=1, user_id=1))

        assert result == mock_action

    def test_get_user_actions(self, mock_db):
        mock_actions = [Mock(), Mock()]
        mock_db.query.return_value.filter.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = mock_actions

        service = RemediationService(mock_db)
        result = asyncio.run(service.get_user_actions(user_id=1))

        assert len(result) == 2


class TestRemediationVerifier:
    def test_verify_secret_replacement_success(
        self, mock_db, mock_finding, mock_github_account
    ):
        mock_action = Mock()
        mock_action.finding = mock_finding
        mock_action.user_id = 1
        mock_action.id = 1
        mock_action.github_response = json.dumps({"replacement_gist_id": "secret123"})

        mock_db.query.return_value.filter.return_value.first.return_value = (
            mock_github_account
        )

        with patch(
            "src.backend.services.remediation_verifier.get_github_service_for_account"
        ) as mock_get_service:
            mock_github = AsyncMock()
            mock_github.get_gist.side_effect = [
                _http_status_error(404),
                {"public": False},
            ]
            mock_get_service.return_value = mock_github

            verifier = RemediationVerifier(mock_db)
            result = asyncio.run(verifier.verify_secret_replacement(mock_action))

            assert result is True
            assert mock_action.verified is True

    def test_verify_secret_replacement_still_public(
        self, mock_db, mock_finding, mock_github_account
    ):
        mock_action = Mock()
        mock_action.finding = mock_finding
        mock_action.user_id = 1
        mock_action.id = 1
        mock_action.github_response = json.dumps({"replacement_gist_id": "secret123"})

        mock_db.query.return_value.filter.return_value.first.return_value = (
            mock_github_account
        )

        with patch(
            "src.backend.services.remediation_verifier.get_github_service_for_account"
        ) as mock_get_service:
            mock_github = AsyncMock()
            mock_github.get_gist.side_effect = [
                _http_status_error(404),
                {"public": True},
            ]
            mock_get_service.return_value = mock_github

            verifier = RemediationVerifier(mock_db)
            result = asyncio.run(verifier.verify_secret_replacement(mock_action))

            assert result is False
            assert mock_action.verified is False

    def test_verify_delete_success(self, mock_db, mock_finding, mock_github_account):
        mock_action = Mock()
        mock_action.finding = mock_finding
        mock_action.user_id = 1
        mock_action.id = 1

        mock_db.query.return_value.filter.return_value.first.return_value = (
            mock_github_account
        )

        with patch(
            "src.backend.services.remediation_verifier.get_github_service_for_account"
        ) as mock_get_service:
            mock_github = AsyncMock()
            mock_github.get_gist.side_effect = _http_status_error(404)
            mock_get_service.return_value = mock_github

            verifier = RemediationVerifier(mock_db)
            result = asyncio.run(verifier.verify_delete(mock_action))

            assert result is True
            assert mock_action.verified is True

    def test_verify_delete_does_not_treat_transport_error_as_deleted(
        self, mock_db, mock_finding, mock_github_account
    ):
        mock_action = Mock(finding=mock_finding, user_id=1, id=1)
        mock_db.query.return_value.filter.return_value.first.return_value = (
            mock_github_account
        )
        with patch(
            "src.backend.services.remediation_verifier.get_github_service_for_account"
        ) as mock_get_service:
            mock_github = AsyncMock()
            mock_github.get_gist.side_effect = httpx.ConnectTimeout("timed out")
            mock_get_service.return_value = mock_github

            result = asyncio.run(
                RemediationVerifier(mock_db).verify_delete(mock_action)
            )

        assert result is False
        assert mock_action.verified is False

    def test_verify_action_dispatches_correctly(
        self, mock_db, mock_finding, mock_github_account
    ):
        mock_action = Mock()
        mock_action.action_type = "replace_with_secret"
        mock_action.finding = mock_finding
        mock_action.user_id = 1
        mock_action.id = 1
        mock_action.github_response = json.dumps({"replacement_gist_id": "secret123"})

        mock_db.query.return_value.filter.return_value.first.return_value = (
            mock_github_account
        )

        with patch(
            "src.backend.services.remediation_verifier.get_github_service_for_account"
        ) as mock_get_service:
            mock_github = AsyncMock()
            mock_github.get_gist.side_effect = [
                _http_status_error(404),
                {"public": False},
            ]
            mock_get_service.return_value = mock_github

            verifier = RemediationVerifier(mock_db)
            result = asyncio.run(verifier.verify_action(mock_action))

            assert result is True


class TestNotificationService:
    def test_send_email(self, mock_db):
        service = NotificationService(mock_db)
        with (
            patch.object(settings, "SMTP_HOST", "smtp.example.test"),
            patch.object(settings, "SMTP_FROM_EMAIL", "alerts@example.test"),
            patch.object(settings, "SMTP_STARTTLS", False),
            patch("src.backend.services.notification_service.smtplib.SMTP") as smtp,
        ):
            result = asyncio.run(service.send_email("test@example.com", "Test", "Body"))

        assert result is True
        smtp.return_value.__enter__.return_value.send_message.assert_called_once()

    def test_send_email_reports_unconfigured_delivery(self, mock_db):
        service = NotificationService(mock_db)
        with patch.object(settings, "SMTP_HOST", ""):
            result = asyncio.run(service.send_email("test@example.com", "Test", "Body"))

        assert result is False

    def test_send_webhook(self, mock_db):
        service = NotificationService(mock_db)
        response = Mock()
        response.raise_for_status.return_value = None
        client = AsyncMock()
        client.__aenter__.return_value = client
        client.__aexit__.return_value = None
        client.post.return_value = response
        with (
            patch.object(service, "_validate_webhook_url", new=AsyncMock()),
            patch(
                "src.backend.services.notification_service.httpx.AsyncClient",
                return_value=client,
            ),
        ):
            result = asyncio.run(
                service.send_webhook("https://example.com", {"event": "test"})
            )

        assert result is True

    def test_notify_remediation_complete(self, mock_db):
        mock_action = Mock()
        mock_action.user = Mock()
        mock_action.user.email = "test@example.com"
        mock_action.finding = Mock()
        mock_action.finding.github_id = "abc123"
        mock_action.finding.severity = "high"
        mock_action.completed_at = datetime.utcnow()
        mock_action.status = "completed"

        service = NotificationService(mock_db)
        service.send_email = AsyncMock(return_value=True)
        result = asyncio.run(service.notify_remediation_complete(mock_action))

        assert result is True
        service.send_email.assert_awaited_once()

    def test_notify_remediation_failed(self, mock_db):
        mock_action = Mock()
        mock_action.user = Mock()
        mock_action.user.email = "test@example.com"
        mock_action.finding = Mock()
        mock_action.finding.github_id = "abc123"
        mock_action.error_message = "API rate limit"
        mock_action.completed_at = datetime.utcnow()

        service = NotificationService(mock_db)
        service.send_email = AsyncMock(return_value=True)
        result = asyncio.run(service.notify_remediation_failed(mock_action))

        assert result is True
        service.send_email.assert_awaited_once()


class TestAuditService:
    def test_log_event(self, mock_db):
        service = AuditService(mock_db)
        event = asyncio.run(
            service.log_event(
                user_id=1,
                event_type="test_event",
                event_description="Test description",
            )
        )

        assert event is not None
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()

    def test_get_user_events(self, mock_db):
        mock_events = [Mock(), Mock()]
        mock_db.query.return_value.filter.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = mock_events

        service = AuditService(mock_db)
        events = asyncio.run(service.get_user_events(user_id=1))

        assert len(events) == 2

    def test_get_events_by_type(self, mock_db):
        mock_events = [Mock()]
        mock_db.query.return_value.filter.return_value.order_by.return_value.offset.return_value.limit.return_value.all.return_value = mock_events

        service = AuditService(mock_db)
        events = asyncio.run(service.get_events_by_type(event_type="login"))

        assert len(events) == 1
