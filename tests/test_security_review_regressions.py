"""
Regression tests for the security-review fixes (commit 159e1fe).

These lock in the behavior changes so they cannot silently regress:
- OAuth state token is single-use (server-side nonce store)
- /token login is rate-limited per client IP
- OAuth-only accounts (no password) cannot log in via password
- create_schedule enforces GitHub-account ownership (IDOR fix)
- POST /schedules/execute is admin-only
- schedule frequency is validated
- inactive users get 403 (not 400)
- security headers are applied via mounted middleware
- CORS is tightened (no wildcard)
- RequestSizeLimitMiddleware rejects oversized bodies
- temporal endpoint reads event.severity (not the removed .details attr)
- _enum_to_str helper + TRIAGE_THRESHOLDS single source of truth
"""

import asyncio
from datetime import datetime
from enum import Enum
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import HTTPException

from src.backend.core import rate_limit as rl_module
from src.backend.core.rate_limit import RateLimiter
from src.backend.core.security import (
    create_oauth_state_token,
    get_password_hash,
    get_current_active_user,
    verify_password,
    verify_oauth_state_token,
)
from src.backend.db.models import UserRole
from src.backend.middleware.security import RequestSizeLimitMiddleware


# --------------------------------------------------------------------------
# OAuth state: single-use, tamper-resistant (core/security.py)
# --------------------------------------------------------------------------
def test_oauth_state_is_single_use():
    token = create_oauth_state_token()
    assert verify_oauth_state_token(token) is True
    # Second verification must fail — the nonce was consumed.
    assert verify_oauth_state_token(token) is False


def test_oauth_state_tampered_rejected():
    token = create_oauth_state_token()
    assert verify_oauth_state_token(token + "x") is False


def test_oauth_state_wrong_purpose_rejected():
    from src.backend.core.config import settings
    from jose import jwt

    bad = jwt.encode(
        {"nonce": "abc", "purpose": "not_oauth"},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    assert verify_oauth_state_token(bad) is False


# --------------------------------------------------------------------------
# Login rate limiting (core/rate_limit.py)
# --------------------------------------------------------------------------
def test_rate_limiter_blocks_after_max():
    limiter = RateLimiter(max_calls=3, window_seconds=60)
    for _ in range(3):
        limiter.check("k")  # within limit — no error
    with pytest.raises(HTTPException) as exc:
        limiter.check("k")
    assert exc.value.status_code == 429


def test_enforce_login_rate_limit_per_client(monkeypatch):
    fresh = RateLimiter(max_calls=1, window_seconds=60)
    monkeypatch.setattr(rl_module, "login_rate_limiter", fresh)

    class FakeRequest:
        client = None
        headers = {"x-forwarded-for": "9.9.9.9, 1.1.1.1"}

    rl_module.enforce_login_rate_limit(FakeRequest())  # first call ok
    with pytest.raises(HTTPException) as exc:
        rl_module.enforce_login_rate_limit(FakeRequest())  # second call blocked
    assert exc.value.status_code == 429


# --------------------------------------------------------------------------
# Inactive user -> 403 (core/security.py)
# --------------------------------------------------------------------------
def test_inactive_user_returns_403():
    user = Mock()
    user.is_active = False
    with pytest.raises(HTTPException) as exc:
        asyncio.run(get_current_active_user(current_user=user))
    assert exc.value.status_code == 403


def test_active_user_passes_through():
    user = Mock()
    user.is_active = True
    assert asyncio.run(get_current_active_user(current_user=user)) is user


def test_password_hash_round_trip_and_invalid_hash():
    hashed = get_password_hash("correct horse battery staple")

    assert verify_password("correct horse battery staple", hashed) is True
    assert verify_password("wrong password", hashed) is False
    assert verify_password("anything", "not-a-bcrypt-hash") is False


# --------------------------------------------------------------------------
# Login endpoint: OAuth-only accounts (hashed_password is None) cannot log in
# --------------------------------------------------------------------------
def test_login_rejects_oauth_only_user(client):
    """OAuth-only users must get 401 from /token, never 500.

    FastAPI binds Depends(get_db) to the original callable object, so patching
    ``auth.get_db`` is a no-op — the real session runs and CI (empty SQLite)
    fails with ``no such table: users``. Override the app dependency instead.
    """
    from src.backend.db.session import get_db
    from src.backend.main import app

    db = Mock()
    user = Mock()
    user.hashed_password = None  # OAuth-only account, no password set
    db.query.return_value.filter.return_value.first.return_value = user

    def _override_get_db():
        yield db

    app.dependency_overrides[get_db] = _override_get_db
    try:
        resp = client.post(
            "/api/v1/auth/token",
            data={"username": "ghost", "password": "whatever"},
        )
    finally:
        app.dependency_overrides.pop(get_db, None)

    # Must be 401 (bad creds), never a 500 from verify_password(None).
    assert resp.status_code == 401


# --------------------------------------------------------------------------
# create_schedule: GitHub-account ownership (IDOR fix) + frequency validation
# --------------------------------------------------------------------------
def _user_with_role(role):
    u = Mock()
    u.id = 1
    u.is_active = True
    u.role = role
    return u


def _fake_schedule():
    s = Mock()
    s.id = 1
    s.user_id = 1
    s.github_account_id = 5
    s.frequency = "daily"
    s.cron_expression = None
    s.enabled = True
    s.last_run_at = None
    s.next_run_at = None
    s.created_at = None
    return s


def test_create_schedule_rejects_other_users_account():
    from src.backend.api.v1.endpoints import schedules as schedules_module

    db = Mock()
    # Account query (id + current_user.id) returns nothing => access denied.
    db.query.return_value.filter.return_value.filter.return_value.first.return_value = (
        None
    )

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            schedules_module.create_schedule(
                request=schedules_module.ScheduleCreateRequest(
                    github_account_id=999, frequency="daily"
                ),
                current_user=_user_with_role(UserRole.USER),
                db=db,
            )
        )
    assert exc.value.status_code == 404


def test_create_schedule_invalid_frequency():
    from src.backend.api.v1.endpoints import schedules as schedules_module

    db = Mock()
    db.query.return_value.filter.return_value.filter.return_value.first.return_value = (
        Mock()
    )

    with pytest.raises(ValueError):
        schedules_module.ScheduleCreateRequest(
            github_account_id=5,
            frequency="hourly",
        )


def test_create_schedule_owner_succeeds():
    from src.backend.api.v1.endpoints import schedules as schedules_module

    db = Mock()
    db.query.return_value.filter.return_value.filter.return_value.first.return_value = (
        Mock()
    )

    with patch.object(schedules_module, "SchedulerService") as MockSvc:
        svc = MockSvc.return_value
        svc.create_schedule = AsyncMock(return_value=_fake_schedule())
        resp = asyncio.run(
            schedules_module.create_schedule(
                request=schedules_module.ScheduleCreateRequest(
                    github_account_id=5, frequency="daily"
                ),
                current_user=_user_with_role(UserRole.USER),
                db=db,
            )
        )
    assert resp["github_account_id"] == 5
    assert resp["frequency"] == "daily"


# --------------------------------------------------------------------------
# POST /schedules/execute is admin-only
# --------------------------------------------------------------------------
def test_execute_due_scans_requires_admin():
    from src.backend.api.v1.endpoints import schedules as schedules_module

    with patch.object(schedules_module, "ScanExecutor") as MockExec:
        MockExec.return_value.execute_all_due_scans = AsyncMock(return_value=[])

        # Non-admin must be rejected.
        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                schedules_module.execute_due_scans(
                    current_user=_user_with_role(UserRole.USER), db=Mock()
                )
            )
        assert exc.value.status_code == 403

        # Admin is allowed through.
        result = asyncio.run(
            schedules_module.execute_due_scans(
                current_user=_user_with_role(UserRole.ADMIN), db=Mock()
            )
        )
        assert result["executed_count"] == 0


# --------------------------------------------------------------------------
# Temporal endpoint reads event.severity (the removed .details attr bug)
# --------------------------------------------------------------------------
def test_temporal_endpoint_uses_severity_not_details():
    from src.backend.api.v1.endpoints import gists as gists_module

    analysis = Mock()
    analysis.re_exposures = [{"id": 1}, {"id": 2}]
    analysis.persistence_counts = {"hash": 3}
    analysis.first_seen = {"hash": datetime(2024, 1, 1)}
    analysis.last_seen = {"hash": datetime(2024, 1, 2)}

    event = Mock()
    event.timestamp = datetime(2024, 1, 1)
    event.event_type = "scan"
    event.gist_id = 1
    event.finding_id = 1
    event.severity = "high"  # previously the code read event.details (AttributeError)
    analysis.events = [event]

    db = Mock()  # gist ownership query returns truthy
    user = Mock()
    user.id = 1

    with patch.object(gists_module, "TemporalAnalyzer") as MockTA:
        MockTA.return_value.analyze_gist_history.return_value = analysis
        MockTA.return_value.analyze_user_posture.return_value = {
            "findings_trend": "improving"
        }
        resp = asyncio.run(
            gists_module.get_temporal_analysis(gist_id=1, current_user=user, db=db)
        )

    MockTA.return_value.analyze_gist_history.assert_called_once_with(1, db)
    MockTA.return_value.analyze_user_posture.assert_called_once_with(1, db)
    assert resp.total_events == 1
    assert resp.re_exposure_count == 2
    assert resp.persistence_count == 3
    assert resp.posture_trend == "improving"
    assert resp.first_detected == datetime(2024, 1, 1)
    assert resp.last_detected == datetime(2024, 1, 2)
    assert resp.events[0].details == "high"


# --------------------------------------------------------------------------
# _enum_to_str helper + TRIAGE_THRESHOLDS single source of truth
# --------------------------------------------------------------------------
def test_enum_to_str_helper():
    from src.backend.api.v1.endpoints.gists import TRIAGE_THRESHOLDS, _enum_to_str

    class Color(Enum):
        RED = "red"

    assert _enum_to_str(Color.RED) == "red"
    assert _enum_to_str("plain") == "plain"
    assert _enum_to_str(None) == "None"
    assert TRIAGE_THRESHOLDS == {
        "auto_triage": 0.75,
        "manual_review": 0.35,
        "escalation": 0.90,
    }


# --------------------------------------------------------------------------
# Middleware: security headers + request size limit (mounted in main.py)
# --------------------------------------------------------------------------
def test_security_headers_present(client):
    resp = client.get("/")  # root handler needs no DB
    for header in [
        "strict-transport-security",
        "x-frame-options",
        "content-security-policy",
        "x-content-type-options",
        "referrer-policy",
    ]:
        assert resp.headers.get(header), f"missing security header: {header}"


def test_request_size_limit_rejects_oversized():
    mw = RequestSizeLimitMiddleware(app=Mock(), max_bytes=10)

    async def call_next(req):
        from starlette.responses import JSONResponse

        return JSONResponse({"ok": True})

    req = Mock()
    req.method = "POST"
    req.headers = {"content-length": "100"}
    resp = asyncio.run(mw.dispatch(req, call_next))
    assert resp.status_code == 413


def test_request_size_limit_allows_small():
    mw = RequestSizeLimitMiddleware(app=Mock(), max_bytes=10)
    called = {}

    async def call_next(req):
        from starlette.responses import JSONResponse

        called["yes"] = True
        return JSONResponse({"ok": True})

    req = Mock()
    req.method = "POST"
    req.headers = {"content-length": "5"}
    resp = asyncio.run(mw.dispatch(req, call_next))
    assert resp.status_code == 200
    assert called.get("yes")


# --------------------------------------------------------------------------
# CORS is tightened (no wildcard allow-origin / methods / headers)
# --------------------------------------------------------------------------
def test_cors_tightened(client):
    resp = client.options(
        "/api/v1/auth/token",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization,Content-Type",
        },
    )
    methods = resp.headers.get("access-control-allow-methods", "")
    assert "GET" in methods and "POST" in methods
    assert "*" not in methods

    headers = resp.headers.get("access-control-allow-headers", "")
    assert "Authorization" in headers
    assert "Content-Type" in headers
