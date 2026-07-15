"""
Minimal in-process rate limiting for sensitive endpoints.

Single-process, in-memory sliding window. Sufficient for the MVP's single
FastAPI worker; a multi-worker deployment would need a shared store (e.g.
Redis) instead.
"""

import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import Depends, HTTPException, Request, status

from src.backend.api.deps import get_current_active_user
from src.backend.db.models import User


class RateLimiter:
    """Sliding-window rate limiter keyed by an arbitrary string (e.g. user id)."""

    def __init__(self, max_calls: int, window_seconds: float):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self._calls: dict[str, deque] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            calls = self._calls[key]
            while calls and now - calls[0] > self.window_seconds:
                calls.popleft()
            if len(calls) >= self.max_calls:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Please slow down and try again shortly.",
                )
            calls.append(now)


# Destructive/irreversible remediation actions: at most 10 per user per minute.
remediation_rate_limiter = RateLimiter(max_calls=10, window_seconds=60)


def enforce_remediation_rate_limit(
    current_user: User = Depends(get_current_active_user),
) -> None:
    remediation_rate_limiter.check(str(current_user.id))


# Login endpoint: at most 20 attempts per client per minute.
# Brute-force / username-enumeration defense. Keyed by client IP (or the first
# X-Forwarded-For hop when behind a proxy) since no user is authenticated yet.
login_rate_limiter = RateLimiter(max_calls=20, window_seconds=60)


def enforce_login_rate_limit(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    key = forwarded.split(",")[0].strip() if forwarded else client
    login_rate_limiter.check(f"login:{key}")
