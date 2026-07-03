"""
Security middleware — headers, CSRF, request limits.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds standard security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Strict Transport Security — 1 year, include subdomains
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent page from being embedded (clickjacking)
        response.headers["X-Frame-Options"] = "DENY"

        # Referrer policy — no origin sent on cross-origin
        response.headers["Referrer-Policy"] = "no-referrer"

        # Permissions policy — disable unnecessary browser features
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        # Content Security Policy — restrictive baseline
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )

        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects requests exceeding a configurable body size limit."""

    def __init__(self, app, max_bytes: int = 10 * 1024 * 1024):  # 10 MB default
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")

        if content_length and int(content_length) > self.max_bytes:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )

        return await call_next(request)


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    Lightweight CSRF protection for state-changing endpoints.

    Requires a custom X-CSRF-Token header on POST/PUT/PATCH/DELETE
    that matches a session-based token. For API-first apps using
    Bearer tokens this is typically not needed, but provides defense
    in depth if cookies are ever used for auth.
    """

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
    EXEMPT_PATHS = {"/api/v1/auth/github/callback", "/health"}

    async def dispatch(self, request: Request, call_next):
        # Skip safe methods and exempt paths
        if request.method in self.SAFE_METHODS:
            return await call_next(request)

        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # For Bearer-token auth, CSRF is not applicable
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            return await call_next(request)

        # Check for CSRF token header on cookie-based requests
        csrf_token = request.headers.get("x-csrf-token")
        session_token = request.cookies.get("csrf_token")

        if session_token and csrf_token != session_token:
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token mismatch"},
            )

        return await call_next(request)
