"""
ASGI Security Middleware for Chainlit - Story S-12

Provides comprehensive security headers and WebSocket origin validation:
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-* policies (COOP, COEP, CORP)
- WebSocket origin pinning
"""

import os
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse

# Environment configuration
PUBLIC_ORIGIN = os.getenv("PUBLIC_ORIGIN", "").rstrip("/")
ALLOWED_ORIGINS = [PUBLIC_ORIGIN] if PUBLIC_ORIGIN else []
CSP_MODE = os.getenv("CSP_MODE", "compatible")  # "compatible" or "strict"
HSTS_MAX_AGE = int(os.getenv("HSTS_MAX_AGE", "31536000"))  # 1 year default


def _build_csp() -> str:
    """
    Build Content-Security-Policy header based on CSP_MODE.

    Returns:
        CSP header value string
    """
    if CSP_MODE == "strict":
        # Strict CSP (may require UI tweaks if Chainlit uses inline scripts/eval)
        return (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            f"connect-src 'self' {PUBLIC_ORIGIN} wss: https:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "form-action 'self'"
        )

    # Compatible CSP for Chainlit UI (allows inline/eval used by some frontends)
    return (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        f"connect-src 'self' {PUBLIC_ORIGIN} wss: https:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "form-action 'self'"
    )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware that adds security headers and validates WebSocket origin.

    Security Features:
    1. WebSocket Origin Pinning: Reject WS upgrades from untrusted origins
    2. Host Header Validation: Ensure Host matches PUBLIC_ORIGIN
    3. Security Response Headers: CSP, HSTS, XFO, and more

    Defense-in-depth: Works even if Load Balancer misconfigured.
    """

    async def dispatch(self, request, call_next):
        """
        Process request and add security headers to response.

        Args:
            request: Starlette Request object
            call_next: Next middleware in chain

        Returns:
            Response with security headers or 403 if validation fails
        """
        scope = request.scope
        headers = dict(request.headers)
        origin = headers.get("origin")
        host = headers.get("host")

        # WebSocket origin pinning
        if (
            scope["type"] == "http"
            and headers.get("upgrade", "").lower() == "websocket"
        ):
            # Check Origin header against allowed list
            if ALLOWED_ORIGINS and origin not in ALLOWED_ORIGINS:
                return PlainTextResponse(
                    f"Forbidden: WebSocket origin '{origin}' not allowed",
                    status_code=403,
                )

            # Check Host header matches PUBLIC_ORIGIN
            if PUBLIC_ORIGIN:
                want_host = urlparse(PUBLIC_ORIGIN).netloc
                if host != want_host:
                    return PlainTextResponse(
                        f"Forbidden: Host header '{host}' does not match expected '{want_host}'",
                        status_code=403,
                    )

        # Proceed with request
        response = await call_next(request)

        # Add security headers to response
        response.headers["Content-Security-Policy"] = _build_csp()
        response.headers[
            "Strict-Transport-Security"
        ] = f"max-age={HSTS_MAX_AGE}; includeSubDomains; preload"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers[
            "Permissions-Policy"
        ] = "geolocation=(), microphone=(), camera=(), usb=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

        return response
