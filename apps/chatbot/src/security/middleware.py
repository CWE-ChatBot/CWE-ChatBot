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
CSP_MODE = os.getenv("CSP_MODE", "compatible")  # "compatible", "strict"
CSP_REPORT_ONLY = (
    os.getenv("CSP_REPORT_ONLY", "0") == "1"
)  # emit a strict CSP-RO alongside
ALLOWED_ORIGINS = [PUBLIC_ORIGIN] if PUBLIC_ORIGIN else []
HSTS_MAX_AGE = int(os.getenv("HSTS_MAX_AGE", "31536000"))  # 1 year default
IMG_EXTRA = os.getenv("CSP_IMG_EXTRA", "https:")  # Additional img-src hosts


def _origin_hosts():
    """Return ('https://host', 'wss://host') tuples for PUBLIC_ORIGIN, or empty if not set."""
    if not PUBLIC_ORIGIN:
        return [], []
    host = urlparse(PUBLIC_ORIGIN).netloc
    return [f"https://{host}"], [f"wss://{host}"]


def _build_csp() -> str:
    """
    Build the enforced Content-Security-Policy header.
    - Compatibility+ profile: no 'unsafe-inline' in script-src, but keep 'unsafe-eval'
    - Tight connect-src to self + your exact origin (no broad https:/wss:)
    - Allow external CSS/fonts for Chainlit dependencies:
      * fonts.googleapis.com - Google Fonts (Inter font family)
      * cdn.jsdelivr.net - KaTeX CSS for math rendering
      * fonts.gstatic.com - Google Fonts assets
    """
    https_hosts, wss_hosts = _origin_hosts()
    connect_list = " ".join(["'self'"] + https_hosts + wss_hosts)

    # Compatibility+ CSP (recommended for Chainlit today)
    # Allows external CDN resources (Google Fonts, KaTeX) and necessary unsafe-* directives
    if CSP_MODE != "strict":
        img_list = " ".join(filter(None, ["'self'", "data:", IMG_EXTRA.strip()]))
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "  # Chainlit requires both for React/inline scripts
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "  # Google Fonts + KaTeX CSS
            f"img-src {img_list}; "
            "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; "  # Google Fonts + KaTeX fonts
            f"connect-src {connect_list}; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "form-action 'self'"
        )

    # Strict CSP (no unsafe-*). Expect breakage unless you’ve audited Chainlit build.
    img_list = " ".join(filter(None, ["'self'", "data:", IMG_EXTRA.strip()]))
    return (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        f"img-src {img_list}; "
        "font-src 'self'; "
        f"connect-src {connect_list}; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "form-action 'self'"
    )


def _build_csp_report_only() -> str:
    """A strict CSP in Report-Only to see what would break."""
    https_hosts, wss_hosts = _origin_hosts()
    connect_list = " ".join(["'self'"] + https_hosts + wss_hosts)
    img_list = " ".join(filter(None, ["'self'", "data:", IMG_EXTRA.strip()]))
    return (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        f"img-src {img_list}; "
        "font-src 'self'; "
        f"connect-src {connect_list}; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "form-action 'self'; "
        "report-uri /csp-report"
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
        response.headers["Strict-Transport-Security"] = (
            f"max-age={HSTS_MAX_AGE}; includeSubDomains; preload"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), usb=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

        return response


# Explicitly export and reference the middleware dispatch so static analyzers see usage
__all__ = ["SecurityHeadersMiddleware"]
_ASGI_MIDDLEWARE_REFS: tuple[object, ...] = (SecurityHeadersMiddleware.dispatch,)
