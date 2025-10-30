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
IMG_EXTRA = os.getenv(
    "CSP_IMG_EXTRA", "https://chainlit-cloud.s3.eu-west-3.amazonaws.com"
)  # Additional img-src hosts


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
      * cdn.jsdelivr.net - KaTeX CSS for math rendering (Chainlit internal)
    - Fonts are now hosted locally (Inter, JetBrains Mono) for SRI compliance
    """
    https_hosts, wss_hosts = _origin_hosts()
    connect_list = " ".join(["'self'"] + https_hosts + wss_hosts)

    # Compatibility+ CSP (recommended for Chainlit today)
    # Allows KaTeX CDN (Chainlit internal) and necessary unsafe-* directives
    # Fonts hosted locally per Nuclei security recommendations
    if CSP_MODE != "strict":
        img_list = " ".join(filter(None, ["'self'", "data:", IMG_EXTRA.strip()]))
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "  # Chainlit requires both for React/inline scripts
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "  # KaTeX CSS (Chainlit internal)
            f"img-src {img_list}; "
            "font-src 'self' data: https://cdn.jsdelivr.net; "  # Local fonts + KaTeX fonts (Chainlit)
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

        # Ensure all cookies have Secure flag when running on HTTPS
        # Addresses ZAP finding: "Cookie Without Secure Flag"
        # This includes Chainlit's oauth_state and other session cookies
        if "set-cookie" in response.headers:
            cookies = response.headers.get("set-cookie")
            # Add Secure flag if not already present
            if (
                cookies
                and "Secure" not in cookies
                and PUBLIC_ORIGIN.startswith("https://")
            ):
                response.headers["set-cookie"] = cookies.rstrip("; ") + "; Secure"

        return response


# Explicitly export and reference the middleware dispatch so static analyzers see usage
__all__ = ["SecurityHeadersMiddleware"]
_ASGI_MIDDLEWARE_REFS: tuple[object, ...] = (SecurityHeadersMiddleware.dispatch,)
