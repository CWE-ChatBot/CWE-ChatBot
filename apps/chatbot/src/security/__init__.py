"""
Security module for CWE ChatBot - Story S-12 implementation.

This module provides comprehensive security features including:
- SecurityHeadersMiddleware: CSP, HSTS, XFO, and other security headers
- CSRF token management for state-changing operations
- WebSocket origin validation
- Output sanitization for XSS prevention
"""

from .csrf import CSRFManager, require_csrf, require_csrf_from_metadata
from .middleware import SecurityHeadersMiddleware
from .sanitization import (
    sanitize_cwe_id,
    sanitize_filename,
    sanitize_html,
    sanitize_markdown,
    sanitize_url,
)

__all__ = [
    "SecurityHeadersMiddleware",
    "CSRFManager",
    "require_csrf",
    "require_csrf_from_metadata",
    "sanitize_html",
    "sanitize_markdown",
    "sanitize_filename",
    "sanitize_cwe_id",
    "sanitize_url",
]
