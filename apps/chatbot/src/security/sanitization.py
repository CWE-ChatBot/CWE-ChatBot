"""
Output Sanitization for XSS Prevention - Story S-12

Provides HTML/Markdown sanitization to prevent XSS attacks when displaying
user-provided content in Chainlit messages and UI elements.

Key Functions:
- sanitize_html: Escape HTML special characters
- sanitize_markdown: Safe markdown rendering (future enhancement)
"""

import html
import re
from typing import Optional


def sanitize_html(text: str, quote: bool = True) -> str:
    """
    Escape HTML special characters to prevent XSS.

    Converts dangerous characters to HTML entities:
    - < becomes &lt;
    - > becomes &gt;
    - & becomes &amp;
    - " becomes &quot; (if quote=True)
    - ' becomes &#x27; (if quote=True)

    Args:
        text: Input text that may contain HTML
        quote: Whether to escape quotes (default True)

    Returns:
        HTML-safe escaped text

    Example:
        >>> filename = "<script>alert('xss')</script>"
        >>> safe_name = sanitize_html(filename)
        >>> await cl.Message(f"File: {safe_name}").send()
        # Displays: File: &lt;script&gt;alert('xss')&lt;/script&gt;
    """
    return html.escape(text, quote=quote)


def sanitize_markdown(text: str, allow_code_blocks: bool = True) -> str:
    """
    Sanitize markdown while preserving safe formatting.

    Currently a placeholder for future enhancement. For now, uses HTML escaping
    which prevents all XSS but also removes markdown formatting.

    Future: Implement safe markdown parsing that:
    - Allows: bold, italic, links, code blocks, lists
    - Blocks: inline HTML, javascript: URLs, data: URLs

    Args:
        text: Markdown text to sanitize
        allow_code_blocks: Whether to allow code blocks (default True)

    Returns:
        Sanitized markdown text

    TODO: Implement proper markdown sanitization with allowed-list approach
    """
    # For now, use HTML escaping to be safe
    # Future: Use a library like bleach or markdown-it with strict config
    return sanitize_html(text)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe display and storage.

    Removes or escapes characters that could be dangerous:
    - Path traversal attempts (../)
    - HTML/JS injection attempts
    - Control characters

    Args:
        filename: User-provided filename

    Returns:
        Sanitized filename safe for display

    Example:
        >>> filename = "../../../etc/passwd"
        >>> safe = sanitize_filename(filename)
        >>> await cl.Message(f"Processing: {safe}").send()
    """
    # Remove path traversal attempts
    filename = filename.replace("../", "").replace("..\\", "")

    # Remove absolute path markers
    filename = filename.lstrip("/\\")

    # Remove null bytes and control characters
    filename = "".join(char for char in filename if ord(char) >= 32)

    # HTML escape for safe display
    filename = sanitize_html(filename)

    return filename


def sanitize_cwe_id(cwe_id: str) -> Optional[str]:
    """
    Validate and sanitize CWE ID format.

    Only allows valid CWE ID format: CWE-[digits]

    Args:
        cwe_id: User-provided CWE ID

    Returns:
        Sanitized CWE ID or None if invalid

    Example:
        >>> cwe_id = "CWE-79<script>"
        >>> safe = sanitize_cwe_id(cwe_id)
        >>> safe
        'CWE-79'
    """
    # Validate CWE ID format: CWE-[digits]
    match = re.match(r"^(CWE-\d+)", cwe_id, re.IGNORECASE)
    if not match:
        return None

    # Return validated and normalized CWE ID
    return match.group(1).upper()


def sanitize_url(url: str, allowed_schemes: Optional[list] = None) -> Optional[str]:
    """
    Validate URL and ensure it uses safe scheme.

    Args:
        url: User-provided URL
        allowed_schemes: List of allowed schemes (default: ['http', 'https'])

    Returns:
        URL if valid and safe, None otherwise

    Example:
        >>> url = "javascript:alert(1)"
        >>> safe = sanitize_url(url)
        >>> safe
        None
        >>> url = "https://example.com"
        >>> safe = sanitize_url(url)
        >>> safe
        'https://example.com'
    """
    if allowed_schemes is None:
        allowed_schemes = ["http", "https"]

    # Check for dangerous schemes
    url_lower = url.lower().strip()
    for scheme in allowed_schemes:
        if url_lower.startswith(f"{scheme}://"):
            return url  # Valid scheme

    # Blocked schemes: javascript:, data:, vbscript:, etc.
    return None
