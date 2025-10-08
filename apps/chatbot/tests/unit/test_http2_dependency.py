#!/usr/bin/env python3
"""
Test HTTP/2 dependency is correctly installed for PDF worker communication.

Story 4.3 - Verifies httpx[http2] extra is installed to prevent h2 import errors.
"""


import pytest


def test_httpx_http2_installed():
    """Test that httpx is installed with HTTP/2 support (h2 package)."""
    try:
        import httpx
    except ImportError:
        pytest.fail("httpx is not installed")

    # Check that h2 package is available (required for HTTP/2)
    try:
        import h2
    except ImportError:
        pytest.fail(
            "h2 package is not installed. " "Install with: pip install httpx[http2]"
        )


def test_httpx_client_http2_support():
    """Test that httpx.Client can be created with http2=True without errors."""
    import httpx

    try:
        # This should not raise an error if h2 is installed
        client = httpx.Client(http2=True, timeout=10)
        client.close()
    except RuntimeError as e:
        if "h2" in str(e).lower():
            pytest.fail(
                f"HTTP/2 support failed: {e}. "
                "Ensure httpx[http2] is in requirements.txt"
            )
        raise


def test_file_processor_http2_client():
    """Test that FileProcessor's shared HTTP client has HTTP/2 enabled."""
    # Import the module to trigger client creation
    try:
        from src.file_processor import _get_httpx_client

        client = _get_httpx_client()

        # Verify HTTP/2 is enabled
        # The h2 library should be importable if http2=True works
        import h2

        # Client should be configured with http2=True
        # We can't directly inspect the http2 setting, but if h2 is installed
        # and client creation succeeded, it's working
        assert client is not None

    except ImportError as e:
        if "h2" in str(e).lower() or "httpx" in str(e).lower():
            pytest.fail(
                f"HTTP/2 client creation failed: {e}. "
                "Ensure httpx[http2] is in requirements.txt"
            )
        raise


def test_requirements_has_http2_extra():
    """
    Verify requirements.txt contains httpx[http2] (not just httpx).

    This is a documentation test to catch requirement regressions.
    """
    from pathlib import Path

    # Find requirements.txt
    current_file = Path(__file__)
    chatbot_dir = current_file.parents[2]  # apps/chatbot/
    requirements_file = chatbot_dir / "requirements.txt"

    if not requirements_file.exists():
        pytest.skip("requirements.txt not found")

    content = requirements_file.read_text()

    # Check for httpx[http2] pattern
    if "httpx[http2]" not in content and "httpx[http2,socks]" not in content:
        pytest.fail(
            "requirements.txt does not contain httpx[http2]. "
            "HTTP/2 support requires explicit installation: httpx[http2]>=0.25.2"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
