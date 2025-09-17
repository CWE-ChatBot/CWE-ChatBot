# apps/cwe_ingestion/tests/unit/test_gemini_dependencies.py
"""
Tests for Gemini API dependencies and imports.
Following TDD Cycle 1.1a from Implementation Plan.
"""
import pytest


def test_google_generativeai_available():
    """Test that google-generativeai dependency is available."""
    try:
        import google.generativeai as genai
        # If import succeeds, dependency is available
        assert genai is not None
    except ImportError:
        pytest.fail("google-generativeai dependency not available")


def test_google_generativeai_version():
    """Test that google-generativeai has acceptable version."""
    try:
        import google.generativeai as genai
        # Should have expected version or later
        # This test will help validate dependency installation
        assert hasattr(genai, 'configure')  # Should have configure method
        assert hasattr(genai, 'embed_content')  # Should have embed_content method
    except ImportError:
        pytest.fail("google-generativeai dependency not available")
