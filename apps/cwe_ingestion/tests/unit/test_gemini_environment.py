# apps/cwe_ingestion/tests/unit/test_gemini_environment.py
"""
Tests for Gemini API environment variable handling.
Following TDD Cycle 1.1b from Implementation Plan.
"""
from unittest.mock import patch

import pytest


def test_gemini_api_key_required():
    """Test that GEMINI_API_KEY environment variable is properly validated."""
    # This test will fail until we implement environment validation
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    from embedder import validate_gemini_environment

    # Should raise clear error without API key
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError, match="GEMINI_API_KEY"):
            validate_gemini_environment()


def test_gemini_api_key_validation():
    """Test that GEMINI_API_KEY format is validated."""
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    from embedder import validate_gemini_environment

    # Test with invalid key format
    with patch.dict(os.environ, {'GEMINI_API_KEY': ''}):
        with pytest.raises(ValueError, match="GEMINI_API_KEY"):
            validate_gemini_environment()

    # Test with valid key format
    with patch.dict(os.environ, {'GEMINI_API_KEY': 'AIzaSyD_test_key_format'}):
        # Should not raise exception
        validate_gemini_environment()


def test_gemini_environment_with_valid_key():
    """Test environment validation with valid API key."""
    import os
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    from embedder import validate_gemini_environment

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'AIzaSyD_valid_test_key'}):
        # Should return successfully
        result = validate_gemini_environment()
        assert result is True  # Or whatever the function should return
