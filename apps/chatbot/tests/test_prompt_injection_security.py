#!/usr/bin/env python3
"""
Security Tests for Response Generator Template Security
Tests that the ResponseGenerator handles prompts safely after refactoring.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Mock chainlit before importing
sys.modules['chainlit'] = MagicMock()

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.response_generator import ResponseGenerator
from src.user_context import UserPersona


class TestResponseGeneratorSecurity:
    """Test suite for response generator security after refactoring."""

    def setup_method(self):
        """Set up test fixtures."""
        with patch('src.response_generator.get_llm_provider'):
            self.response_generator = ResponseGenerator("test-api-key")

    def test_persona_prompt_templates_exist(self):
        """Test that all persona prompt templates are loaded."""
        expected_personas = [
            "PSIRT Member",
            "Developer",
            "Academic Researcher",
            "Bug Bounty Hunter",
            "Product Manager",
            "CWE Analyzer",
            "CVE Creator"
        ]

        for persona in expected_personas:
            assert persona in self.response_generator.persona_prompts, f"Missing prompt template for {persona}"
            prompt_template = self.response_generator.persona_prompts[persona]
            assert "{user_query}" in prompt_template, f"Template for {persona} missing user_query placeholder"
            assert "{user_evidence}" in prompt_template, f"Template for {persona} missing user_evidence placeholder"
            # CVE Creator uses a different template structure without CWE context
            if persona != "CVE Creator":
                assert "{cwe_context}" in prompt_template, f"Template for {persona} missing cwe_context placeholder"

    def test_context_building_structure(self):
        """Test that context building handles chunks safely."""
        test_chunks = [
            {
                'document': 'Test CWE content for Cross-site Scripting',
                'metadata': {'cwe_id': 'CWE-79', 'cwe_name': 'Cross-site Scripting'},
                'scores': {'hybrid': 0.95}
            },
            {
                'document': 'Another CWE entry for SQL Injection',
                'metadata': {'cwe_id': 'CWE-89', 'cwe_name': 'SQL Injection'},
                'scores': {'hybrid': 0.85}
            }
        ]

        context = self.response_generator._build_context(test_chunks)

        # Ensure context is built and contains expected elements
        assert 'CWE-79' in context, "Context should contain CWE-79"
        assert 'CWE-89' in context, "Context should contain CWE-89"
        assert 'Test CWE content' in context, "Context should contain document content"
        assert 'Another CWE entry' in context, "Context should contain second document content"

    def test_fallback_response_generation(self):
        """Test that fallback responses are generated safely."""
        personas = ["Developer", "PSIRT Member", "Academic Researcher"]

        for persona in personas:
            fallback = self.response_generator._generate_fallback_response("test query", persona)

            # Ensure fallback is generated and contains safe content
            assert len(fallback) > 0, f"Fallback response should not be empty for {persona}"
            assert "CWE" in fallback, f"Fallback should mention CWE for {persona}"
            # Should not contain sensitive system information
            assert "error" not in fallback.lower(), f"Fallback should not expose errors for {persona}"

    def test_error_response_generation(self):
        """Test that error responses don't expose system details."""
        personas = ["Developer", "PSIRT Member", "Academic Researcher"]

        for persona in personas:
            error_response = self.response_generator._generate_error_response(persona)

            # Ensure error response is safe
            assert len(error_response) > 0, f"Error response should not be empty for {persona}"
            assert "technical difficulties" in error_response, f"Error response should be generic for {persona}"
            # Should not contain sensitive system information
            assert "exception" not in error_response.lower(), f"Error response should not expose exceptions for {persona}"
            assert "traceback" not in error_response.lower(), f"Error response should not expose tracebacks for {persona}"

    def test_empty_chunks_handling(self):
        """Test that empty or None chunks are handled safely."""
        # Test with empty list
        context = self.response_generator._build_context([])
        assert isinstance(context, str), "Context should be a string even with empty chunks"

        # Test with None
        context = self.response_generator._build_context(None)
        assert isinstance(context, str), "Context should be a string even with None chunks"

    def test_prompt_template_safety(self):
        """Test that prompt templates contain proper placeholders and instructions."""
        for persona, template in self.response_generator.persona_prompts.items():
            # Check for required placeholders
            assert "{user_query}" in template, f"Template for {persona} missing user_query placeholder"
            assert "{user_evidence}" in template, f"Template for {persona} missing user_evidence placeholder"
            # CVE Creator uses a different template structure without CWE context
            if persona != "CVE Creator":
                assert "{cwe_context}" in template, f"Template for {persona} missing cwe_context placeholder"

            # Check for security-oriented instructions
            lower_template = template.lower()
            security_indicators = ['cite', 'cwe', 'response:', 'instructions:']
            assert any(indicator in lower_template for indicator in security_indicators), \
                f"Template for {persona} should contain security guidance"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])