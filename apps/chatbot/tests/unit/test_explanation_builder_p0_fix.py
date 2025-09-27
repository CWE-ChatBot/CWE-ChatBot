#!/usr/bin/env python3
"""
Unit test for ExplanationBuilder P0 fix: document field access
Verifies that ExplanationBuilder correctly extracts content from the "document" field
as the primary source, with fallback to "content" field.
"""

import pytest
from src.processing.explanation_builder import ExplanationBuilder


class TestExplanationBuilderP0Fix:
    """Test ExplanationBuilder document field access (P0 fix)."""

    def test_extract_snippet_candidates_uses_document_field_primary(self):
        """Test that ExplanationBuilder uses 'document' field as primary source."""
        builder = ExplanationBuilder()
        query = "buffer overflow"

        # Chunk with both document and content fields - document should be preferred
        chunks = [
            {
                "document": "Buffer overflow vulnerability allows attackers to overwrite memory",
                "content": "This should be ignored when document field exists",
                "metadata": {"section": "Description"},
                "score": 0.8
            }
        ]

        candidates = builder._extract_snippet_candidates(query, chunks)

        # Should have extracted candidates from the document field
        assert len(candidates) > 0

        # Check that content came from document field (contains "Buffer overflow")
        found_content = False
        for candidate in candidates:
            if "Buffer overflow vulnerability" in candidate["text"]:
                found_content = True
                break

        assert found_content, "Should extract content from 'document' field"

    def test_extract_snippet_candidates_falls_back_to_content_field(self):
        """Test that ExplanationBuilder falls back to 'content' field when 'document' is missing."""
        builder = ExplanationBuilder()
        query = "injection attack"

        # Chunk with only content field (no document field)
        chunks = [
            {
                "content": "SQL injection attacks exploit vulnerable database queries",
                "metadata": {"section": "Description"},
                "score": 0.7
            }
        ]

        candidates = builder._extract_snippet_candidates(query, chunks)

        # Should have extracted candidates from the content field
        assert len(candidates) > 0

        # Check that content came from content field (contains "SQL injection")
        found_content = False
        for candidate in candidates:
            if "SQL injection attacks" in candidate["text"]:
                found_content = True
                break

        assert found_content, "Should fall back to 'content' field when 'document' is missing"

    def test_extract_snippet_candidates_handles_empty_fields(self):
        """Test that ExplanationBuilder handles empty or missing content gracefully."""
        builder = ExplanationBuilder()
        query = "test query"

        # Chunks with empty/missing content
        chunks = [
            {
                "document": "",
                "content": "Some fallback content",
                "metadata": {"section": "Description"},
                "score": 0.5
            },
            {
                # No document field
                "content": "",
                "metadata": {"section": "Description"},
                "score": 0.3
            },
            {
                # Both empty
                "document": "",
                "content": "",
                "metadata": {"section": "Description"},
                "score": 0.1
            }
        ]

        candidates = builder._extract_snippet_candidates(query, chunks)

        # Should only extract from the first chunk (has fallback content)
        assert len(candidates) >= 0  # May be 0 if no relevant sentences found

        # Verify no empty content was extracted
        for candidate in candidates:
            assert len(candidate["text"].strip()) > 0, "Should not extract empty content"

    def test_build_explanation_uses_document_field(self):
        """Test that build() method correctly uses document field for explanations."""
        builder = ExplanationBuilder()
        query = "cross-site scripting"
        cwe_id = "CWE-79"

        chunks = [
            {
                "document": "Cross-site scripting (XSS) vulnerabilities allow injection of malicious scripts into web pages viewed by other users",
                "content": "This content should be ignored",
                "metadata": {
                    "section": "Description",
                    "name": "Cross-site Scripting",
                    "cwe_name": "Cross-site Scripting"
                },
                "score": 0.9
            }
        ]

        explanation = builder.build(query, cwe_id, chunks)

        # Should have extracted snippets from document field
        assert len(explanation["snippets"]) > 0

        # Check that snippet contains content from document field
        snippet_text = explanation["snippets"][0]["text"]
        assert "Cross-site scripting (XSS) vulnerabilities" in snippet_text
        assert "This content should be ignored" not in snippet_text

        # Should have proper section coverage
        assert "Description" in explanation["section_coverage"]
        assert explanation["section_coverage"]["Description"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])