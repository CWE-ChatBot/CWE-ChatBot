"""
Unit tests for CWE extraction and query analysis functionality.
Tests CWE ID extraction, query type classification, and keyphrase analysis.
"""

import pytest
from src.processing.cwe_extractor import CWEExtractor


class TestCWEExtractor:
    """Test suite for CWE extraction functionality."""

    @pytest.fixture
    def extractor(self):
        """Provide a CWEExtractor instance for testing."""
        return CWEExtractor()

    def test_has_direct_cwe_reference_positive(self, extractor):
        """Test detection of direct CWE references."""
        test_cases = [
            "What is CWE-79?",
            "Tell me about CWE-89 and SQL injection",
            "Compare CWE-79 with CWE-89",
            "CWE-22 path traversal vulnerability",
            "I need info on CWE-787"
        ]

        for query in test_cases:
            assert extractor.has_direct_cwe_reference(query), \
                f"Should detect CWE reference in: {query}"

    def test_has_direct_cwe_reference_negative(self, extractor):
        """Test rejection of queries without CWE references."""
        test_cases = [
            "What is SQL injection?",
            "How do I prevent XSS attacks?",
            "Tell me about buffer overflows",
            "Security best practices for web applications",
            "What are common vulnerabilities?"
        ]

        for query in test_cases:
            assert not extractor.has_direct_cwe_reference(query), \
                f"Should not detect CWE reference in: {query}"

    def test_extract_cwe_ids_single(self, extractor):
        """Test extraction of single CWE IDs."""
        test_cases = [
            ("What is CWE-79?", {"CWE-79"}),
            ("Tell me about CWE-89", {"CWE-89"}),
            ("CWE-22 path traversal", {"CWE-22"}),
            ("Information about CWE-787", {"CWE-787"})
        ]

        for query, expected in test_cases:
            result = extractor.extract_cwe_ids(query)
            assert result == expected, \
                f"Expected {expected} from '{query}', got {result}"

    def test_extract_cwe_ids_multiple(self, extractor):
        """Test extraction of multiple CWE IDs from single query."""
        test_cases = [
            ("Compare CWE-79 with CWE-89", {"CWE-79", "CWE-89"}),
            ("CWE-22, CWE-23, and CWE-24 are related", {"CWE-22", "CWE-23", "CWE-24"}),
            ("Differences between CWE-787 and CWE-120", {"CWE-787", "CWE-120"})
        ]

        for query, expected in test_cases:
            result = extractor.extract_cwe_ids(query)
            assert result == expected, \
                f"Expected {expected} from '{query}', got {result}"

    def test_extract_cwe_ids_none(self, extractor):
        """Test extraction when no CWE IDs present."""
        test_cases = [
            "What is SQL injection?",
            "How to prevent XSS?",
            "Buffer overflow mitigation",
            "Security scanning tools"
        ]

        for query in test_cases:
            result = extractor.extract_cwe_ids(query)
            assert result == set(), \
                f"Expected empty set from '{query}', got {result}"

    def test_enhance_query_for_search_vulnerability_inquiry(self, extractor):
        """Test query enhancement for vulnerability inquiry type."""
        query = "What is CWE-79 and how does it work?"

        result = extractor.enhance_query_for_search(query)

        assert result["query_type"] == "vulnerability_inquiry"
        assert "CWE-79" in result["cwe_ids"]
        assert "cross-site scripting" in " ".join(
            sum(result["keyphrases"].values(), [])
        ).lower()

    def test_enhance_query_for_search_prevention_guidance(self, extractor):
        """Test query enhancement for prevention guidance type."""
        query = "How do I prevent SQL injection attacks?"

        result = extractor.enhance_query_for_search(query)

        assert result["query_type"] == "prevention_guidance"
        assert "sql injection" in " ".join(
            sum(result["keyphrases"].values(), [])
        ).lower()

    def test_enhance_query_for_search_direct_cwe_lookup(self, extractor):
        """Test query enhancement for direct CWE lookup type."""
        query = "CWE-89"

        result = extractor.enhance_query_for_search(query)

        assert result["query_type"] == "direct_cwe_lookup"
        assert "CWE-89" in result["cwe_ids"]

    def test_enhance_query_for_search_comparison(self, extractor):
        """Test query enhancement for CWE comparison queries."""
        query = "Compare CWE-79 with CWE-89 and explain differences"

        result = extractor.enhance_query_for_search(query)

        assert result["query_type"] in ["vulnerability_inquiry", "direct_cwe_lookup"]
        assert {"CWE-79", "CWE-89"}.issubset(result["cwe_ids"])

    def test_enhance_query_for_search_general_security(self, extractor):
        """Test query enhancement for general security questions."""
        query = "What are common web application vulnerabilities?"

        result = extractor.enhance_query_for_search(query)

        assert result["query_type"] == "general_security"
        assert "web application" in " ".join(
            sum(result["keyphrases"].values(), [])
        ).lower()

    def test_enhance_query_for_search_structure(self, extractor):
        """Test that query enhancement returns expected structure."""
        query = "What is CWE-79?"

        result = extractor.enhance_query_for_search(query)

        # Check required keys
        required_keys = ["query_type", "cwe_ids", "keyphrases", "enhanced_query"]
        for key in required_keys:
            assert key in result, f"Missing required key: {key}"

        # Check data types
        assert isinstance(result["query_type"], str)
        assert isinstance(result["cwe_ids"], set)
        assert isinstance(result["keyphrases"], dict)
        assert isinstance(result["enhanced_query"], str)

        # Check valid query type
        valid_types = {
            "vulnerability_inquiry", "prevention_guidance",
            "direct_cwe_lookup", "general_security"
        }
        assert result["query_type"] in valid_types

    def test_case_insensitive_cwe_extraction(self, extractor):
        """Test that CWE extraction is case insensitive."""
        test_cases = [
            "what is cwe-79?",
            "TELL ME ABOUT CWE-89",
            "Compare cWe-22 with CWE-23"
        ]

        for query in test_cases:
            assert extractor.has_direct_cwe_reference(query)
            cwe_ids = extractor.extract_cwe_ids(query)
            assert len(cwe_ids) > 0

    def test_cwe_id_validation(self, extractor):
        """Test that only valid CWE ID formats are extracted."""
        test_cases = [
            ("CWE-79 is valid", {"CWE-79"}),
            ("CWE-1234 is valid", {"CWE-1234"}),
            ("CWE-99999 is valid", {"CWE-99999"}),
            ("CWE- is invalid", set()),  # Missing number
            ("CWE-abc is invalid", set()),  # Non-numeric
            ("CWEE-79 is invalid", set()),  # Wrong format
        ]

        for query, expected in test_cases:
            result = extractor.extract_cwe_ids(query)
            assert result == expected, \
                f"Expected {expected} from '{query}', got {result}"

    def test_keyphrase_extraction_security_terms(self, extractor):
        """Test extraction of security-related keyphrases."""
        query = "How do I prevent buffer overflow and SQL injection?"

        result = extractor.enhance_query_for_search(query)

        all_keyphrases = " ".join(sum(result["keyphrases"].values(), []))
        assert "buffer overflow" in all_keyphrases.lower()
        assert "sql injection" in all_keyphrases.lower()

    def test_enhanced_query_expansion(self, extractor):
        """Test that enhanced query includes relevant expansions."""
        query = "CWE-79"

        result = extractor.enhance_query_for_search(query)

        enhanced = result["enhanced_query"].lower()
        # Should expand CWE-79 to include XSS-related terms
        assert any(term in enhanced for term in [
            "cross-site scripting", "xss", "injection"
        ])

    def test_empty_and_whitespace_queries(self, extractor):
        """Test handling of empty and whitespace-only queries."""
        test_cases = ["", "   ", "\n\t", "  \n  "]

        for query in test_cases:
            assert not extractor.has_direct_cwe_reference(query)
            assert extractor.extract_cwe_ids(query) == set()

            result = extractor.enhance_query_for_search(query)
            assert result["query_type"] == "general_security"
            assert result["cwe_ids"] == set()