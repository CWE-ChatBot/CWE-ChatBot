"""
Tests for response formatting with security considerations.
"""

import pytest
from src.formatting.response_formatter import ResponseFormatter
from src.retrieval.base_retriever import CWEResult


class TestResponseFormatter:
    """Test response formatting functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.formatter = ResponseFormatter()
        
        # Sample CWE results for testing
        self.sample_cwe_result = CWEResult(
            cwe_id="CWE-79",
            name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            description="The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
            confidence_score=0.95,
            source_method="dense",
            metadata={"abstraction": "Base", "structure": "Simple"}
        )
        
        self.multiple_results = [
            CWEResult(
                cwe_id="CWE-79",
                name="Cross-site Scripting",
                description="XSS vulnerability description",
                confidence_score=0.95,
                source_method="dense"
            ),
            CWEResult(
                cwe_id="CWE-89",
                name="SQL Injection",
                description="SQL injection vulnerability description",
                confidence_score=0.88,
                source_method="sparse"
            ),
            CWEResult(
                cwe_id="CWE-120",
                name="Buffer Copy without Checking Size of Input",
                description="Buffer overflow vulnerability description",
                confidence_score=0.75,
                source_method="hybrid"
            )
        ]
    
    def test_format_single_result(self):
        """Test formatting of a single CWE result."""
        result = self.formatter.format_cwe_results([self.sample_cwe_result])
        
        assert "CWE-79" in result
        assert "Cross-site Scripting" in result
        assert self.sample_cwe_result.description in result
        assert "**" in result  # Should have bold formatting
    
    def test_format_multiple_results(self):
        """Test formatting of multiple CWE results."""
        result = self.formatter.format_cwe_results(self.multiple_results)
        
        assert "Found 3 relevant CWE entries" in result
        assert "CWE-79" in result
        assert "CWE-89" in result
        assert "CWE-120" in result
        assert "1." in result and "2." in result and "3." in result  # Numbered list
    
    def test_format_empty_results(self):
        """Test formatting when no results are found."""
        result = self.formatter.format_cwe_results([])
        
        # Should return fallback message
        assert "I can only provide information about Common Weakness Enumerations" in result
        assert "CWE" in result
    
    def test_format_with_confidence_scores(self):
        """Test formatting with confidence scores displayed."""
        formatter = ResponseFormatter(show_confidence_scores=True)
        result = formatter.format_cwe_results([self.sample_cwe_result])
        
        # Should show confidence percentage
        assert "95%" in result
        assert "Confidence" in result
    
    def test_format_without_confidence_scores(self):
        """Test formatting with confidence scores hidden."""
        formatter = ResponseFormatter(show_confidence_scores=False)
        result = formatter.format_cwe_results([self.sample_cwe_result])
        
        # Should not show confidence
        assert "95%" not in result
        assert "Confidence" not in result
    
    def test_format_with_source_methods(self):
        """Test formatting with source methods displayed."""
        formatter = ResponseFormatter(show_source_methods=True)
        result = formatter.format_cwe_results([self.sample_cwe_result])
        
        # Should show retrieval method
        assert "dense search" in result or "Retrieved via" in result
    
    def test_format_without_source_methods(self):
        """Test formatting with source methods hidden."""
        formatter = ResponseFormatter(show_source_methods=False)
        result = formatter.format_cwe_results([self.sample_cwe_result])
        
        # Should not show retrieval method
        assert "dense search" not in result
        assert "Retrieved via" not in result
    
    def test_format_direct_cwe_result(self):
        """Test formatting for direct CWE ID queries."""
        result = self.formatter.format_direct_cwe_result(self.sample_cwe_result)
        
        assert "CWE-79" in result
        assert "Description:" in result
        assert self.sample_cwe_result.description in result
        
        # Should show metadata for direct queries
        if self.sample_cwe_result.metadata:
            assert "Abstraction Level:" in result or "Structure:" in result
    
    def test_format_direct_cwe_result_none(self):
        """Test direct formatting with None result."""
        result = self.formatter.format_direct_cwe_result(None)
        
        # Should return fallback
        assert "I can only provide information about Common Weakness Enumerations" in result
    
    def test_max_results_display_limit(self):
        """Test that max results display limit is respected."""
        formatter = ResponseFormatter(max_results_display=2)
        
        # Pass 3 results but only 2 should be displayed
        result = formatter.format_cwe_results(self.multiple_results)
        
        assert "Found 2 relevant CWE entries" in result
        assert "CWE-79" in result
        assert "CWE-89" in result
        # Third result should not be displayed
        assert result.count("CWE-") == 2
    
    def test_description_truncation(self):
        """Test that long descriptions are truncated in multiple results."""
        long_description_result = CWEResult(
            cwe_id="CWE-Test",
            name="Test Weakness",
            description="A" * 300,  # Very long description
            confidence_score=1.0,
            source_method="test"
        )
        
        result = self.formatter.format_cwe_results([long_description_result])
        
        # For single result, should show full description
        assert len(result) > 300
        
        # For multiple results, should truncate
        multiple_with_long = [long_description_result, self.sample_cwe_result]
        result_multiple = self.formatter.format_cwe_results(multiple_with_long)
        
        # Should have truncation indicator
        assert "..." in result_multiple
    
    def test_fallback_responses(self):
        """Test various fallback response types."""
        test_cases = [
            ("no_results", "I can only provide information about Common Weakness Enumerations"),
            ("invalid_query", "I'm sorry, I can't fulfill that request"),
            ("system_error", "I'm experiencing technical difficulties"),
            ("unknown_type", "I'm sorry, I can't fulfill that request")  # Default fallback
        ]
        
        for fallback_type, expected_text in test_cases:
            result = self.formatter.get_fallback_response(fallback_type)
            assert expected_text in result
    
    def test_format_search_summary(self):
        """Test formatting with search context summary."""
        query_info = {
            'query_type': 'vulnerability_inquiry',
            'has_direct_cwe': False
        }
        
        result = self.formatter.format_search_summary(self.multiple_results, query_info)
        
        assert "Vulnerability information:" in result
        assert "Found 3 relevant CWE entries" in result
    
    def test_format_search_summary_direct_lookup(self):
        """Test search summary for direct CWE lookup."""
        query_info = {
            'query_type': 'direct_cwe_lookup',
            'has_direct_cwe': True
        }
        
        result = self.formatter.format_search_summary([self.sample_cwe_result], query_info)
        
        assert "Direct CWE lookup:" in result
        assert "CWE-79" in result
    
    def test_format_search_summary_prevention(self):
        """Test search summary for prevention guidance."""
        query_info = {
            'query_type': 'prevention_guidance',
            'has_direct_cwe': False
        }
        
        result = self.formatter.format_search_summary(self.multiple_results, query_info)
        
        assert "Prevention and mitigation guidance:" in result
    
    def test_format_error_response(self):
        """Test secure error response formatting."""
        # Should not expose internal error details
        result = self.formatter.format_error_response("Internal database connection failed")
        
        # Should be generic message
        assert "technical difficulties" in result
        # Should not contain internal details
        assert "database" not in result
        assert "connection" not in result
    
    def test_secure_fallback_no_internal_details(self):
        """Test that fallback responses never expose internal details."""
        fallback_types = ["no_results", "invalid_query", "system_error"]
        
        for fallback_type in fallback_types:
            result = self.formatter.get_fallback_response(fallback_type)
            
            # Should not contain technical terms that could help attackers
            forbidden_terms = [
                "database", "sql", "server", "connection", "exception",
                "error", "stack", "trace", "internal", "system",
                "config", "configuration", "path", "file"
            ]
            
            result_lower = result.lower()
            for term in forbidden_terms:
                assert term not in result_lower, f"Fallback contains forbidden term '{term}': {result}"
    
    def test_confidence_score_display(self):
        """Test confidence score display formatting."""
        # Perfect confidence (1.0) should not show score
        perfect_result = CWEResult(
            cwe_id="CWE-Test",
            name="Test",
            description="Test description",
            confidence_score=1.0,
            source_method="direct"
        )
        
        formatter = ResponseFormatter(show_confidence_scores=True)
        result = formatter.format_cwe_results([perfect_result])
        
        # Perfect confidence should not show percentage
        assert "100%" not in result
        assert "Confidence:" not in result
        
        # Lower confidence should show
        low_confidence_result = CWEResult(
            cwe_id="CWE-Test",
            name="Test", 
            description="Test description",
            confidence_score=0.75,
            source_method="hybrid"
        )
        
        result = formatter.format_cwe_results([low_confidence_result])
        assert "75%" in result
        assert "Confidence:" in result
    
    def test_exception_handling_in_formatting(self):
        """Test that formatting exceptions are handled securely."""
        # Create a malformed result that might cause exceptions
        malformed_result = CWEResult(
            cwe_id=None,  # This could cause issues
            name=None,
            description=None,
            confidence_score="invalid",  # Wrong type
            source_method="test"
        )
        
        # Should not raise exception, should return error response
        result = self.formatter.format_cwe_results([malformed_result])
        
        # Should be a secure error response
        assert "technical difficulties" in result or "CWE information" in result


if __name__ == "__main__":
    pytest.main([__file__])