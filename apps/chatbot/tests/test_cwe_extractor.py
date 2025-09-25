"""
Tests for CWE ID extraction and security keyphrase analysis.
"""

import pytest
from src.processing.cwe_extractor import CWEExtractor


class TestCWEExtractor:
    """Test CWE ID extraction and keyphrase analysis."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = CWEExtractor()
    
    def test_single_cwe_id_extraction(self):
        """Test extraction of single CWE IDs."""
        test_cases = [
            ("What is CWE-79?", {"CWE-79"}),
            ("Tell me about CWE-89 vulnerability", {"CWE-89"}),
            ("Explain CWE-120 buffer overflow", {"CWE-120"}),
            ("CWE-787 out of bounds write", {"CWE-787"}),
            ("Information about cwe-22", {"CWE-22"})  # Case insensitive
        ]
        
        for text, expected in test_cases:
            result = self.extractor.extract_cwe_ids(text)
            assert result == expected, f"Failed for: {text}"
    
    def test_multiple_cwe_id_extraction(self):
        """Test extraction of multiple CWE IDs from same text."""
        text = "Compare CWE-79 and CWE-89 with CWE-120"
        result = self.extractor.extract_cwe_ids(text)
        expected = {"CWE-79", "CWE-89", "CWE-120"}
        assert result == expected
    
    def test_no_cwe_ids_found(self):
        """Test handling when no CWE IDs are present."""
        test_cases = [
            "What are SQL injection vulnerabilities?",
            "Tell me about buffer overflows",
            "Explain cross-site scripting",
            "Security best practices",
            ""
        ]
        
        for text in test_cases:
            result = self.extractor.extract_cwe_ids(text)
            assert result == set(), f"False positive for: {text}"
    
    def test_cwe_id_boundary_cases(self):
        """Test CWE ID extraction boundary cases."""
        test_cases = [
            ("CWE-1", {"CWE-1"}),  # Single digit
            ("CWE-1234", {"CWE-1234"}),  # Multi-digit
            ("Not-CWE-79 here", set()),  # Invalid prefix
            ("CWE-79-extended", {"CWE-79"}),  # Valid with suffix
            ("CWE- 79", set()),  # Space breaks pattern
            ("CWE-abc", set())  # Non-numeric
        ]
        
        for text, expected in test_cases:
            result = self.extractor.extract_cwe_ids(text)
            assert result == expected, f"Failed for: {text}"
    
    def test_direct_cwe_reference_detection(self):
        """Test detection of direct CWE references."""
        positive_cases = [
            "What is CWE-79?",
            "Tell me about CWE-89",
            "CWE-120 buffer overflow"
        ]
        
        negative_cases = [
            "SQL injection vulnerabilities",
            "Buffer overflow attacks",
            "No CWE mentioned here"
        ]
        
        for text in positive_cases:
            assert self.extractor.has_direct_cwe_reference(text), f"Should detect CWE in: {text}"
        
        for text in negative_cases:
            assert not self.extractor.has_direct_cwe_reference(text), f"False positive for: {text}"
    
    def test_vulnerability_type_keyphrase_extraction(self):
        """Test extraction of vulnerability type keyphrases."""
        test_cases = [
            ("SQL injection vulnerabilities", ["injection", "sql injection"]),
            ("Cross-site scripting attacks", ["cross-site scripting"]),
            ("Buffer overflow in C programs", ["buffer overflow", "overflow"]),
            ("Command injection vulnerabilities", ["command injection", "injection"]),
            ("Authentication bypass", ["authentication"])
        ]
        
        for text, expected_phrases in test_cases:
            result = self.extractor.extract_keyphrases(text)
            vuln_types = result.get('vulnerability_types', [])
            
            for phrase in expected_phrases:
                assert any(phrase in vuln_type.lower() for vuln_type in vuln_types), \
                    f"Expected '{phrase}' in vulnerability types for: {text}"
    
    def test_security_terms_extraction(self):
        """Test extraction of general security terms."""
        test_cases = [
            ("Vulnerability assessment", ["vulnerability"]),
            ("Security weakness analysis", ["weakness", "security"]),
            ("Threat modeling", ["threat"]),
            ("Risk assessment", ["risk"]),
            ("Exploit development", ["exploit"])
        ]
        
        for text, expected_terms in test_cases:
            result = self.extractor.extract_keyphrases(text)
            security_terms = result.get('security_terms', [])
            
            for term in expected_terms:
                assert any(term in sec_term.lower() for sec_term in security_terms), \
                    f"Expected '{term}' in security terms for: {text}"
    
    def test_programming_context_extraction(self):
        """Test extraction of programming context keyphrases."""
        test_cases = [
            ("C programming buffer overflow", ["c programming"]),
            ("Java web application security", ["java", "web application"]),
            ("Python input validation", ["python"]),
            ("JavaScript XSS vulnerability", ["javascript"]),
            ("Database SQL injection", ["database"])
        ]
        
        for text, expected_contexts in test_cases:
            result = self.extractor.extract_keyphrases(text)
            prog_contexts = result.get('programming_contexts', [])
            
            for context in expected_contexts:
                assert any(context in prog_context.lower() for prog_context in prog_contexts), \
                    f"Expected '{context}' in programming contexts for: {text}"
    
    def test_query_type_classification(self):
        """Test classification of query types."""
        test_cases = [
            ("What is CWE-79?", "direct_cwe_lookup"),
            ("SQL injection vulnerabilities", "vulnerability_inquiry"),
            ("How to prevent buffer overflows?", "prevention_guidance"),
            ("Security best practices", "general_security"),
            ("C programming security", "programming_security"),
            ("What is the weather?", "general_query"),
            ("", "unknown")
        ]
        
        for text, expected_type in test_cases:
            result = self.extractor.classify_query_type(text)
            assert result == expected_type, f"Failed classification for: {text}"
    
    def test_enhance_query_for_search(self):
        """Test comprehensive query enhancement."""
        query = "Tell me about CWE-79 cross-site scripting prevention"
        result = self.extractor.enhance_query_for_search(query)

        # Check all components are present
        assert 'CWE-79' in result['cwe_ids']
        assert result['query_type'] == 'direct_cwe_lookup'
        assert len(result['keyphrases']) > 0
        assert 'enhanced_query' in result
        assert len(result['enhanced_query']) >= len(query)
        
        # Check keyphrases contain expected terms
        all_phrases = []
        for phrase_list in result['keyphrases'].values():
            all_phrases.extend(phrase_list)
        
        assert any('xss' in phrase.lower() or 'cross-site scripting' in phrase.lower() 
                  for phrase in all_phrases)
    
    def test_edge_cases(self):
        """Test edge cases and error conditions."""
        # Non-string input
        assert self.extractor.extract_cwe_ids(None) == set()
        assert self.extractor.extract_cwe_ids(123) == set()
        assert self.extractor.extract_cwe_ids([]) == set()
        
        # Empty and whitespace
        assert self.extractor.extract_cwe_ids("") == set()
        assert self.extractor.extract_cwe_ids("   ") == set()
        assert self.extractor.extract_cwe_ids("\\n\\n\\n") == set()
        
        # Classification of edge cases
        assert self.extractor.classify_query_type(None) == "unknown"
        assert self.extractor.classify_query_type("") == "unknown"
        assert self.extractor.classify_query_type("   ") == "unknown"
    
    def test_case_insensitive_matching(self):
        """Test that matching is case insensitive."""
        test_cases = [
            "cwe-79 vulnerability",
            "CWE-79 Vulnerability", 
            "Cwe-79 VULNERABILITY",
            "SQL INJECTION attack",
            "sql injection ATTACK",
            "Buffer OVERFLOW prevention",
            "BUFFER overflow PREVENTION"
        ]
        
        for text in test_cases:
            # Should extract CWE IDs regardless of case
            if 'cwe-79' in text.lower():
                cwe_ids = self.extractor.extract_cwe_ids(text)
                assert 'CWE-79' in cwe_ids
            
            # Should extract keyphrases regardless of case
            keyphrases = self.extractor.extract_keyphrases(text)
            assert len(keyphrases) > 0  # Should find something
    
    def test_keyphrase_deduplication(self):
        """Test that duplicate keyphrases are removed."""
        text = "SQL injection and SQL injection vulnerabilities and more SQL injection"
        result = self.extractor.extract_keyphrases(text)
        
        vuln_types = result.get('vulnerability_types', [])
        # Should not have duplicates
        assert len(vuln_types) == len(set(vuln_types))


if __name__ == "__main__":
    pytest.main([__file__])