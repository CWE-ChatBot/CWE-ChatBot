"""
Query processor for enhanced retrieval with security-first design.
Integrates input sanitization, CWE extraction, and query enhancement.
"""

import logging
from typing import Dict, List, Set, Any, Optional

from ..security.input_sanitizer import InputSanitizer
from .cwe_extractor import CWEExtractor


logger = logging.getLogger(__name__)


class QueryProcessor:
    """
    Processes queries for enhanced retrieval with security safeguards.
    
    Combines input sanitization, CWE ID extraction, and keyphrase analysis
    to prepare queries for hybrid retrieval systems.
    """
    
    def __init__(
        self, 
        max_input_length: int = 1000,
        strict_mode: bool = True
    ):
        """
        Initialize the query processor.
        
        Args:
            max_input_length: Maximum allowed input length
            strict_mode: If True, reject malicious inputs
        """
        self.sanitizer = InputSanitizer(
            max_length=max_input_length,
            strict_mode=strict_mode
        )
        self.cwe_extractor = CWEExtractor()
        
        logger.info("Initialized QueryProcessor with security-first design")
    
    def preprocess_query(self, query: str) -> Dict[str, Any]:
        """
        Complete query preprocessing pipeline.
        
        Args:
            query: Raw user query string
            
        Returns:
            Dictionary with preprocessed query information
            
        Raises:
            ValueError: If input is malicious and strict_mode is True
            TypeError: If input is not a string
        """
        if not isinstance(query, str):
            raise TypeError("Query must be a string")
        
        logger.debug(f"Preprocessing query of length {len(query)}")
        
        try:
            # Step 1: Input sanitization (security-first)
            sanitized_query = self.sanitizer.sanitize(query)
            
            # Step 2: Security analysis  
            is_malicious, detected_patterns = self.sanitizer.is_potentially_malicious(query)
            
            # Step 3: CWE extraction and analysis
            cwe_analysis = self.cwe_extractor.enhance_query_for_search(sanitized_query)
            
            # Step 4: Build comprehensive result
            result = {
                # Original and processed queries
                "original_query": query,
                "sanitized_query": sanitized_query,
                
                # Security analysis
                "security_check": {
                    "is_potentially_malicious": is_malicious,
                    "detected_patterns": detected_patterns,
                    "sanitization_applied": sanitized_query != query
                },
                
                # CWE analysis
                "cwe_ids": cwe_analysis['cwe_ids'],
                "keyphrases": cwe_analysis['keyphrases'],
                "query_type": cwe_analysis['query_type'],
                "has_direct_cwe": cwe_analysis['has_direct_cwe'],
                
                # Query routing information
                "search_strategy": self._determine_search_strategy(cwe_analysis),
                "boost_factors": self._calculate_boost_factors(cwe_analysis)
            }
            
            logger.debug(f"Query preprocessing completed: {result['query_type']}")
            return result
            
        except Exception as e:
            logger.error(f"Query preprocessing failed: {e}")
            raise
    
    def _determine_search_strategy(self, cwe_analysis: Dict[str, Any]) -> str:
        """
        Determine the optimal search strategy based on query analysis.
        
        Args:
            cwe_analysis: Results from CWE extraction
            
        Returns:
            Recommended search strategy
        """
        # Direct CWE lookup for explicit CWE references
        if cwe_analysis['has_direct_cwe']:
            return "direct_lookup"
        
        # Hybrid search for complex security queries
        query_type = cwe_analysis['query_type']
        if query_type in ['vulnerability_inquiry', 'prevention_guidance']:
            return "hybrid_search"
        
        # Dense search for general security concepts
        if query_type in ['general_security', 'programming_security']:
            return "dense_search"
        
        # Sparse search for keyword-heavy queries
        if cwe_analysis['keyphrases']:
            return "sparse_search"
        
        # Default to hybrid for unknown query types
        return "hybrid_search"
    
    def _calculate_boost_factors(self, cwe_analysis: Dict[str, Any]) -> Dict[str, float]:
        """
        Calculate boost factors for different retrieval methods.
        
        Args:
            cwe_analysis: Results from CWE extraction
            
        Returns:
            Dictionary of boost factors for dense/sparse methods
        """
        boost_factors = {"dense": 1.0, "sparse": 1.0}
        
        # Boost sparse search for keyword-rich queries
        if cwe_analysis['keyphrases']:
            keyphrase_count = sum(len(phrases) for phrases in cwe_analysis['keyphrases'].values())
            boost_factors["sparse"] = 1.0 + (keyphrase_count * 0.1)
        
        # Boost dense search for conceptual queries
        query_type = cwe_analysis['query_type']
        if query_type in ['general_security', 'prevention_guidance']:
            boost_factors["dense"] = 1.2
        
        return boost_factors
    
    def extract_cwe_ids(self, query: str) -> Set[str]:
        """
        Extract CWE IDs from query (convenience method).
        
        Args:
            query: Query string to analyze
            
        Returns:
            Set of extracted CWE IDs
        """
        return self.cwe_extractor.extract_cwe_ids(query)
    
    def is_direct_cwe_query(self, query: str) -> bool:
        """
        Check if query is asking for a specific CWE (convenience method).
        
        Args:
            query: Query string to check
            
        Returns:
            True if query contains direct CWE references
        """
        return self.cwe_extractor.has_direct_cwe_reference(query)
    
    def validate_input(self, query: str) -> bool:
        """
        Validate input without full preprocessing (convenience method).
        
        Args:
            query: Query string to validate
            
        Returns:
            True if input passes security validation
        """
        try:
            self.sanitizer.sanitize(query)
            return True
        except (ValueError, TypeError):
            return False
    
    def get_security_report(self, query: str) -> Dict[str, Any]:
        """
        Get detailed security analysis report for a query.
        
        Args:
            query: Query string to analyze
            
        Returns:
            Detailed security analysis report
        """
        is_malicious, patterns = self.sanitizer.is_potentially_malicious(query)
        
        try:
            sanitized = self.sanitizer.sanitize(query)
            sanitization_success = True
        except (ValueError, TypeError) as e:
            sanitized = ""
            sanitization_success = False
        
        return {
            "input_length": len(query),
            "is_potentially_malicious": is_malicious,
            "detected_patterns": patterns,
            "sanitization_success": sanitization_success,
            "sanitized_length": len(sanitized),
            "changes_made": sanitized != query,
            "security_level": "high_risk" if is_malicious else "safe"
        }