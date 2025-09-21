"""
CWE ID extraction module for detecting direct CWE references in user queries.
"""

import re
import logging
from typing import List, Set, Dict, Any


logger = logging.getLogger(__name__)


class CWEExtractor:
    """
    Extracts CWE IDs and related security terms from user queries.
    
    Provides both direct CWE ID matching and security-related keyphrase extraction
    for hybrid retrieval systems.
    """
    
    # Regex pattern for CWE IDs (CWE-XXX format) - allow start/whitespace/punctuation but not after dash or alphanumeric
    CWE_PATTERN = re.compile(r'(?:^|(?<=\s)|(?<=[(,.:;!?]))CWE-(\d+)', re.IGNORECASE)
    
    # Security-related keywords for keyphrase extraction
    SECURITY_KEYWORDS = {
        'vulnerability_types': [
            'injection', 'sql injection', 'xss', 'cross-site scripting',
            'buffer overflow', 'overflow', 'underflow',
            'authentication', 'authorization', 'access control',
            'cryptographic', 'encryption', 'hashing',
            'path traversal', 'directory traversal',
            'command injection', 'code injection',
            'deserialization', 'serialization',
            'race condition', 'concurrency',
            'information disclosure', 'information leak',
            'denial of service', 'dos', 'resource exhaustion',
            'input validation', 'sanitization',
            'session management', 'session fixation',
            'csrf', 'cross-site request forgery',
            'clickjacking', 'frame injection'
        ],
        'security_terms': [
            'security', 'vulnerability', 'weakness', 'security flaw', 'security bug',
            'exploit', 'attack', 'threat', 'risk',
            'secure', 'insecure', 'unsafe', 'safe',
            'malicious', 'adversary', 'attacker',
            'mitigation', 'prevention', 'protection', 'defense',
            'validation', 'verification', 'authentication',
            'authorization', 'privilege', 'permission'
        ],
        'programming_contexts': [
            'c programming', 'c++', 'java', 'python', 'javascript',
            'web application', 'web app', 'api', 'database',
            'memory management', 'pointer', 'array',
            'function', 'method', 'class', 'variable',
            'input', 'output', 'user input', 'user data'
        ]
    }
    
    def __init__(self) -> None:
        """Initialize the CWE extractor."""
        pass
    
    def extract_cwe_ids(self, text: str) -> Set[str]:
        """
        Extract all CWE IDs from the given text.
        
        Args:
            text: Input text to search for CWE IDs
            
        Returns:
            Set of CWE IDs found in format "CWE-XXX"
        """
        if not isinstance(text, str):
            return set()
        
        matches = self.CWE_PATTERN.findall(text)
        cwe_ids = {f"CWE-{match}" for match in matches}
        
        if cwe_ids:
            logger.debug(f"Extracted CWE IDs: {cwe_ids}")
        
        return cwe_ids
    
    def has_direct_cwe_reference(self, text: str) -> bool:
        """
        Check if text contains direct CWE ID references.
        
        Args:
            text: Input text to check
            
        Returns:
            True if text contains at least one CWE ID
        """
        if not isinstance(text, str):
            return False
        
        return bool(self.CWE_PATTERN.search(text))
    
    def extract_keyphrases(self, text: str) -> Dict[str, Any]:
        """
        Extract security-related keyphrases for enhanced retrieval.
        
        Args:
            text: Input text to analyze
            
        Returns:
            Dictionary containing extracted keyphrases by category
        """
        if not isinstance(text, str):
            return {}
        
        text_lower = text.lower()
        extracted = {}
        
        for category, keywords in self.SECURITY_KEYWORDS.items():
            matches = []
            for keyword in keywords:
                if keyword.lower() in text_lower:
                    matches.append(keyword)
            
            if matches:
                extracted[category] = list(set(matches))  # Remove duplicates
        
        if extracted:
            logger.debug(f"Extracted keyphrases: {extracted}")
        
        return extracted
    
    def classify_query_type(self, text: str) -> str:
        """
        Classify the type of security query based on content.
        
        Args:
            text: Input text to classify
            
        Returns:
            String classification of query type
        """
        if not isinstance(text, str) or not text.strip():
            return "unknown"
        
        text_lower = text.lower()
        
        # Check for direct CWE reference
        if self.has_direct_cwe_reference(text):
            return "direct_cwe_lookup"
        
        # Check for prevention/mitigation queries FIRST (higher priority)
        prevention_terms = ['prevent', 'avoid', 'mitigate', 'fix', 'secure', 'protection']
        if any(term in text_lower for term in prevention_terms):
            return "prevention_guidance"
        
        # Check for specific vulnerability types
        vuln_keywords = self.SECURITY_KEYWORDS['vulnerability_types']
        for keyword in vuln_keywords:
            if keyword in text_lower:
                return "vulnerability_inquiry"
        
        # Check if it's about programming (more specific, higher priority)
        prog_terms = self.SECURITY_KEYWORDS['programming_contexts']
        if any(term in text_lower for term in prog_terms):
            return "programming_security"
        
        # Check for general security terms
        security_terms = self.SECURITY_KEYWORDS['security_terms']
        if any(term in text_lower for term in security_terms):
            return "general_security"
        
        return "general_query"
    
    def enhance_query_for_search(self, text: str) -> Dict[str, Any]:
        """
        Enhance query with extracted information for improved search.
        
        Args:
            text: Original user query
            
        Returns:
            Dictionary with enhanced query information
        """
        return {
            'original_query': text,
            'cwe_ids': self.extract_cwe_ids(text),
            'keyphrases': self.extract_keyphrases(text),
            'query_type': self.classify_query_type(text),
            'has_direct_cwe': self.has_direct_cwe_reference(text)
        }