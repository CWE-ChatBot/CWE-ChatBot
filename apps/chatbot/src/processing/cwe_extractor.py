"""
CWE ID extraction module for detecting direct CWE references in user queries.
"""

import logging
import re
from typing import Any, Dict, Set

logger = logging.getLogger(__name__)


class CWEExtractor:
    """
    Extracts CWE IDs and related security terms from user queries.

    Provides both direct CWE ID matching and security-related keyphrase extraction
    for hybrid retrieval systems.
    """

    # Regex pattern for CWE IDs - matches both CWE-XXX and CWE XXX formats
    CWE_PATTERN = re.compile(
        r"(?:^|(?<=\s)|(?<=[(,.:;!?]))CWE[-\s](\d+)", re.IGNORECASE
    )

    # Security-related keywords for keyphrase extraction
    SECURITY_KEYWORDS = {
        "vulnerability_types": [
            "injection",
            "sql injection",
            "xss",
            "cross-site scripting",
            "buffer overflow",
            "overflow",
            "underflow",
            "authentication",
            "authorization",
            "access control",
            "cryptographic",
            "encryption",
            "hashing",
            "path traversal",
            "directory traversal",
            "command injection",
            "code injection",
            "deserialization",
            "serialization",
            "race condition",
            "concurrency",
            "information disclosure",
            "information leak",
            "denial of service",
            "dos",
            "resource exhaustion",
            "input validation",
            "sanitization",
            "session management",
            "session fixation",
            "csrf",
            "cross-site request forgery",
            "clickjacking",
            "frame injection",
        ],
        "security_terms": [
            "security",
            "vulnerability",
            "weakness",
            "security flaw",
            "security bug",
            "exploit",
            "attack",
            "threat",
            "risk",
            "secure",
            "insecure",
            "unsafe",
            "safe",
            "malicious",
            "adversary",
            "attacker",
            "mitigation",
            "prevention",
            "protection",
            "defense",
            "validation",
            "verification",
            "authentication",
            "authorization",
            "privilege",
            "permission",
        ],
        "programming_contexts": [
            "c programming",
            "c++",
            "java",
            "python",
            "javascript",
            "web application",
            "web app",
            "api",
            "database",
            "memory management",
            "pointer",
            "array",
            "function",
            "method",
            "class",
            "variable",
            "input",
            "output",
            "user input",
            "user data",
        ],
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
        return bool(self.CWE_PATTERN.search(text))

    def extract_keyphrases(self, text: str) -> Dict[str, Any]:
        """
        Extract security-related keyphrases for enhanced retrieval.

        Args:
            text: Input text to analyze

        Returns:
            Dictionary containing extracted keyphrases by category
        """
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
        prevention_terms = [
            "prevent",
            "avoid",
            "mitigate",
            "fix",
            "secure",
            "protection",
        ]
        if any(term in text_lower for term in prevention_terms):
            return "prevention_guidance"

        # Check for specific vulnerability types
        vuln_keywords = self.SECURITY_KEYWORDS["vulnerability_types"]
        for keyword in vuln_keywords:
            if keyword in text_lower:
                return "vulnerability_inquiry"

        # Check if it's about programming (more specific, higher priority)
        prog_terms = self.SECURITY_KEYWORDS["programming_contexts"]
        if any(term in text_lower for term in prog_terms):
            return "programming_security"

        # Check for general security terms
        security_terms = self.SECURITY_KEYWORDS["security_terms"]
        if any(term in text_lower for term in security_terms):
            return "general_security"

        # NEW: Check if query is completely off-topic before defaulting
        if self._is_off_topic_query(text_lower):
            return "off_topic"

        return "general_query"

    def _is_off_topic_query(self, text_lower: str) -> bool:
        """
        Detect queries that are completely unrelated to cybersecurity.

        Args:
            text_lower: Lowercase text to analyze

        Returns:
            True if query appears to be off-topic
        """
        # Common non-security topics that should be redirected
        off_topic_indicators = [
            # Animals
            "dog",
            "cat",
            "animal",
            "pet",
            "puppy",
            "kitten",
            # Food
            "recipe",
            "cooking",
            "food",
            "meal",
            "restaurant",
            # Weather
            "weather",
            "rain",
            "sunny",
            "temperature",
            "climate",
            # Sports
            "football",
            "soccer",
            "basketball",
            "baseball",
            "game",
            # Entertainment
            "movie",
            "film",
            "music",
            "song",
            "tv show",
            "celebrity",
            # General knowledge
            "what is a",
            "who is",
            "where is",
            "when did",
            "how tall",
            # Geography
            "country",
            "city",
            "capital",
            "mountain",
            "ocean",
            # Basic math/science (unless security-related)
            "add",
            "subtract",
            "multiply",
            "divide",
            "equation",
        ]

        # Count off-topic indicators
        off_topic_count = sum(
            1 for indicator in off_topic_indicators if indicator in text_lower
        )

        # If multiple off-topic terms or very obvious patterns
        if off_topic_count >= 2:
            return True

        # Check for very obvious non-security patterns
        obvious_patterns = [
            "what is a dog",
            "what is a cat",
            "what is an animal",
            "how to cook",
            "recipe for",
            "weather today",
            "who is the president",
            "capital of",
            "movie about",
        ]

        return any(pattern in text_lower for pattern in obvious_patterns)

    def enhance_query_for_search(self, text: str) -> Dict[str, Any]:
        """
        Enhance query with extracted information for improved search.

        Args:
            text: Original user query

        Returns:
            Dictionary with enhanced query information including expanded terms
        """
        # Get base query classification
        query_type = self.classify_query_type(text)

        # Map internal types to expected external types
        type_mapping = {
            "direct_cwe_lookup": "direct_cwe_lookup",
            "prevention_guidance": "prevention_guidance",
            "vulnerability_inquiry": "vulnerability_inquiry",
            "programming_security": "general_security",
            "general_security": "general_security",
            "general_query": "general_security",
            "off_topic": "off_topic",  # NEW: Handle off-topic queries
            "unknown": "general_security",
        }

        mapped_type = type_mapping.get(query_type, "general_security")

        # Generate enhanced query with relevant expansions
        enhanced_query = self._generate_enhanced_query(text, mapped_type)

        return {
            "query_type": mapped_type,
            "cwe_ids": self.extract_cwe_ids(text),
            "keyphrases": self.extract_keyphrases(text),
            "enhanced_query": enhanced_query,
        }

    def _generate_enhanced_query(self, original: str, query_type: str) -> str:
        """
        Generate enhanced query with expanded terms for better retrieval.

        Args:
            original: Original query text
            query_type: Classified query type

        Returns:
            Enhanced query string with relevant expansions
        """
        enhanced = original

        # Add CWE-specific expansions
        cwe_ids = self.extract_cwe_ids(original)
        for cwe_id in cwe_ids:
            if cwe_id == "CWE-79":
                enhanced += " cross-site scripting XSS injection script"
            elif cwe_id == "CWE-89":
                enhanced += " SQL injection database query"
            elif cwe_id == "CWE-787":
                enhanced += " buffer overflow memory corruption"
            elif cwe_id == "CWE-22":
                enhanced += " path traversal directory traversal"

        # Add query type specific terms
        if query_type == "prevention_guidance":
            enhanced += " mitigation prevention secure coding best practices"
        elif query_type == "vulnerability_inquiry":
            enhanced += " vulnerability weakness security flaw exploit"

        return enhanced
