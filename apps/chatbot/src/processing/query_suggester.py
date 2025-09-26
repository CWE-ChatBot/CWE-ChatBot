#!/usr/bin/env python3
"""
Query Suggester - Story 3.2
Provides persona-specific guidance for improving low-confidence queries.
"""

import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

# Maximum suggestions per query to avoid overwhelming users
MAX_SUGGESTIONS = 3

# Persona-specific improvement hints
PERSONA_HINTS = {
    "Developer": [
        "Add specific programming language or framework details",
        "Include the failing function or method name",
        "Mention error messages or stack traces if available",
        "Describe the specific code construct causing issues",
        "Add information about input validation or data handling"
    ],
    "PSIRT Member": [
        "Provide affected product name and version",
        "Add CVE identifier if known",
        "Include severity or impact assessment details",
        "Mention exploit vectors or attack scenarios",
        "Add vendor or product category information"
    ],
    "Academic Researcher": [
        "Include research methodology or analysis approach",
        "Add references to related vulnerabilities or papers",
        "Mention specific weakness categories of interest",
        "Include dataset or corpus being analyzed",
        "Add theoretical framework or classification system"
    ],
    "Bug Bounty Hunter": [
        "Add target application type or technology stack",
        "Include exploitation method or proof-of-concept details",
        "Mention affected endpoints or components",
        "Add vulnerability discovery context",
        "Include impact or business logic details"
    ],
    "Product Manager": [
        "Add product category or business domain",
        "Include timeline or release planning context",
        "Mention customer impact or security requirements",
        "Add compliance or regulatory considerations",
        "Include risk assessment or prioritization needs"
    ],
    "CWE Analyzer": [
        "Provide more technical details about the vulnerability",
        "Include specific attack vectors or exploitation methods",
        "Add context about the affected system or component",
        "Mention related security controls or mitigations",
        "Include vulnerability assessment or testing results"
    ],
    "CVE Creator": [
        "Add affected product name, version, and vendor information",
        "Include technical root cause details",
        "Provide attack vector and impact information",
        "Add proof-of-concept or exploitation details",
        "Include discovery timeline and disclosure status"
    ]
}

# General improvement hints that apply to all personas
GENERAL_HINTS = [
    "Be more specific about the technology or system involved",
    "Add context about how the vulnerability was discovered",
    "Include specific error conditions or failure scenarios",
    "Mention related security concepts or weakness categories",
    "Add information about the environment or deployment context"
]


class QuerySuggester:
    """
    Provides persona-specific suggestions for improving query quality.

    Features:
    - Role-based improvement hints tailored to user personas
    - Analysis of query characteristics to provide targeted advice
    - Limited suggestion count to avoid overwhelming users
    - Fallback to general hints if persona-specific hints aren't suitable
    """

    def __init__(self, max_suggestions: int = MAX_SUGGESTIONS):
        """
        Initialize query suggester.

        Args:
            max_suggestions: Maximum number of suggestions to provide (default: 3)
        """
        self.max_suggestions = max_suggestions
        logger.info(f"QuerySuggester initialized with max_suggestions={max_suggestions}")

    def suggest(self, query: str, persona: str, confidence_score: float = 0.0) -> List[str]:
        """
        Generate improvement suggestions for a query based on persona and confidence.

        Args:
            query: Original user query
            persona: User persona (Developer, PSIRT Member, etc.)
            confidence_score: Confidence score of the query results (0.0-1.0)

        Returns:
            List of improvement suggestions (max: max_suggestions)
        """
        if not query or not query.strip():
            return ["Please provide a more detailed query about your security concern."]

        logger.debug(f"Generating suggestions for persona={persona}, confidence={confidence_score:.3f}")

        # Analyze query characteristics
        query_analysis = self._analyze_query(query)

        # Get persona-specific hints
        persona_hints = self._get_persona_hints(persona, query_analysis)

        # Get general hints if needed
        general_hints = self._get_general_hints(query_analysis)

        # Combine and rank suggestions
        all_suggestions = persona_hints + general_hints
        ranked_suggestions = self._rank_suggestions(all_suggestions, query_analysis, confidence_score)

        # Return top suggestions
        return ranked_suggestions[:self.max_suggestions]

    def _analyze_query(self, query: str) -> Dict:
        """
        Analyze query characteristics to guide suggestion generation.

        Args:
            query: User query to analyze

        Returns:
            Dictionary with query analysis results
        """
        query_lower = query.lower()
        words = query_lower.split()

        analysis = {
            "word_count": len(words),
            "has_technical_terms": any(term in query_lower for term in
                                     ["sql", "xss", "buffer", "injection", "authentication", "crypto"]),
            "has_product_info": any(term in query_lower for term in
                                  ["version", "application", "system", "product", "software"]),
            "has_cwe_reference": "cwe" in query_lower,
            "has_specific_context": any(term in query_lower for term in
                                      ["function", "method", "endpoint", "component", "module"]),
            "is_very_short": len(words) < 4,
            "is_very_long": len(words) > 50,
            "has_questions": any(word in query_lower for word in
                               ["what", "how", "why", "when", "where", "which"]),
            "has_error_terms": any(term in query_lower for term in
                                 ["error", "fail", "crash", "exception", "bug"])
        }

        return analysis

    def _get_persona_hints(self, persona: str, analysis: Dict) -> List[str]:
        """
        Get persona-specific improvement hints.

        Args:
            persona: User persona
            analysis: Query analysis results

        Returns:
            List of persona-specific hints
        """
        persona_hints = PERSONA_HINTS.get(persona, [])
        if not persona_hints:
            return []

        # Filter hints based on query analysis
        relevant_hints = []

        for hint in persona_hints:
            hint_lower = hint.lower()

            # Skip hints that don't match query characteristics
            if "language" in hint_lower and analysis["has_technical_terms"]:
                continue
            if "product" in hint_lower and analysis["has_product_info"]:
                continue
            if "function" in hint_lower and analysis["has_specific_context"]:
                continue

            relevant_hints.append(hint)

        return relevant_hints

    def _get_general_hints(self, analysis: Dict) -> List[str]:
        """
        Get general improvement hints based on query analysis.

        Args:
            analysis: Query analysis results

        Returns:
            List of general hints
        """
        hints = []

        # Add hints based on missing elements
        if analysis["is_very_short"]:
            hints.append("Provide more detailed context about your security concern")

        if not analysis["has_technical_terms"]:
            hints.append("Include specific technical terms related to the vulnerability")

        if not analysis["has_specific_context"]:
            hints.append("Add details about the specific component or system affected")

        if analysis["has_questions"] and not analysis["has_cwe_reference"]:
            hints.append("Consider including CWE identifiers if known")

        # Add general hints if we don't have enough specific ones
        if len(hints) < 2:
            hints.extend(GENERAL_HINTS[:2])

        return hints

    def _rank_suggestions(self, suggestions: List[str], analysis: Dict, confidence_score: float) -> List[str]:
        """
        Rank suggestions by relevance to the query and confidence score.

        Args:
            suggestions: List of candidate suggestions
            analysis: Query analysis results
            confidence_score: Confidence score (lower = more suggestions needed)

        Returns:
            Ranked list of suggestions
        """
        if not suggestions:
            return ["Provide more specific details about your security concern."]

        # Remove duplicates while preserving order
        unique_suggestions = []
        seen = set()
        for suggestion in suggestions:
            if suggestion.lower() not in seen:
                unique_suggestions.append(suggestion)
                seen.add(suggestion.lower())

        # For very low confidence, prioritize more specific suggestions
        if confidence_score < 0.3:
            # Prioritize suggestions that ask for specific technical details
            technical_suggestions = [s for s in unique_suggestions
                                   if any(term in s.lower() for term in
                                        ["specific", "technical", "details", "context"])]
            other_suggestions = [s for s in unique_suggestions if s not in technical_suggestions]
            unique_suggestions = technical_suggestions + other_suggestions

        return unique_suggestions

    def get_persona_specific_intro(self, persona: str) -> str:
        """
        Get persona-specific introduction text for low-confidence guidance.

        Args:
            persona: User persona

        Returns:
            Introduction text tailored to the persona
        """
        intros = {
            "Developer": "To get more targeted CWE recommendations for your development context:",
            "PSIRT Member": "To improve CWE mapping accuracy for your security advisory:",
            "Academic Researcher": "To enhance CWE analysis results for your research:",
            "Bug Bounty Hunter": "To get better CWE classifications for your vulnerability findings:",
            "Product Manager": "To get more actionable CWE insights for product planning:",
            "CWE Analyzer": "To improve the accuracy of your CWE vulnerability analysis:",
            "CVE Creator": "To create more precise CVE-to-CWE mappings:"
        }

        return intros.get(persona, "To get more accurate CWE recommendations:")

    def generate_improvement_banner(self, query: str, persona: str, confidence_score: float) -> Dict:
        """
        Generate complete improvement guidance banner for low-confidence queries.

        Args:
            query: Original user query
            persona: User persona
            confidence_score: Confidence score

        Returns:
            Dictionary with banner components:
            {
                "show_banner": bool,
                "intro": str,
                "suggestions": List[str],
                "confidence_level": str
            }
        """
        # Show banner for low and very low confidence
        show_banner = confidence_score < 0.6

        if not show_banner:
            return {"show_banner": False}

        intro = self.get_persona_specific_intro(persona)
        suggestions = self.suggest(query, persona, confidence_score)

        confidence_level = "Very Low" if confidence_score < 0.4 else "Low"

        return {
            "show_banner": True,
            "intro": intro,
            "suggestions": suggestions,
            "confidence_level": confidence_level
        }