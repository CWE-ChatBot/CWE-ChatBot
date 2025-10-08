"""
Query processor for enhanced retrieval with security-first design.
Integrates input sanitization, CWE extraction, and query enhancement.
"""

import logging
from typing import Any, Dict, Optional, Set

from ..input_security import InputSanitizer
from .cwe_extractor import CWEExtractor

# Story 2.2: Follow-up processing imports
from .followup_processor import FollowupProcessor

logger = logging.getLogger(__name__)


class QueryProcessor:
    """
    Processes queries for enhanced retrieval with security safeguards.

    Combines input sanitization, CWE ID extraction, and keyphrase analysis
    to prepare queries for hybrid retrieval systems.
    """

    def __init__(self, max_input_length: int = 1000, strict_mode: bool = True):
        """
        Initialize the query processor.

        Args:
            max_input_length: Maximum allowed input length
            strict_mode: If True, reject malicious inputs
        """
        self.sanitizer = InputSanitizer()
        self.cwe_extractor = CWEExtractor()

        # Story 2.2: Follow-up processor initialization
        self.followup_processor = FollowupProcessor()

        logger.info(
            "Initialized QueryProcessor with security-first design and follow-up support"
        )

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
            sanitization_result = self.sanitizer.sanitize_input(query)
            sanitized_query = sanitization_result["sanitized_input"]

            # Step 2: Security analysis
            is_malicious = not sanitization_result["is_safe"]
            detected_patterns = sanitization_result["security_flags"]

            # Step 3: CWE extraction and analysis
            cwe_analysis = self.cwe_extractor.enhance_query_for_search(sanitized_query)
            has_direct = self.cwe_extractor.has_direct_cwe_reference(sanitized_query)

            # Step 4: Build comprehensive result
            analysis = {
                # Original and processed queries
                "original_query": query,
                "sanitized_query": sanitized_query,
                # Security analysis
                "security_check": {
                    "is_potentially_malicious": is_malicious,
                    "detected_patterns": detected_patterns,
                    "sanitization_applied": sanitized_query != query,
                },
                # CWE analysis
                "cwe_ids": cwe_analysis["cwe_ids"],
                "keyphrases": cwe_analysis["keyphrases"],
                "query_type": cwe_analysis["query_type"],
                "has_direct_cwe": has_direct,
                "enhanced_query": cwe_analysis["enhanced_query"],
            }

            # Query routing information based on the assembled analysis dict
            analysis["search_strategy"] = self._determine_search_strategy(analysis)
            analysis["boost_factors"] = self._calculate_boost_factors(analysis)

            logger.debug(f"Query preprocessing completed: {analysis['query_type']}")
            return analysis

        except Exception as e:
            logger.error(f"Query preprocessing failed: {e}")
            raise

    def _determine_search_strategy(self, analysis: Dict[str, Any]) -> str:
        """
        Determine the optimal search strategy based on query analysis.

        Args:
            cwe_analysis: Results from CWE extraction

        Returns:
            Recommended search strategy
        """
        # Direct CWE lookup for explicit CWE references
        if analysis.get("has_direct_cwe"):
            return "direct_lookup"

        # Hybrid search for complex security queries
        query_type = analysis["query_type"]
        if query_type == "direct_cwe_lookup":
            return "direct_lookup"
        if query_type in ["vulnerability_inquiry", "prevention_guidance"]:
            return "hybrid_search"

        # Dense search for general security concepts
        if query_type in ["general_security", "programming_security"]:
            return "dense_search"

        # Sparse search for keyword-heavy queries
        if analysis["keyphrases"]:
            return "sparse_search"

        # Default to hybrid for unknown query types
        return "hybrid_search"

    def _calculate_boost_factors(self, analysis: Dict[str, Any]) -> Dict[str, float]:
        """
        Calculate boost factors for different retrieval methods.

        Args:
            cwe_analysis: Results from CWE extraction

        Returns:
            Dictionary of boost factors for dense/sparse methods
        """
        boost_factors = {"dense": 1.0, "sparse": 1.0}

        # Boost sparse search for keyword-rich queries
        if analysis["keyphrases"]:
            keyphrase_count = sum(
                len(phrases) for phrases in analysis["keyphrases"].values()
            )
            boost_factors["sparse"] = 1.0 + (keyphrase_count * 0.1)

        # Boost dense search for conceptual queries
        query_type = analysis["query_type"]
        if query_type in ["general_security", "prevention_guidance"]:
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
            sanitization_result = self.sanitizer.sanitize_input(query)
            return (
                bool(sanitization_result["is_safe"])
                if isinstance(sanitization_result, dict)
                else False
            )
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
        sanitization_result = self.sanitizer.sanitize_input(query)
        sanitized_query = sanitization_result["sanitized_input"]

        return {
            "input_length": len(query),
            "is_potentially_malicious": not sanitization_result["is_safe"],
            "detected_patterns": sanitization_result["security_flags"],
            "sanitization_success": sanitization_result["is_safe"],
            "sanitized_length": len(sanitized_query),
            "changes_made": sanitized_query != query,
            "security_level": "high_risk"
            if not sanitization_result["is_safe"]
            else "safe",
        }

    # Story 2.2: Context-aware processing methods

    def process_with_context(
        self, query: str, session_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Enhanced processing with session context awareness for follow-up queries.

        Args:
            query: User query string
            session_context: Current session context (current CWE, history, etc.)

        Returns:
            Enhanced processing results with context and follow-up intent
        """
        if not query or not query.strip():
            raise ValueError("Empty query provided")

        try:
            # Start with standard preprocessing
            base_result = self.preprocess_query(query)

            # Add context-aware processing
            context_cwe = None
            if session_context:
                # Prefer explicit current_cwe if present; otherwise use the most recently discussed CWE
                if isinstance(session_context.get("current_cwe"), dict):
                    context_cwe = session_context["current_cwe"].get("cwe_id")
                elif session_context.get("last_cwes"):
                    last = session_context.get("last_cwes") or []
                    if isinstance(last, list) and last:
                        # Use most relevant/most recent CWE first (ConversationManager prioritizes direct requests first)
                        context_cwe = last[0]

            # Detect follow-up intent
            followup_intent = self.followup_processor.detect_followup_intent(query)

            # If it's a follow-up and we have context, process contextually
            if followup_intent.is_followup and context_cwe:
                followup_result = self.followup_processor.process_followup_query(
                    query, context_cwe, followup_intent
                )

                # Merge results
                base_result.update(
                    {
                        "is_followup": True,
                        "followup_intent": followup_intent,
                        "context_cwe": context_cwe,
                        "enhanced_query": followup_result.get("enhanced_query", query),
                        "retrieval_strategy": followup_result.get(
                            "retrieval_strategy", "hybrid"
                        ),
                        "retrieval_params": followup_result.get("retrieval_params", {}),
                        "contextual_processing": True,
                    }
                )

                logger.info(
                    f"Processed follow-up query: {followup_intent.intent_type} for {context_cwe}"
                )

            else:
                # Standard processing without context
                base_result.update(
                    {
                        "is_followup": False,
                        "followup_intent": followup_intent,
                        "context_cwe": None,
                        "contextual_processing": False,
                    }
                )

            return base_result

        except Exception as e:
            logger.error(f"Context-aware query processing failed: {e}")
            # Fallback to basic processing
            base_result = self.preprocess_query(query)
            base_result.update(
                {
                    "is_followup": False,
                    "contextual_processing": False,
                    "processing_error": str(e),
                }
            )
            return base_result
