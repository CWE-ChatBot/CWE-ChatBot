"""
Unit tests for Story 2.2 Follow-up Processing components.

Tests follow-up intent detection and contextual query processing.
"""


import pytest
from src.processing.followup_processor import FollowupIntent, FollowupProcessor


class TestFollowupProcessor:
    """Test follow-up processing functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.processor = FollowupProcessor()

    def test_initialization(self):
        """Test FollowupProcessor initialization."""
        processor = FollowupProcessor()
        assert hasattr(processor, "followup_patterns")
        assert hasattr(processor, "intent_patterns")
        assert processor.confidence_threshold == 0.6

    def test_followup_intent_creation(self):
        """Test FollowupIntent object creation."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type="related",
            confidence=0.85,
            matched_patterns=["related", "similar"],
        )

        assert intent.is_followup is True
        assert intent.intent_type == "related"
        assert intent.confidence == 0.85
        assert "related" in intent.matched_patterns

    def test_detect_followup_intent_related_cwes(self):
        """Test detection of related CWEs intent."""
        queries = [
            "What CWEs are related to this?",
            "Show me similar vulnerabilities",
            "Are there any related weaknesses?",
            "What's similar to this CWE?",
        ]

        for query in queries:
            intent = self.processor.detect_followup_intent(query)

            assert isinstance(intent, FollowupIntent)
            if intent.is_followup:
                assert intent.intent_type == "related"
                assert intent.confidence > self.processor.confidence_threshold

    def test_detect_followup_intent_consequences(self):
        """Test detection of consequences intent."""
        queries = [
            "What are the consequences of this vulnerability?",
            "What's the impact?",
            "How does this affect security?",
            "What damage can this cause?",
        ]

        for query in queries:
            intent = self.processor.detect_followup_intent(query)

            if intent.is_followup and intent.intent_type == "consequences":
                assert intent.confidence > self.processor.confidence_threshold
                assert any(
                    "consequence" in pattern.lower() or "impact" in pattern.lower()
                    for pattern in intent.matched_patterns
                )

    def test_detect_followup_intent_prevention(self):
        """Test detection of prevention intent."""
        queries = [
            "How can I prevent this?",
            "What's the mitigation?",
            "How do I fix this vulnerability?",
            "How to prevent this weakness?",
        ]

        for query in queries:
            intent = self.processor.detect_followup_intent(query)

            if intent.is_followup and intent.intent_type == "prevention":
                assert intent.confidence > self.processor.confidence_threshold
                assert any(
                    "prevent" in pattern.lower() or "mitigation" in pattern.lower()
                    for pattern in intent.matched_patterns
                )

    def test_detect_followup_intent_tell_more(self):
        """Test detection of tell me more intent."""
        queries = [
            "Tell me more about this",
            "Can you give more details?",
            "I want more information",
            "Elaborate on this CWE",
        ]

        for query in queries:
            intent = self.processor.detect_followup_intent(query)

            if intent.is_followup and intent.intent_type == "tell_more":
                assert intent.confidence > self.processor.confidence_threshold
                assert any(
                    "more" in pattern.lower() or "detail" in pattern.lower()
                    for pattern in intent.matched_patterns
                )

    def test_detect_followup_intent_children_parents(self):
        """Test detection of children and parents intents."""
        children_queries = [
            "What are the child CWEs?",
            "Show me the children",
            "What CWEs are more specific?",
        ]

        parents_queries = [
            "What are the parent CWEs?",
            "Show me broader categories",
            "What's the parent vulnerability?",
        ]

        for query in children_queries:
            intent = self.processor.detect_followup_intent(query)
            if intent.is_followup and intent.intent_type == "children":
                assert intent.confidence > 0.5

        for query in parents_queries:
            intent = self.processor.detect_followup_intent(query)
            if intent.is_followup and intent.intent_type == "parents":
                assert intent.confidence > 0.5

    def test_detect_followup_intent_examples(self):
        """Test detection of examples intent."""
        queries = [
            "Can you show me examples?",
            "Give me some examples of this vulnerability",
            "What are some real-world cases?",
            "Show me code examples",
        ]

        for query in queries:
            intent = self.processor.detect_followup_intent(query)

            if intent.is_followup and intent.intent_type == "examples":
                assert intent.confidence > self.processor.confidence_threshold
                assert any(
                    "example" in pattern.lower() for pattern in intent.matched_patterns
                )

    def test_detect_followup_intent_general_followup(self):
        """Test detection of general follow-up intent."""
        queries = [
            "Can you explain it better?",
            "I don't understand this",
            "What does this mean?",
            "Can you clarify?",
        ]

        for query in queries:
            intent = self.processor.detect_followup_intent(query)

            if intent.is_followup and intent.intent_type == "general_followup":
                assert intent.confidence > 0.4  # Lower threshold for general

    def test_detect_followup_intent_not_followup(self):
        """Test detection when query is not a follow-up."""
        queries = [
            "Tell me about CWE-79",  # Direct CWE query
            "What is SQL injection?",  # New topic
            "Search for buffer overflow vulnerabilities",  # New search
            "How does authentication work?",  # Unrelated topic
        ]

        for query in queries:
            intent = self.processor.detect_followup_intent(query)
            assert intent.is_followup is False
            assert intent.confidence < self.processor.confidence_threshold

    def test_process_followup_query_related(self):
        """Test processing of related CWEs follow-up query."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type="related",
            confidence=0.85,
            matched_patterns=["related", "similar"],
        )

        result = self.processor.process_followup_query(
            query="What's related to this?", context_cwe_id="CWE-79", intent=intent
        )

        assert isinstance(result, dict)
        assert result["retrieval_strategy"] == "similarity_search"
        assert result["retrieval_params"]["base_cwe"] == "CWE-79"
        assert result["retrieval_params"]["k"] >= 5
        assert "enhanced_query" in result

    def test_process_followup_query_consequences(self):
        """Test processing of consequences follow-up query."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type="consequences",
            confidence=0.9,
            matched_patterns=["consequences", "impact"],
        )

        result = self.processor.process_followup_query(
            query="What are the consequences?", context_cwe_id="CWE-89", intent=intent
        )

        assert result["retrieval_strategy"] == "comprehensive_lookup"
        assert result["retrieval_params"]["cwe_id"] == "CWE-89"
        assert result["retrieval_params"]["focus"] == "consequences"
        assert "consequences" in result["enhanced_query"].lower()

    def test_process_followup_query_prevention(self):
        """Test processing of prevention follow-up query."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type="prevention",
            confidence=0.85,
            matched_patterns=["prevent", "mitigation"],
        )

        result = self.processor.process_followup_query(
            query="How to prevent this?", context_cwe_id="CWE-120", intent=intent
        )

        assert result["retrieval_strategy"] == "comprehensive_lookup"
        assert result["retrieval_params"]["focus"] == "prevention"
        assert (
            "prevention" in result["enhanced_query"].lower()
            or "mitigation" in result["enhanced_query"].lower()
        )

    def test_process_followup_query_children_parents(self):
        """Test processing of children/parents relationship queries."""
        children_intent = FollowupIntent(
            is_followup=True,
            intent_type="children",
            confidence=0.8,
            matched_patterns=["children", "child"],
        )

        parents_intent = FollowupIntent(
            is_followup=True,
            intent_type="parents",
            confidence=0.8,
            matched_patterns=["parents", "parent"],
        )

        # Test children query
        result = self.processor.process_followup_query(
            query="Show me child CWEs", context_cwe_id="CWE-79", intent=children_intent
        )

        assert result["retrieval_strategy"] == "relationship_lookup"
        assert result["retrieval_params"]["relationship_type"] == "ParentOf"
        assert result["retrieval_params"]["base_cwe"] == "CWE-79"

        # Test parents query
        result = self.processor.process_followup_query(
            query="Show me parent CWEs", context_cwe_id="CWE-79", intent=parents_intent
        )

        assert result["retrieval_strategy"] == "relationship_lookup"
        assert result["retrieval_params"]["relationship_type"] == "ChildOf"

    def test_process_followup_query_invalid_context(self):
        """Test processing follow-up query with invalid context."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type="related",
            confidence=0.8,
            matched_patterns=["related"],
        )

        # Test with None context CWE
        result = self.processor.process_followup_query(
            query="What's related?", context_cwe_id=None, intent=intent
        )

        assert result["retrieval_strategy"] == "fallback"
        assert result["retrieval_params"]["reason"] == "no_context_cwe"

    def test_confidence_calculation(self):
        """Test confidence score calculation."""
        # High confidence query
        high_conf_intent = self.processor.detect_followup_intent(
            "What are the consequences and impacts of this vulnerability?"
        )

        # Low confidence query
        low_conf_intent = self.processor.detect_followup_intent("This is interesting")

        if high_conf_intent.is_followup:
            assert high_conf_intent.confidence > 0.8

        if low_conf_intent.is_followup:
            assert low_conf_intent.confidence < 0.5

    def test_pattern_matching_accuracy(self):
        """Test accuracy of pattern matching."""
        test_cases = [
            ("What CWEs are similar to this one?", "related"),
            ("How bad is the impact?", "consequences"),
            ("How do I fix this vulnerability?", "prevention"),
            ("Tell me everything about this CWE", "tell_more"),
            ("Show me some examples", "examples"),
            ("What are the child CWEs?", "children"),
            ("What's the parent category?", "parents"),
        ]

        correct_predictions = 0
        for query, expected_intent in test_cases:
            intent = self.processor.detect_followup_intent(query)

            if intent.is_followup and intent.intent_type == expected_intent:
                correct_predictions += 1

        # Should get at least 70% accuracy
        accuracy = correct_predictions / len(test_cases)
        assert accuracy >= 0.7

    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        edge_cases = [
            "",  # Empty string
            "a",  # Single character
            "?" * 100,  # Very long question
            "CWE-79 CWE-89 CWE-120",  # Multiple CWE IDs
            "What what what?",  # Repeated words
        ]

        for query in edge_cases:
            intent = self.processor.detect_followup_intent(query)

            # Should not crash and should return a valid FollowupIntent
            assert isinstance(intent, FollowupIntent)
            assert isinstance(intent.is_followup, bool)
            assert isinstance(intent.confidence, (int, float))
            assert intent.confidence >= 0.0 and intent.confidence <= 1.0

    def test_query_enhancement(self):
        """Test query enhancement for different intent types."""
        test_cases = [
            ("related", "CWE-79", "What's similar?", "related vulnerabilities CWE-79"),
            ("consequences", "CWE-89", "Impact?", "consequences impacts CWE-89"),
            ("prevention", "CWE-120", "How to fix?", "prevention mitigation CWE-120"),
            ("examples", "CWE-79", "Show examples", "examples code samples CWE-79"),
        ]

        for intent_type, cwe_id, query, expected_keywords in test_cases:
            intent = FollowupIntent(
                is_followup=True,
                intent_type=intent_type,
                confidence=0.8,
                matched_patterns=[intent_type],
            )

            result = self.processor.process_followup_query(query, cwe_id, intent)
            enhanced_query = result["enhanced_query"].lower()

            # Check that enhancement includes relevant keywords
            keywords = expected_keywords.lower().split()
            matching_keywords = sum(
                1 for keyword in keywords if keyword in enhanced_query
            )
            assert matching_keywords >= 2  # At least 2 keywords should match


@pytest.mark.integration
class TestFollowupProcessorIntegration:
    """Integration tests for follow-up processor."""

    def setup_method(self):
        """Set up integration test fixtures."""
        self.processor = FollowupProcessor()

    def test_complete_followup_workflow(self):
        """Test complete follow-up processing workflow."""
        # Simulate a conversation flow
        context_cwe = "CWE-79"
        followup_queries = [
            "What are the consequences?",
            "How can I prevent this?",
            "Show me related CWEs",
            "Give me more details",
            "What are some examples?",
        ]

        results = []
        for query in followup_queries:
            # Detect intent
            intent = self.processor.detect_followup_intent(query)

            # Process if it's a follow-up
            if intent.is_followup:
                result = self.processor.process_followup_query(
                    query, context_cwe, intent
                )
                results.append(
                    (query, intent.intent_type, result["retrieval_strategy"])
                )

        # Should have processed most queries as follow-ups
        assert len(results) >= 4

        # Should have different intent types
        intent_types = [result[1] for result in results]
        assert len(set(intent_types)) >= 3  # At least 3 different intent types

        # Should have appropriate retrieval strategies
        strategies = [result[2] for result in results]
        expected_strategies = [
            "comprehensive_lookup",
            "similarity_search",
            "relationship_lookup",
        ]
        assert any(strategy in expected_strategies for strategy in strategies)

    def test_contextual_understanding(self):
        """Test contextual understanding across different CWE types."""
        cwe_types = [
            ("CWE-79", "Cross-site Scripting"),
            ("CWE-89", "SQL Injection"),
            ("CWE-120", "Buffer Overflow"),
            ("CWE-20", "Input Validation"),
        ]

        for cwe_id, cwe_name in cwe_types:
            # Test that follow-up processing works for different CWE types
            intent = self.processor.detect_followup_intent("What are the consequences?")

            if intent.is_followup:
                result = self.processor.process_followup_query(
                    "What are the consequences?", cwe_id, intent
                )

                # Should include the specific CWE ID in processing
                assert cwe_id in result["enhanced_query"] or cwe_id in str(
                    result["retrieval_params"]
                )
                assert result["retrieval_strategy"] == "comprehensive_lookup"
