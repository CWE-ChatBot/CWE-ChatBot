"""
Unit tests for fallback response strategies.

Tests the R18 Phase 2 refactoring of _generate_contextual_fallback_answer().
"""

import pytest

from apps.chatbot.src.fallback_strategies import (
    DominantCWEStrategy,
    ExplicitCWEStrategy,
    MultiCWEBriefStrategy,
)


def make_chunk(cwe_id: str, name: str, section: str, content: str, score: float = 0.8):
    """Helper to create test chunk."""
    return {
        "metadata": {"cwe_id": cwe_id, "name": name, "section": section},
        "document": content,
        "scores": {"hybrid": score},
    }


class TestExplicitCWEStrategy:
    """Test ExplicitCWEStrategy for queries mentioning specific CWEs."""

    def test_supports_explicit_cwe_mention(self):
        """Test strategy supports queries with explicit CWE mention."""
        chunks = [
            make_chunk("CWE-79", "Cross-site Scripting", "Abstract", "XSS vulnerability"),
            make_chunk("CWE-89", "SQL Injection", "Abstract", "SQL injection vulnerability"),
        ]

        strategy = ExplicitCWEStrategy()

        assert strategy.supports("Tell me about CWE-79", chunks) is True
        assert strategy.supports("What is CWE-89?", chunks) is True
        assert strategy.supports("Explain CWE 79 to me", chunks) is True  # Space variant

    def test_does_not_support_without_cwe_mention(self):
        """Test strategy does not support queries without CWE mention."""
        chunks = [make_chunk("CWE-79", "XSS", "Abstract", "XSS vulnerability")]

        strategy = ExplicitCWEStrategy()

        assert strategy.supports("What are injection attacks?", chunks) is False
        assert strategy.supports("security vulnerabilities", chunks) is False

    def test_does_not_support_unmatched_cwe(self):
        """Test strategy does not support when mentioned CWE not in results."""
        chunks = [make_chunk("CWE-79", "XSS", "Abstract", "XSS vulnerability")]

        strategy = ExplicitCWEStrategy()

        assert strategy.supports("Tell me about CWE-89", chunks) is False

    def test_respond_generates_single_cwe_response(self):
        """Test response generation for explicit CWE."""
        chunks = [
            make_chunk(
                "CWE-79",
                "Cross-site Scripting (XSS)",
                "Abstract",
                "XSS occurs when untrusted data is sent to a web browser without proper validation.",
                0.9,
            ),
            make_chunk(
                "CWE-79",
                "Cross-site Scripting (XSS)",
                "Mitigations",
                "Use output encoding and Content Security Policy.",
                0.8,
            ),
        ]

        strategy = ExplicitCWEStrategy()
        response = strategy.respond("Tell me about CWE-79", "Developer", chunks)

        assert "CWE-79" in response
        assert "Cross-site Scripting (XSS)" in response
        assert "Developer perspective" in response
        assert "XSS occurs" in response or "validation" in response
        assert "Mitigations" in response or "encoding" in response


class TestDominantCWEStrategy:
    """Test DominantCWEStrategy for single-CWE dominance."""

    def test_supports_single_cwe(self):
        """Test strategy supports when only one CWE present."""
        chunks = [
            make_chunk("CWE-79", "XSS", "Abstract", "XSS vulnerability", 0.9),
            make_chunk("CWE-79", "XSS", "Mitigations", "Use encoding", 0.8),
        ]

        strategy = DominantCWEStrategy()

        assert strategy.supports("security issue", chunks) is True

    def test_supports_dominant_score(self):
        """Test strategy supports when one CWE has much higher score."""
        chunks = [
            make_chunk("CWE-79", "XSS", "Abstract", "XSS", 0.9),
            make_chunk("CWE-89", "SQLi", "Abstract", "SQLi", 0.4),  # 2x lower
        ]

        strategy = DominantCWEStrategy()

        assert strategy.supports("security", chunks) is True

    def test_does_not_support_balanced_scores(self):
        """Test strategy does not support when scores are balanced."""
        chunks = [
            make_chunk("CWE-79", "XSS", "Abstract", "XSS", 0.9),
            make_chunk("CWE-89", "SQLi", "Abstract", "SQLi", 0.85),  # Close scores
        ]

        strategy = DominantCWEStrategy()

        assert strategy.supports("security", chunks) is False

    def test_respond_generates_dominant_cwe_response(self):
        """Test response generation for dominant CWE."""
        chunks = [make_chunk("CWE-79", "XSS", "Abstract", "XSS vulnerability", 0.9)]

        strategy = DominantCWEStrategy()
        response = strategy.respond("What is this?", "Developer", chunks)

        assert "CWE-79" in response
        assert "XSS" in response


class TestMultiCWEBriefStrategy:
    """Test MultiCWEBriefStrategy for multi-CWE summaries."""

    def test_always_supports_with_chunks(self):
        """Test strategy always supports as fallback."""
        chunks = [
            make_chunk("CWE-79", "XSS", "Abstract", "XSS", 0.9),
            make_chunk("CWE-89", "SQLi", "Abstract", "SQLi", 0.8),
            make_chunk("CWE-352", "CSRF", "Abstract", "CSRF", 0.7),
        ]

        strategy = MultiCWEBriefStrategy()

        assert strategy.supports("security", chunks) is True

    def test_respond_lists_multiple_cwes(self):
        """Test response lists multiple CWEs with summaries."""
        chunks = [
            make_chunk("CWE-79", "Cross-site Scripting", "Abstract", "XSS vulnerability", 0.9),
            make_chunk("CWE-89", "SQL Injection", "Abstract", "SQLi vulnerability", 0.8),
            make_chunk("CWE-352", "CSRF", "Abstract", "CSRF vulnerability", 0.7),
        ]

        strategy = MultiCWEBriefStrategy()
        response = strategy.respond("What are these?", "Developer", chunks, max_cwes=3)

        # Should list all CWEs
        assert "CWE-79" in response
        assert "CWE-89" in response
        assert "CWE-352" in response

        # Should include names
        assert "Cross-site Scripting" in response
        assert "SQL Injection" in response

        # Should have list format
        assert "most relevant CWE findings" in response or "relevant" in response

    def test_limits_to_max_cwes(self):
        """Test response limits to max_cwes parameter."""
        chunks = [
            make_chunk("CWE-79", "XSS", "Abstract", "XSS", 0.9),
            make_chunk("CWE-89", "SQLi", "Abstract", "SQLi", 0.8),
            make_chunk("CWE-352", "CSRF", "Abstract", "CSRF", 0.7),
            make_chunk("CWE-434", "File Upload", "Abstract", "Upload", 0.6),
        ]

        strategy = MultiCWEBriefStrategy()
        response = strategy.respond("security", "Developer", chunks, max_cwes=2)

        # Should only include top 2
        assert "CWE-79" in response
        assert "CWE-89" in response
        # Should not include lower scoring ones
        assert "CWE-434" not in response

    def test_persona_specific_tail(self):
        """Test persona-specific guidance in response."""
        chunks = [make_chunk("CWE-79", "XSS", "Abstract", "XSS", 0.9)]

        strategy = MultiCWEBriefStrategy()

        dev_response = strategy.respond("security", "Developer", chunks)
        assert "input validation" in dev_response or "safe APIs" in dev_response

        psirt_response = strategy.respond("security", "PSIRT Member", chunks)
        assert "impact assessment" in psirt_response or "advisories" in psirt_response

        researcher_response = strategy.respond("security", "Academic Researcher", chunks)
        assert "taxonomy" in researcher_response or "relationships" in researcher_response


class TestStrategyChain:
    """Test the strategy chain ordering and selection."""

    def test_explicit_cwe_takes_precedence(self):
        """Test ExplicitCWEStrategy is chosen when CWE mentioned."""
        chunks = [
            make_chunk("CWE-79", "XSS", "Abstract", "XSS", 0.5),
            make_chunk("CWE-89", "SQLi", "Abstract", "SQLi", 0.9),  # Higher score but not mentioned
        ]

        # Simulate strategy chain
        explicit = ExplicitCWEStrategy()
        dominant = DominantCWEStrategy()

        query = "Tell me about CWE-79"

        # Explicit should support
        assert explicit.supports(query, chunks) is True
        # Should generate response focused on CWE-79, not CWE-89
        response = explicit.respond(query, "Developer", chunks)
        assert "CWE-79" in response

    def test_dominant_chosen_when_single_cwe(self):
        """Test DominantCWEStrategy chosen for single CWE."""
        chunks = [make_chunk("CWE-79", "XSS", "Abstract", "XSS", 0.9)]

        explicit = ExplicitCWEStrategy()
        dominant = DominantCWEStrategy()

        query = "What is this vulnerability?"

        # Explicit should not support (no CWE mention)
        assert explicit.supports(query, chunks) is False
        # Dominant should support (single CWE)
        assert dominant.supports(query, chunks) is True

    def test_multi_cwe_as_fallback(self):
        """Test MultiCWEBriefStrategy as fallback for balanced results."""
        chunks = [
            make_chunk("CWE-79", "XSS", "Abstract", "XSS", 0.9),
            make_chunk("CWE-89", "SQLi", "Abstract", "SQLi", 0.85),
        ]

        explicit = ExplicitCWEStrategy()
        dominant = DominantCWEStrategy()
        multi = MultiCWEBriefStrategy()

        query = "security vulnerabilities"

        # Explicit should not support
        assert explicit.supports(query, chunks) is False
        # Dominant should not support (balanced scores)
        assert dominant.supports(query, chunks) is False
        # Multi should always support
        assert multi.supports(query, chunks) is True
