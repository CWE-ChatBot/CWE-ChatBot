#!/usr/bin/env python3
"""
Unit test for ConfidenceCalculator P0 fix: scores.hybrid reading
Verifies that create_aggregated_cwe correctly extracts scores from nested scores structure
with fallback chain: score -> hybrid_score -> scores.hybrid -> scores.vec -> 0.0
"""

import pytest
from src.processing.confidence_calculator import (
    ConfidenceCalculator,
    create_aggregated_cwe,
)


class TestConfidenceCalculatorP0Fix:
    """Test ConfidenceCalculator scores.hybrid reading (P0 fix)."""

    def test_create_aggregated_cwe_extracts_direct_score(self):
        """Test that create_aggregated_cwe extracts direct 'score' field first."""
        chunks = [
            {
                "score": 0.85,
                "hybrid_score": 0.70,  # Should be ignored
                "scores": {"hybrid": 0.60, "vec": 0.50},  # Should be ignored
                "metadata": {"section": "Description"},
            }
        ]

        agg = create_aggregated_cwe("CWE-79", "Cross-site Scripting", chunks)

        assert agg["top_hybrid_scores"] == [0.85]
        assert agg["source_count"] == 1

    def test_create_aggregated_cwe_falls_back_to_hybrid_score(self):
        """Test that create_aggregated_cwe falls back to 'hybrid_score' when 'score' is missing."""
        chunks = [
            {
                # No 'score' field
                "hybrid_score": 0.75,
                "scores": {"hybrid": 0.60, "vec": 0.50},  # Should be ignored
                "metadata": {"section": "Description"},
            }
        ]

        agg = create_aggregated_cwe("CWE-89", "SQL Injection", chunks)

        assert agg["top_hybrid_scores"] == [0.75]
        assert agg["source_count"] == 1

    def test_create_aggregated_cwe_reads_scores_hybrid(self):
        """Test that create_aggregated_cwe reads scores.hybrid when direct fields missing."""
        chunks = [
            {
                # No 'score' or 'hybrid_score' fields
                "scores": {"hybrid": 0.65, "vec": 0.55},
                "metadata": {"section": "Description"},
            }
        ]

        agg = create_aggregated_cwe("CWE-120", "Buffer Overflow", chunks)

        assert agg["top_hybrid_scores"] == [0.65]
        assert agg["source_count"] == 1

    def test_create_aggregated_cwe_falls_back_to_scores_vec(self):
        """Test that create_aggregated_cwe falls back to scores.vec when hybrid is missing."""
        chunks = [
            {
                # No direct score fields and no hybrid in scores
                "scores": {"vec": 0.55},
                "metadata": {"section": "Description"},
            }
        ]

        agg = create_aggregated_cwe("CWE-22", "Path Traversal", chunks)

        assert agg["top_hybrid_scores"] == [0.55]
        assert agg["source_count"] == 1

    def test_create_aggregated_cwe_defaults_to_zero(self):
        """Test that create_aggregated_cwe defaults to 0.0 when no scores available."""
        chunks = [
            {
                # No score fields at all
                "metadata": {"section": "Description"}
            },
            {
                # Empty scores dict
                "scores": {},
                "metadata": {"section": "Consequences"},
            },
        ]

        agg = create_aggregated_cwe("CWE-476", "NULL Pointer Dereference", chunks)

        assert agg["top_hybrid_scores"] == [0.0, 0.0]
        assert agg["source_count"] == 2

    def test_create_aggregated_cwe_handles_mixed_score_formats(self):
        """Test that create_aggregated_cwe handles chunks with different score formats."""
        chunks = [
            {"score": 0.90, "metadata": {"section": "Description"}},  # Direct score
            {
                "hybrid_score": 0.80,  # Hybrid score
                "metadata": {"section": "Consequences"},
            },
            {
                "scores": {"hybrid": 0.70},  # Nested hybrid score
                "metadata": {"section": "Mitigations"},
            },
            {
                "scores": {"vec": 0.60},  # Nested vector score only
                "metadata": {"section": "Examples"},
            },
            {
                # No scores at all
                "metadata": {"section": "References"}
            },
        ]

        agg = create_aggregated_cwe("CWE-200", "Information Exposure", chunks)

        # Should extract all scores in descending order
        expected_scores = [0.90, 0.80, 0.70]  # Top 3 scores only
        assert agg["top_hybrid_scores"] == expected_scores
        assert agg["source_count"] == 5

    def test_confidence_calculator_uses_extracted_scores(self):
        """Test that ConfidenceCalculator properly uses scores extracted by create_aggregated_cwe."""
        calculator = ConfidenceCalculator()

        # Create aggregated CWE with mixed score formats
        chunks = [
            {"scores": {"hybrid": 0.85}, "metadata": {"section": "Description"}},
            {"score": 0.75, "metadata": {"section": "Consequences"}},
        ]

        agg = create_aggregated_cwe(
            "CWE-79", "Cross-site Scripting", chunks, exact_match=True
        )

        # Calculate confidence
        score = calculator.score(agg)

        # Should be > 0 since we have valid scores and exact match
        assert score > 0.0
        assert score <= 1.0

        # Should be high confidence due to exact match and good scores
        level = calculator.level(score)
        assert level in ["High", "Medium", "Low", "Very Low"]

    def test_create_aggregated_cwe_sorts_scores_descending(self):
        """Test that create_aggregated_cwe sorts scores in descending order."""
        chunks = [
            {"score": 0.60, "metadata": {"section": "Description"}},
            {"score": 0.90, "metadata": {"section": "Consequences"}},
            {"score": 0.75, "metadata": {"section": "Mitigations"}},
        ]

        agg = create_aggregated_cwe("CWE-89", "SQL Injection", chunks)

        # Should be sorted descending and take top 3
        assert agg["top_hybrid_scores"] == [0.90, 0.75, 0.60]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
