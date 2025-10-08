#!/usr/bin/env python3
"""
Confidence Calculator - Story 3.2
Calculates confidence scores for CWE recommendations based on multiple factors.
"""

import logging
from typing import Dict, List, Literal, TypedDict

logger = logging.getLogger(__name__)

ConfidenceLevel = Literal["High", "Medium", "Low", "Very Low"]


class AggregatedCWE(TypedDict):
    """Aggregated CWE data structure for confidence calculation."""

    cwe_id: str
    name: str
    top_hybrid_scores: List[float]  # top 3 scores from retrieval
    exact_alias_match: bool  # exact name/alias hit
    section_hits: Dict[str, int]  # {"Description":2,"Consequences":1}
    source_count: int  # distinct chunks


class ConfidenceCalculator:
    """
    Calculates confidence scores for CWE recommendations using weighted factors.

    Scoring factors:
    - Hybrid retrieval scores (vector + FTS + alias matching)
    - Exact alias matches (CWE name/alias exact match)
    - Section diversity (different sections matched)
    - Source count (number of distinct chunks)
    """

    def __init__(
        self,
        hybrid_weight: float = 0.50,
        alias_weight: float = 0.25,
        section_weight: float = 0.15,
        source_weight: float = 0.10,
    ):
        """
        Initialize confidence calculator with scoring weights.

        Args:
            hybrid_weight: Weight for hybrid retrieval scores (0.50)
            alias_weight: Weight for exact alias matches (0.25)
            section_weight: Weight for section diversity (0.15)
            source_weight: Weight for source count (0.10)
        """
        if (
            abs((hybrid_weight + alias_weight + section_weight + source_weight) - 1.0)
            > 0.001
        ):
            raise ValueError("Weights must sum to 1.0")

        self.hybrid_weight = hybrid_weight
        self.alias_weight = alias_weight
        self.section_weight = section_weight
        self.source_weight = source_weight

        logger.info(
            f"ConfidenceCalculator initialized with weights: hybrid={hybrid_weight}, "
            f"alias={alias_weight}, section={section_weight}, source={source_weight}"
        )

    def score(self, agg: AggregatedCWE) -> float:
        """
        Calculate confidence score for an aggregated CWE.

        Args:
            agg: AggregatedCWE data structure

        Returns:
            Confidence score between 0.0 and 1.0
        """
        try:
            # Hybrid score component (average of top 3 scores, normalized to 0-1)
            hybrid_component = 0.0
            if agg["top_hybrid_scores"]:
                # Take up to top 3 scores
                top_scores = sorted(agg["top_hybrid_scores"], reverse=True)[:3]
                hybrid_component = sum(top_scores) / len(top_scores)
                # Normalize to 0-1 range (assuming scores come in 0-1 range already)
                hybrid_component = max(0.0, min(1.0, hybrid_component))

            # Alias match component (binary: 1.0 if exact match, 0.0 otherwise)
            alias_component = 1.0 if agg["exact_alias_match"] else 0.0

            # Section diversity component (normalize section count to 0-1)
            # Assume max 14 sections based on CWE corpus structure
            max_sections = 14
            section_count = len(agg["section_hits"])
            section_component = (
                min(1.0, section_count / max_sections) if section_count > 0 else 0.0
            )

            # Source count component (normalize to 0-1, cap at reasonable maximum)
            # Assume max 20 chunks per CWE as reasonable upper bound
            max_sources = 20
            source_component = (
                min(1.0, agg["source_count"] / max_sources)
                if agg["source_count"] > 0
                else 0.0
            )

            # Calculate weighted final score
            final_score = (
                self.hybrid_weight * hybrid_component
                + self.alias_weight * alias_component
                + self.section_weight * section_component
                + self.source_weight * source_component
            )

            # Clamp to valid range
            final_score = max(0.0, min(1.0, final_score))

            logger.debug(
                f"Confidence calculation for {agg['cwe_id']}: "
                f"hybrid={hybrid_component:.3f}, alias={alias_component:.3f}, "
                f"section={section_component:.3f}, source={source_component:.3f}, "
                f"final={final_score:.3f}"
            )

            return final_score

        except Exception as e:
            logger.error(
                f"Error calculating confidence for CWE {agg.get('cwe_id', 'unknown')}: {e}"
            )
            return 0.0

    @staticmethod
    def level(score: float) -> ConfidenceLevel:
        """
        Convert confidence score to confidence level.

        Args:
            score: Confidence score between 0.0 and 1.0

        Returns:
            ConfidenceLevel: High, Medium, Low, or Very Low
        """
        if score >= 0.80:
            return "High"
        elif score >= 0.60:
            return "Medium"
        elif score >= 0.40:
            return "Low"
        else:
            return "Very Low"

    def score_and_level(self, agg: AggregatedCWE) -> tuple[float, ConfidenceLevel]:
        """
        Calculate both score and level in one call.

        Args:
            agg: AggregatedCWE data structure

        Returns:
            Tuple of (score, level)
        """
        score = self.score(agg)
        level = self.level(score)
        return score, level


def create_aggregated_cwe(
    cwe_id: str, name: str, chunks: List[Dict], exact_match: bool = False
) -> AggregatedCWE:
    """
    Helper function to create AggregatedCWE from chunk data.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-79")
        name: CWE name
        chunks: List of retrieved chunks with scores and metadata
        exact_match: Whether there was an exact alias match

    Returns:
        AggregatedCWE data structure
    """
    # Extract top hybrid scores
    top_scores = []
    section_hits: Dict[str, int] = {}

    for chunk in chunks:
        # Extract score (could be in different fields depending on retrieval method)
        score = chunk.get("score", chunk.get("hybrid_score"))
        if score is None:
            # Your retrieval shape keeps scores nested under "scores"
            s = chunk.get("scores") or {}
            score = s.get("hybrid", s.get("vec", 0.0))
        if isinstance(score, (int, float)):
            top_scores.append(float(score))

        # Count section hits
        section = chunk.get("metadata", {}).get("section", "Unknown")
        section_hits[section] = section_hits.get(section, 0) + 1

    # Sort scores and take top values
    top_scores = sorted(top_scores, reverse=True)

    return AggregatedCWE(
        cwe_id=cwe_id,
        name=name,
        top_hybrid_scores=top_scores[:3],  # Top 3 scores
        exact_alias_match=exact_match,
        section_hits=section_hits,
        source_count=len(chunks),
    )
