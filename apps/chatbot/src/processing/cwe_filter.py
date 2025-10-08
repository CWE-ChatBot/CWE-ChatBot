#!/usr/bin/env python3
"""
CWE Filter - Story 3.2
Filters CWE recommendations to remove prohibited/discouraged CWEs and limit results.
"""

import logging
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Hard cap on maximum recommendations to prevent information overload
MAX_RECS = 5


class CWEFilter:
    """
    Filters CWE recommendations based on corpus metadata and configured limits.

    Features:
    - Remove prohibited CWEs (status="Prohibited" in corpus)
    - Remove discouraged CWEs (status="Discouraged" in corpus)
    - Hard cap results to MAX_RECS (5) to prevent information overload
    - Track filter reasoning for debugging and transparency
    """

    def __init__(
        self,
        prohibited: Optional[Set[str]] = None,
        discouraged: Optional[Set[str]] = None,
        max_recommendations: int = MAX_RECS,
    ) -> None:
        """
        Initialize CWE filter with prohibited and discouraged CWE sets.

        Args:
            prohibited: Set of prohibited CWE IDs (e.g., {"CWE-1000", "CWE-1001"})
            discouraged: Set of discouraged CWE IDs (e.g., {"CWE-699", "CWE-700"})
            max_recommendations: Maximum number of recommendations to return (default: 5)
        """
        self.prohibited = prohibited or set()
        self.discouraged = discouraged or set()
        self.max_recommendations = max_recommendations

        logger.info(
            f"CWEFilter initialized: prohibited={len(self.prohibited)}, "
            f"discouraged={len(self.discouraged)}, max={max_recommendations}"
        )

    def filter(self, recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Filter recommendations based on configured rules.

        Args:
            recommendations: List of recommendation dictionaries with cwe_id field

        Returns:
            Dictionary with filtered recommendations and filtering metadata:
            {
                "recommendations": List[Dict],  # Filtered recommendations
                "filtered_out": List[Dict],     # Recommendations that were filtered
                "filter_reasons": Dict[str, str],  # CWE_ID -> reason mapping
                "original_count": int,          # Original count before filtering
                "final_count": int              # Final count after filtering
            }
        """
        if not recommendations:
            return {
                "recommendations": [],
                "filtered_out": [],
                "filter_reasons": {},
                "original_count": 0,
                "final_count": 0,
            }

        original_count = len(recommendations)
        filtered_recommendations: List[Dict[str, Any]] = []
        filtered_out: List[Dict[str, Any]] = []
        filter_reasons: Dict[str, str] = {}

        logger.debug(f"Filtering {original_count} recommendations")

        for rec in recommendations:
            cwe_id = rec.get("cwe_id", "").upper()

            # Check prohibited CWEs
            if cwe_id in self.prohibited:
                filtered_out.append(rec)
                filter_reasons[cwe_id] = "prohibited"
                logger.debug(f"Filtered out {cwe_id}: prohibited")
                continue

            # Check discouraged CWEs
            if cwe_id in self.discouraged:
                filtered_out.append(rec)
                filter_reasons[cwe_id] = "discouraged"
                logger.debug(f"Filtered out {cwe_id}: discouraged")
                continue

            # Keep recommendation if it passes filters
            filtered_recommendations.append(rec)

        # Apply hard cap on results
        if len(filtered_recommendations) > self.max_recommendations:
            # Keep top N by confidence score (assuming recommendations are pre-sorted)
            capped_recommendations = filtered_recommendations[
                : self.max_recommendations
            ]
            excess_recommendations = filtered_recommendations[
                self.max_recommendations :
            ]

            # Mark excess as filtered for transparency
            for rec in excess_recommendations:
                cwe_id = rec.get("cwe_id", "").upper()
                filtered_out.append(rec)
                filter_reasons[
                    cwe_id
                ] = f"exceeded_max_limit_{self.max_recommendations}"

            filtered_recommendations = capped_recommendations
            logger.debug(
                f"Applied hard cap: kept {len(capped_recommendations)}, "
                f"filtered {len(excess_recommendations)} excess"
            )

        final_count = len(filtered_recommendations)

        logger.info(
            f"Filtering complete: {original_count} → {final_count} "
            f"(prohibited: {len([r for r in filter_reasons.values() if r == 'prohibited'])}, "
            f"discouraged: {len([r for r in filter_reasons.values() if r == 'discouraged'])}, "
            f"capped: {len([r for r in filter_reasons.values() if r.startswith('exceeded_max')])})"
        )

        return {
            "recommendations": filtered_recommendations,
            "filtered_out": filtered_out,
            "filter_reasons": filter_reasons,
            "original_count": original_count,
            "final_count": final_count,
        }

    def is_allowed(self, cwe_id: str) -> bool:
        """
        Check if a CWE ID is allowed (not prohibited or discouraged).

        Args:
            cwe_id: CWE identifier to check

        Returns:
            True if allowed, False if prohibited or discouraged
        """
        cwe_id = cwe_id.upper()
        return cwe_id not in self.prohibited and cwe_id not in self.discouraged

    def add_prohibited(self, cwe_ids: List[str]) -> None:
        """
        Add CWE IDs to the prohibited set.

        Args:
            cwe_ids: List of CWE IDs to mark as prohibited
        """
        for cwe_id in cwe_ids:
            self.prohibited.add(cwe_id.upper())
        logger.info(
            f"Added {len(cwe_ids)} prohibited CWEs, total: {len(self.prohibited)}"
        )

    def add_discouraged(self, cwe_ids: List[str]) -> None:
        """
        Add CWE IDs to the discouraged set.

        Args:
            cwe_ids: List of CWE IDs to mark as discouraged
        """
        for cwe_id in cwe_ids:
            self.discouraged.add(cwe_id.upper())
        logger.info(
            f"Added {len(cwe_ids)} discouraged CWEs, total: {len(self.discouraged)}"
        )

    def get_filter_stats(self) -> Dict[str, int]:
        """
        Get current filter configuration statistics.

        Returns:
            Dictionary with filter statistics
        """
        return {
            "prohibited_count": len(self.prohibited),
            "discouraged_count": len(self.discouraged),
            "max_recommendations": self.max_recommendations,
            "total_filtered_types": len(self.prohibited) + len(self.discouraged),
        }


def load_filter_config_from_corpus_metadata(
    corpus_data: List[Dict],
) -> tuple[Set[str], Set[str]]:
    """
    Load prohibited and discouraged CWE sets from corpus metadata.

    Args:
        corpus_data: List of CWE corpus entries with metadata

    Returns:
        Tuple of (prohibited_set, discouraged_set)
    """
    prohibited = set()
    discouraged = set()

    for entry in corpus_data:
        cwe_id = entry.get("cwe_id", "").upper()
        status = entry.get("status", "").lower()

        if status == "prohibited":
            prohibited.add(cwe_id)
        elif status == "discouraged":
            discouraged.add(cwe_id)

    logger.info(
        f"Loaded filter config from corpus: {len(prohibited)} prohibited, "
        f"{len(discouraged)} discouraged"
    )

    return prohibited, discouraged


def create_default_filter() -> CWEFilter:
    """
    Create a CWEFilter with common prohibited/discouraged CWEs.

    These are typically high-level categories, deprecated entries, or
    overly broad classifications that provide limited actionable guidance.

    Returns:
        CWEFilter with default configuration
    """
    # Common prohibited CWEs (high-level categories, deprecated)
    prohibited = {
        "CWE-1000",  # Research Concepts
        "CWE-1001",  # SFP Secondary Cluster
        "CWE-1008",  # Architectural Concepts
    }

    # Common discouraged CWEs (too broad for specific guidance)
    discouraged = {
        "CWE-699",  # Development Concepts
        "CWE-700",  # Seven Pernicious Kingdoms
        "CWE-711",  # OWASP Top Ten 2007 Category A8
    }

    return CWEFilter(prohibited=prohibited, discouraged=discouraged)
