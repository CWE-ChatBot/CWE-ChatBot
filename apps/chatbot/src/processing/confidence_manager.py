#!/usr/bin/env python3
"""
Confidence Management System
Enhanced confidence scoring with normalization and display optimization.
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from ..retrieval.base_retriever import CWEResult
from ..security.secure_logging import get_secure_logger

logger = get_secure_logger(__name__)


@dataclass
class ConfidenceMetrics:
    """Confidence metrics for a query response."""
    normalized_percentage: int  # 0-100
    raw_score: float  # Original similarity score
    confidence_level: str  # "High", "Medium", "Low"
    reliability_indicator: str  # User-friendly description
    should_show_warning: bool  # Whether to show low confidence warning


class ConfidenceManager:
    """
    Manages confidence scoring and normalization for CWE responses.
    
    Provides enhanced confidence scoring with better user experience,
    including normalization, thresholds, and user-friendly indicators.
    """
    
    # Confidence thresholds
    HIGH_CONFIDENCE_THRESHOLD = 0.75
    MEDIUM_CONFIDENCE_THRESHOLD = 0.50
    LOW_CONFIDENCE_THRESHOLD = 0.30
    
    def __init__(self):
        """Initialize the confidence manager."""
        self.score_history = []  # For calibration tracking
        logger.info("Initialized ConfidenceManager with enhanced scoring")
    
    def calculate_confidence_metrics(
        self, 
        similarity_score: float,
        query_type: str = "general",
        result_count: int = 1
    ) -> ConfidenceMetrics:
        """
        Calculate comprehensive confidence metrics for a similarity score.
        
        Args:
            similarity_score: Raw similarity score (0.0 to 1.0)
            query_type: Type of query ("direct_cwe_lookup", "concept_search", etc.)
            result_count: Number of results returned
            
        Returns:
            ConfidenceMetrics with normalized and enhanced scoring
        """
        try:
            # Normalize score to percentage with enhanced algorithm
            normalized_percentage = self._normalize_to_percentage(similarity_score, query_type)
            
            # Determine confidence level
            confidence_level = self._determine_confidence_level(normalized_percentage)
            
            # Generate user-friendly reliability indicator
            reliability_indicator = self._get_reliability_indicator(confidence_level, result_count)
            
            # Determine if warning should be shown
            should_show_warning = normalized_percentage < (self.LOW_CONFIDENCE_THRESHOLD * 100)
            
            metrics = ConfidenceMetrics(
                normalized_percentage=normalized_percentage,
                raw_score=similarity_score,
                confidence_level=confidence_level,
                reliability_indicator=reliability_indicator,
                should_show_warning=should_show_warning
            )
            
            # Track for calibration
            self.score_history.append({
                'raw_score': similarity_score,
                'normalized': normalized_percentage,
                'query_type': query_type
            })
            
            logger.debug(f"Calculated confidence: {normalized_percentage}% ({confidence_level}) for score {similarity_score}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error calculating confidence metrics: {e}")
            # Return conservative fallback
            return ConfidenceMetrics(
                normalized_percentage=50,
                raw_score=similarity_score,
                confidence_level="Medium",
                reliability_indicator="Moderate relevance expected",
                should_show_warning=True
            )
    
    def _normalize_to_percentage(self, raw_score: float, query_type: str) -> int:
        """
        Normalize raw similarity score to user-friendly percentage.
        
        Uses advanced normalization that considers query type and score distribution.
        """
        if raw_score < 0.0 or raw_score > 1.0:
            logger.warning(f"Raw score out of range: {raw_score}")
            raw_score = max(0.0, min(1.0, raw_score))
        
        # Query type adjustments
        if query_type == "direct_cwe_lookup":
            # Direct lookups should have higher confidence baseline
            adjusted_score = min(1.0, raw_score * 1.1)
        elif query_type == "concept_search":
            # Concept searches are inherently less precise
            adjusted_score = raw_score * 0.9
        else:
            adjusted_score = raw_score
        
        # Enhanced normalization algorithm
        if adjusted_score >= 0.9:
            # Very high scores: map to 90-100%
            percentage = 90 + int((adjusted_score - 0.9) * 100)
        elif adjusted_score >= 0.7:
            # High scores: map to 75-89%
            percentage = 75 + int((adjusted_score - 0.7) * 70)
        elif adjusted_score >= 0.5:
            # Medium scores: map to 50-74%
            percentage = 50 + int((adjusted_score - 0.5) * 120)
        elif adjusted_score >= 0.3:
            # Low scores: map to 25-49%
            percentage = 25 + int((adjusted_score - 0.3) * 120)
        else:
            # Very low scores: map to 10-24%
            percentage = 10 + int(adjusted_score * 47)
        
        return max(10, min(100, percentage))
    
    def _determine_confidence_level(self, percentage: int) -> str:
        """Determine confidence level based on percentage."""
        if percentage >= (self.HIGH_CONFIDENCE_THRESHOLD * 100):
            return "High"
        elif percentage >= (self.MEDIUM_CONFIDENCE_THRESHOLD * 100):
            return "Medium"
        else:
            return "Low"
    
    def _get_reliability_indicator(self, confidence_level: str, result_count: int) -> str:
        """Generate user-friendly reliability indicator."""
        base_indicators = {
            "High": "Strong match - information is highly relevant",
            "Medium": "Good match - information should be relevant", 
            "Low": "Weak match - information may be partially relevant"
        }
        
        base = base_indicators.get(confidence_level, "Moderate relevance expected")
        
        # Adjust based on result count
        if result_count == 1:
            return base
        elif result_count > 5:
            return f"{base} (multiple alternatives available)"
        else:
            return f"{base} (few alternatives found)"
    
    def format_confidence_display(
        self, 
        metrics: ConfidenceMetrics, 
        show_raw_score: bool = False
    ) -> str:
        """
        Format confidence metrics for display.
        
        Args:
            metrics: Confidence metrics to format
            show_raw_score: Whether to include raw score for debugging
            
        Returns:
            Formatted confidence display string
        """
        display = f"**Confidence: {metrics.normalized_percentage}%** ({metrics.confidence_level})"
        
        if show_raw_score:
            display += f" [Raw: {metrics.raw_score:.3f}]"
        
        return display
    
    def format_confidence_indicator(self, metrics: ConfidenceMetrics) -> str:
        """Format a brief confidence indicator for inline display."""
        emoji_map = {
            "High": "🟢",
            "Medium": "🟡", 
            "Low": "🔴"
        }
        
        emoji = emoji_map.get(metrics.confidence_level, "⚪")
        return f"{emoji} {metrics.normalized_percentage}%"
    
    def get_low_confidence_warning(self, metrics: ConfidenceMetrics) -> Optional[str]:
        """
        Get warning message for low confidence results.
        
        Args:
            metrics: Confidence metrics
            
        Returns:
            Warning message if applicable, None otherwise
        """
        if not metrics.should_show_warning:
            return None
        
        return f"""⚠️ **Low Confidence Match ({metrics.normalized_percentage}%)**

The information retrieved may not be highly relevant to your query. Consider:
• Refining your query with more specific terms
• Trying different keywords or phrases
• Asking about a specific CWE ID if known

*{metrics.reliability_indicator}*"""
    
    def get_confidence_help_text(self) -> str:
        """Get help text explaining confidence scores."""
        return """**Understanding Confidence Scores:**

🟢 **High (75-100%)**: Information is highly relevant and accurate
🟡 **Medium (50-74%)**: Information is likely relevant with good accuracy
🔴 **Low (10-49%)**: Information may be partially relevant; consider refining your query

Confidence scores are based on how well your query matches the CWE database content."""
    
    def get_calibration_stats(self) -> Dict[str, Any]:
        """Get calibration statistics for monitoring."""
        if not self.score_history:
            return {"message": "No scoring history available"}
        
        recent_scores = self.score_history[-100:]  # Last 100 scores
        avg_raw = sum(s['raw_score'] for s in recent_scores) / len(recent_scores)
        avg_normalized = sum(s['normalized'] for s in recent_scores) / len(recent_scores)
        
        return {
            "total_queries": len(self.score_history),
            "recent_avg_raw": round(avg_raw, 3),
            "recent_avg_normalized": round(avg_normalized, 1),
            "score_distribution": self._get_score_distribution(recent_scores)
        }
    
    def _get_score_distribution(self, scores: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of confidence levels."""
        distribution = {"High": 0, "Medium": 0, "Low": 0}
        
        for score in scores:
            level = self._determine_confidence_level(score['normalized'])
            distribution[level] += 1
        
        return distribution