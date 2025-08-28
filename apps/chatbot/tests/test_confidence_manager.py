#!/usr/bin/env python3
"""
Tests for Enhanced Confidence Management System
Tests confidence scoring, normalization, and display functionality.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Mock chainlit and secure logging before importing
sys.modules['chainlit'] = MagicMock()

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.processing.confidence_manager import ConfidenceManager, ConfidenceMetrics


class TestConfidenceManager:
    """Test suite for ConfidenceManager functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        with patch('src.processing.confidence_manager.get_secure_logger'):
            self.confidence_manager = ConfidenceManager()
    
    def test_calculate_confidence_metrics_high_score(self):
        """Test confidence calculation for high similarity scores."""
        metrics = self.confidence_manager.calculate_confidence_metrics(
            similarity_score=0.92,
            query_type="direct_cwe_lookup",
            result_count=1
        )
        
        assert isinstance(metrics, ConfidenceMetrics)
        assert metrics.confidence_level == "High"
        assert metrics.normalized_percentage >= 85  # High scores should be 85+
        assert not metrics.should_show_warning
        assert "highly relevant" in metrics.reliability_indicator.lower()
    
    def test_calculate_confidence_metrics_medium_score(self):
        """Test confidence calculation for medium similarity scores."""
        metrics = self.confidence_manager.calculate_confidence_metrics(
            similarity_score=0.65,
            query_type="concept_search",
            result_count=3
        )
        
        assert metrics.confidence_level == "Medium"
        assert 50 <= metrics.normalized_percentage < 75
        assert not metrics.should_show_warning
        assert "relevant" in metrics.reliability_indicator.lower()
    
    def test_calculate_confidence_metrics_low_score(self):
        """Test confidence calculation for low similarity scores."""
        metrics = self.confidence_manager.calculate_confidence_metrics(
            similarity_score=0.25,
            query_type="general",
            result_count=1
        )
        
        assert metrics.confidence_level == "Low"
        assert metrics.normalized_percentage < 50
        assert metrics.should_show_warning
        assert "weak" in metrics.reliability_indicator.lower() or "partially" in metrics.reliability_indicator.lower()
    
    def test_normalize_to_percentage_edge_cases(self):
        """Test percentage normalization with edge cases."""
        # Test out-of-range inputs
        percentage = self.confidence_manager._normalize_to_percentage(-0.1, "general")
        assert 10 <= percentage <= 100
        
        percentage = self.confidence_manager._normalize_to_percentage(1.5, "general")
        assert 10 <= percentage <= 100
        
        # Test boundary values
        percentage = self.confidence_manager._normalize_to_percentage(0.0, "general")
        assert percentage >= 10
        
        percentage = self.confidence_manager._normalize_to_percentage(1.0, "general")
        assert percentage <= 100
    
    def test_query_type_adjustments(self):
        """Test query type-specific score adjustments."""
        base_score = 0.7
        
        # Direct CWE lookup should boost confidence
        direct_pct = self.confidence_manager._normalize_to_percentage(base_score, "direct_cwe_lookup")
        
        # Concept search should lower confidence slightly
        concept_pct = self.confidence_manager._normalize_to_percentage(base_score, "concept_search")
        
        # General should be baseline
        general_pct = self.confidence_manager._normalize_to_percentage(base_score, "general")
        
        assert direct_pct >= general_pct  # Direct lookups get boost
        assert concept_pct <= general_pct  # Concept searches get penalty
    
    def test_determine_confidence_level(self):
        """Test confidence level determination logic."""
        # High confidence
        assert self.confidence_manager._determine_confidence_level(85) == "High"
        assert self.confidence_manager._determine_confidence_level(75) == "High"
        
        # Medium confidence
        assert self.confidence_manager._determine_confidence_level(65) == "Medium"
        assert self.confidence_manager._determine_confidence_level(50) == "Medium"
        
        # Low confidence
        assert self.confidence_manager._determine_confidence_level(45) == "Low"
        assert self.confidence_manager._determine_confidence_level(15) == "Low"
    
    def test_format_confidence_display(self):
        """Test confidence display formatting."""
        metrics = ConfidenceMetrics(
            normalized_percentage=78,
            raw_score=0.78,
            confidence_level="High",
            reliability_indicator="Strong match",
            should_show_warning=False
        )
        
        # Basic display
        display = self.confidence_manager.format_confidence_display(metrics)
        assert "78%" in display
        assert "High" in display
        assert "**" in display  # Should be bold
        
        # Display with raw score
        display_raw = self.confidence_manager.format_confidence_display(metrics, show_raw_score=True)
        assert "0.78" in display_raw or "0.780" in display_raw
        assert "[Raw:" in display_raw
    
    def test_format_confidence_indicator(self):
        """Test brief confidence indicator formatting."""
        high_metrics = ConfidenceMetrics(
            normalized_percentage=85,
            raw_score=0.85,
            confidence_level="High",
            reliability_indicator="Strong match",
            should_show_warning=False
        )
        
        indicator = self.confidence_manager.format_confidence_indicator(high_metrics)
        assert "85%" in indicator
        assert "🟢" in indicator  # Green for high
        
        low_metrics = ConfidenceMetrics(
            normalized_percentage=30,
            raw_score=0.30,
            confidence_level="Low",
            reliability_indicator="Weak match",
            should_show_warning=True
        )
        
        indicator = self.confidence_manager.format_confidence_indicator(low_metrics)
        assert "30%" in indicator
        assert "🔴" in indicator  # Red for low
    
    def test_get_low_confidence_warning_triggered(self):
        """Test low confidence warning generation."""
        low_metrics = ConfidenceMetrics(
            normalized_percentage=25,
            raw_score=0.25,
            confidence_level="Low",
            reliability_indicator="Weak match",
            should_show_warning=True
        )
        
        warning = self.confidence_manager.get_low_confidence_warning(low_metrics)
        assert warning is not None
        assert "⚠️" in warning
        assert "Low Confidence" in warning
        assert "25%" in warning
        assert "refining your query" in warning.lower() or "more specific" in warning.lower()
    
    def test_get_low_confidence_warning_not_triggered(self):
        """Test that high confidence doesn't generate warnings."""
        high_metrics = ConfidenceMetrics(
            normalized_percentage=85,
            raw_score=0.85,
            confidence_level="High",
            reliability_indicator="Strong match",
            should_show_warning=False
        )
        
        warning = self.confidence_manager.get_low_confidence_warning(high_metrics)
        assert warning is None
    
    def test_get_confidence_help_text(self):
        """Test confidence help text generation."""
        help_text = self.confidence_manager.get_confidence_help_text()
        
        assert isinstance(help_text, str)
        assert len(help_text) > 100  # Should be substantial
        assert "🟢" in help_text  # Should include emojis
        assert "🟡" in help_text
        assert "🔴" in help_text
        assert "75-100%" in help_text or "High" in help_text
        assert "confidence" in help_text.lower()
    
    def test_score_history_tracking(self):
        """Test that score history is properly tracked."""
        initial_count = len(self.confidence_manager.score_history)
        
        # Generate several metrics to build history
        for score in [0.8, 0.6, 0.4, 0.9]:
            self.confidence_manager.calculate_confidence_metrics(score, "general", 1)
        
        assert len(self.confidence_manager.score_history) == initial_count + 4
        
        # Check that history entries contain expected data
        latest_entry = self.confidence_manager.score_history[-1]
        assert 'raw_score' in latest_entry
        assert 'normalized' in latest_entry
        assert 'query_type' in latest_entry
    
    def test_get_calibration_stats(self):
        """Test calibration statistics generation."""
        # Add some scores to history
        test_scores = [0.8, 0.7, 0.6, 0.5, 0.9]
        for score in test_scores:
            self.confidence_manager.calculate_confidence_metrics(score, "general", 1)
        
        stats = self.confidence_manager.get_calibration_stats()
        
        assert 'total_queries' in stats
        assert 'recent_avg_raw' in stats
        assert 'recent_avg_normalized' in stats
        assert 'score_distribution' in stats
        
        # Check distribution structure
        distribution = stats['score_distribution']
        assert 'High' in distribution
        assert 'Medium' in distribution
        assert 'Low' in distribution
        
        # Values should be reasonable
        assert stats['total_queries'] >= len(test_scores)
        assert 0.0 <= stats['recent_avg_raw'] <= 1.0
        assert 10 <= stats['recent_avg_normalized'] <= 100
    
    def test_get_calibration_stats_empty(self):
        """Test calibration stats with no history."""
        empty_manager = ConfidenceManager()
        stats = empty_manager.get_calibration_stats()
        
        assert 'message' in stats
        assert 'no scoring history' in stats['message'].lower()
    
    def test_confidence_thresholds(self):
        """Test confidence threshold constants."""
        assert 0.0 < self.confidence_manager.LOW_CONFIDENCE_THRESHOLD < self.confidence_manager.MEDIUM_CONFIDENCE_THRESHOLD
        assert self.confidence_manager.MEDIUM_CONFIDENCE_THRESHOLD < self.confidence_manager.HIGH_CONFIDENCE_THRESHOLD
        assert self.confidence_manager.HIGH_CONFIDENCE_THRESHOLD <= 1.0
    
    def test_error_handling_in_calculate_metrics(self):
        """Test error handling during metrics calculation."""
        with patch.object(self.confidence_manager, '_normalize_to_percentage', side_effect=Exception("Test error")):
            # Should return conservative fallback metrics
            metrics = self.confidence_manager.calculate_confidence_metrics(0.5, "general", 1)
            
            assert isinstance(metrics, ConfidenceMetrics)
            assert metrics.normalized_percentage == 50  # Fallback value
            assert metrics.confidence_level == "Medium"
            assert metrics.should_show_warning  # Conservative approach


class TestConfidenceMetricsDataClass:
    """Test suite for ConfidenceMetrics data class."""
    
    def test_confidence_metrics_creation(self):
        """Test ConfidenceMetrics data class creation."""
        metrics = ConfidenceMetrics(
            normalized_percentage=75,
            raw_score=0.75,
            confidence_level="High",
            reliability_indicator="Good match",
            should_show_warning=False
        )
        
        assert metrics.normalized_percentage == 75
        assert metrics.raw_score == 0.75
        assert metrics.confidence_level == "High"
        assert metrics.reliability_indicator == "Good match"
        assert not metrics.should_show_warning
    
    def test_confidence_metrics_immutable(self):
        """Test that ConfidenceMetrics behaves as expected data class."""
        metrics = ConfidenceMetrics(
            normalized_percentage=60,
            raw_score=0.6,
            confidence_level="Medium",
            reliability_indicator="Moderate relevance",
            should_show_warning=False
        )
        
        # Should be able to access all fields
        assert hasattr(metrics, 'normalized_percentage')
        assert hasattr(metrics, 'raw_score') 
        assert hasattr(metrics, 'confidence_level')
        assert hasattr(metrics, 'reliability_indicator')
        assert hasattr(metrics, 'should_show_warning')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])