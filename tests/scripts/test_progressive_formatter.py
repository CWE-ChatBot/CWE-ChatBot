"""
Unit tests for Story 2.2 Progressive Response Formatter components.

Tests progressive disclosure functionality, action button creation, and response formatting.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List

# Mock Chainlit before importing formatter components
import sys
mock_cl = Mock()
mock_cl.Action = Mock(side_effect=lambda name, value, description, label: {
    'name': name, 'value': value, 'description': description, 'label': label
})
sys.modules['chainlit'] = mock_cl

from src.formatting.progressive_response_formatter import ProgressiveResponseFormatter
from src.retrieval.base_retriever import CWEResult
from src.processing.contextual_responder import ContextualResponse


class TestProgressiveResponseFormatter:
    """Test progressive response formatting functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.formatter = ProgressiveResponseFormatter()
        
        # Create sample CWE data for testing
        self.sample_cwe_data = CWEResult(
            cwe_id='CWE-79',
            name='Cross-site Scripting (XSS)',
            description='The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.',
            confidence_score=0.95,
            extended_description='This is a detailed description of XSS vulnerabilities...',
            abstraction='Base',
            status='Stable',
            relationships={'ChildOf': ['CWE-20'], 'ParentOf': ['CWE-80', 'CWE-81']},
            consequences=[
                {'scope': 'Confidentiality', 'impact': 'Information disclosure'},
                {'scope': 'Integrity', 'impact': 'Data modification'}
            ]
        )
    
    def test_initialization(self):
        """Test ProgressiveResponseFormatter initialization."""
        formatter = ProgressiveResponseFormatter()
        assert formatter.response_count == 0
        assert formatter.SUMMARY_MAX_LENGTH == 300
        assert formatter.DETAILED_MAX_LENGTH == 1500
        assert 'tell_more' in formatter.ACTION_BUTTON_CONFIGS
    
    def test_format_summary_response_basic(self):
        """Test basic summary response formatting."""
        content, actions = self.formatter.format_summary_response(self.sample_cwe_data)
        
        assert 'CWE-79' in content
        assert 'Cross-site Scripting (XSS)' in content
        assert 'The software does not neutralize' in content
        assert 'Use the buttons below' in content
        
        # Should have created action buttons
        assert len(actions) > 0
        assert self.formatter.response_count == 1
    
    def test_format_summary_response_without_actions(self):
        """Test summary response formatting without action buttons."""
        content, actions = self.formatter.format_summary_response(
            self.sample_cwe_data, 
            include_actions=False
        )
        
        assert 'CWE-79' in content
        assert len(actions) == 0
    
    def test_format_summary_response_metadata_inclusion(self):
        """Test that metadata is properly included in summary."""
        content, actions = self.formatter.format_summary_response(self.sample_cwe_data)
        
        assert 'Abstraction**: Base' in content
        assert 'Status**: Stable' in content
    
    def test_format_detailed_response_comprehensive(self):
        """Test comprehensive detailed response formatting."""
        content = self.formatter.format_detailed_response(
            self.sample_cwe_data, 
            detail_type="comprehensive"
        )
        
        assert 'CWE-79' in content
        assert 'Cross-site Scripting (XSS)' in content
        assert 'Detailed Description' in content
        assert 'Potential Consequences' in content
        assert 'Related Vulnerabilities' in content
        assert 'Technical Information' in content
        assert 'ChildOf' in content
        assert 'ParentOf' in content
    
    def test_format_detailed_response_consequences_only(self):
        """Test consequences-focused detailed response."""
        content = self.formatter.format_detailed_response(
            self.sample_cwe_data, 
            detail_type="consequences"
        )
        
        assert 'CWE-79' in content
        assert 'Potential Consequences' in content
        assert 'Confidentiality' in content
        assert 'Integrity' in content
        assert 'Information disclosure' in content
    
    def test_format_detailed_response_related_only(self):
        """Test related CWEs detailed response."""
        content = self.formatter.format_detailed_response(
            self.sample_cwe_data, 
            detail_type="related"
        )
        
        assert 'CWE-79' in content
        assert 'Related Vulnerabilities' in content
        assert 'ChildOf' in content
        assert 'CWE-20' in content
    
    def test_format_detailed_response_prevention_only(self):
        """Test prevention-focused detailed response."""
        content = self.formatter.format_detailed_response(
            self.sample_cwe_data, 
            detail_type="prevention"
        )
        
        assert 'CWE-79' in content
        assert 'Prevention Strategies' in content
        assert 'input validation' in content
        assert 'security controls' in content
        assert 'Best Practices' in content
    
    def test_create_action_buttons_all_types(self):
        """Test creation of all action button types."""
        actions = self.formatter._create_action_buttons(self.sample_cwe_data)
        
        # Should create tell_more, consequences, related, and prevention buttons
        assert len(actions) == 4
        
        action_names = [action['name'] for action in actions]
        assert 'tell_more' in action_names
        assert 'show_consequences' in action_names
        assert 'show_related' in action_names
        assert 'show_prevention' in action_names
        
        # Check action values contain CWE ID
        for action in actions:
            assert 'CWE-79' in action['value']
    
    def test_create_action_buttons_minimal_data(self):
        """Test action button creation with minimal CWE data."""
        minimal_cwe = CWEResult(
            cwe_id='CWE-20',
            name='Input Validation',
            description='Basic description',
            confidence_score=0.8
        )
        
        actions = self.formatter._create_action_buttons(minimal_cwe)
        
        # Should still have tell_more and prevention (always included)
        action_names = [action['name'] for action in actions]
        assert 'tell_more' in action_names
        assert 'show_prevention' in action_names
        
        # Should not have consequences or related (no data available)
        assert 'show_consequences' not in action_names
        assert 'show_related' not in action_names
    
    def test_format_contextual_summary(self):
        """Test contextual summary formatting for follow-up responses."""
        contextual_response = ContextualResponse(
            content="This is a contextual response about XSS vulnerabilities.",
            confidence_score=0.9,
            context_used=True,
            metadata={'intent': 'related_cwes', 'original_cwe': 'CWE-79'}
        )
        
        content, actions = self.formatter.format_contextual_summary(
            contextual_response, 
            self.sample_cwe_data
        )
        
        assert content == "This is a contextual response about XSS vulnerabilities."
        assert len(actions) > 0  # Should have contextual actions
    
    def test_contextual_actions_creation(self):
        """Test creation of contextual actions based on response metadata."""
        contextual_response = ContextualResponse(
            content="Response content",
            confidence_score=0.9,
            context_used=True,
            metadata={'intent': 'consequences'}
        )
        
        actions = self.formatter._create_contextual_actions(
            contextual_response, 
            self.sample_cwe_data
        )
        
        # Should not include consequences action (already shown)
        action_names = [action['name'] for action in actions]
        assert 'show_consequences' not in action_names
        assert 'tell_more' in action_names  # Should include others
    
    def test_text_truncation(self):
        """Test text truncation functionality."""
        long_text = "This is a very long text " * 50  # Much longer than max
        
        truncated = self.formatter._truncate_text(long_text, 100)
        
        assert len(truncated) <= 103  # 100 + "..."
        assert truncated.endswith("...")
        assert truncated != long_text
    
    def test_text_truncation_preserves_short_text(self):
        """Test that short text is not truncated."""
        short_text = "This is short"
        
        result = self.formatter._truncate_text(short_text, 100)
        
        assert result == short_text
        assert not result.endswith("...")
    
    def test_action_metadata_parsing(self):
        """Test parsing of action metadata from values."""
        # Test valid action value
        metadata = self.formatter.get_action_metadata("tell_more:CWE-79")
        
        assert metadata['action_type'] == 'tell_more'
        assert metadata['cwe_id'] == 'CWE-79'
        
        # Test action value without CWE ID
        metadata = self.formatter.get_action_metadata("tell_more")
        
        assert metadata['action_type'] == 'tell_more'
        assert metadata['cwe_id'] is None
    
    def test_action_metadata_parsing_error_handling(self):
        """Test action metadata parsing with invalid input."""
        metadata = self.formatter.get_action_metadata("")
        
        assert metadata['action_type'] == 'unknown'
        assert metadata['cwe_id'] is None
    
    def test_comprehensive_details_formatting(self):
        """Test comprehensive details formatting method."""
        details = self.formatter._format_comprehensive_details(self.sample_cwe_data)
        
        assert len(details) > 0
        assert any('Detailed Description' in detail for detail in details)
        assert any('Potential Consequences' in detail for detail in details)
        assert any('Related Vulnerabilities' in detail for detail in details)
        assert any('Technical Information' in detail for detail in details)
    
    def test_consequences_details_formatting(self):
        """Test consequences-specific details formatting."""
        details = self.formatter._format_consequences_details(self.sample_cwe_data)
        
        assert len(details) > 0
        assert any('Potential Consequences' in detail for detail in details)
        assert any('Confidentiality' in detail for detail in details)
        assert any('Integrity' in detail for detail in details)
    
    def test_consequences_details_no_data_fallback(self):
        """Test consequences details with no consequence data."""
        minimal_cwe = CWEResult(
            cwe_id='CWE-20',
            name='Input Validation',
            description='Basic description',
            confidence_score=0.8
        )
        
        details = self.formatter._format_consequences_details(minimal_cwe)
        
        assert len(details) > 0
        assert any('Specific consequences depend on' in detail for detail in details)
        assert any('Common potential impacts' in detail for detail in details)
    
    def test_related_details_formatting(self):
        """Test related CWEs details formatting."""
        details = self.formatter._format_related_details(self.sample_cwe_data)
        
        assert len(details) > 0
        assert any('Related Vulnerabilities' in detail for detail in details)
        assert any('ChildOf' in detail for detail in details)
        assert any('CWE-20' in detail for detail in details)
    
    def test_prevention_details_formatting(self):
        """Test prevention-focused details formatting."""
        details = self.formatter._format_prevention_details(self.sample_cwe_data)
        
        assert len(details) > 0
        assert any('Prevention Strategies' in detail for detail in details)
        assert any('input validation' in detail for detail in details)
        assert any('Best Practices' in detail for detail in details)
    
    def test_error_handling_summary_response(self):
        """Test error handling in summary response formatting."""
        # Test with invalid data
        invalid_cwe = Mock()
        invalid_cwe.cwe_id = None  # This should cause an error
        
        content, actions = self.formatter.format_summary_response(invalid_cwe)
        
        # Should return fallback content
        assert "Unable to format" in content
        assert len(actions) == 0
    
    def test_error_handling_detailed_response(self):
        """Test error handling in detailed response formatting."""
        invalid_cwe = Mock()
        invalid_cwe.cwe_id = None
        
        content = self.formatter.format_detailed_response(invalid_cwe)
        
        assert "Unable to format" in content


@pytest.mark.integration
class TestProgressiveFormatterIntegration:
    """Integration tests for progressive response formatter."""
    
    def setup_method(self):
        """Set up integration test fixtures."""
        self.formatter = ProgressiveResponseFormatter()
    
    def test_full_disclosure_workflow(self):
        """Test complete progressive disclosure workflow."""
        cwe_data = CWEResult(
            cwe_id='CWE-89',
            name='SQL Injection',
            description='SQL injection vulnerability description',
            confidence_score=0.95,
            extended_description='Detailed SQL injection information...',
            consequences=[
                {'scope': 'Confidentiality', 'impact': 'Database access'},
                {'scope': 'Integrity', 'impact': 'Data modification'}
            ],
            relationships={'ChildOf': ['CWE-20']}
        )
        
        # Step 1: Generate summary response
        summary_content, summary_actions = self.formatter.format_summary_response(cwe_data)
        
        assert 'CWE-89' in summary_content
        assert 'SQL Injection' in summary_content
        assert len(summary_actions) > 0
        
        # Step 2: Generate detailed response (simulating button click)
        detailed_content = self.formatter.format_detailed_response(cwe_data, "comprehensive")
        
        assert len(detailed_content) > len(summary_content)
        assert 'Detailed Description' in detailed_content
        assert 'Potential Consequences' in detailed_content
        
        # Step 3: Generate specific detail responses
        consequences_content = self.formatter.format_detailed_response(cwe_data, "consequences")
        prevention_content = self.formatter.format_detailed_response(cwe_data, "prevention")
        
        assert 'Confidentiality' in consequences_content
        assert 'Prevention Strategies' in prevention_content
    
    def test_action_button_metadata_consistency(self):
        """Test consistency between action creation and metadata parsing."""
        cwe_data = CWEResult(
            cwe_id='CWE-79',
            name='XSS',
            description='XSS description',
            confidence_score=0.9,
            consequences=[{'scope': 'Test', 'impact': 'Test impact'}],
            relationships={'ChildOf': ['CWE-20']}
        )
        
        actions = self.formatter._create_action_buttons(cwe_data)
        
        for action in actions:
            # Parse the action value
            metadata = self.formatter.get_action_metadata(action['value'])
            
            # Verify consistency
            assert metadata['action_type'] == action['name']
            assert metadata['cwe_id'] == 'CWE-79'
            
            # Verify action configuration exists
            if action['name'] in self.formatter.ACTION_BUTTON_CONFIGS:
                config = self.formatter.ACTION_BUTTON_CONFIGS[action['name']]
                assert action['name'] == config['name']