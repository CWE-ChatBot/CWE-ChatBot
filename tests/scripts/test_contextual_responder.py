"""
Unit tests for Story 2.2 Contextual Responder components.

Tests context-aware response generation for different follow-up intents.
"""

import pytest
from unittest.mock import Mock, patch
from typing import Dict, List

from src.processing.contextual_responder import ContextualResponder, ContextualResponse
from src.processing.followup_processor import FollowupIntent
from src.retrieval.base_retriever import CWEResult


class TestContextualResponder:
    """Test contextual response generation functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.responder = ContextualResponder()
        
        # Sample relationship data for testing
        self.sample_relationship_data = {
            'relationships': {
                'ChildOf': ['CWE-20', 'CWE-707'],
                'ParentOf': ['CWE-80', 'CWE-81'],
                'CanPrecede': ['CWE-94']
            },
            'consequences': [
                {'scope': 'Confidentiality', 'impact': 'Information disclosure'},
                {'scope': 'Integrity', 'impact': 'Data modification'},
                {'scope': 'Availability', 'impact': 'System disruption'}
            ],
            'extended_description': 'Extended technical description of the vulnerability.'
        }
        
        # Sample related CWE results
        self.sample_related_results = [
            CWEResult(
                cwe_id='CWE-80',
                name='Basic XSS',
                description='Basic cross-site scripting vulnerability',
                confidence_score=0.9
            ),
            CWEResult(
                cwe_id='CWE-81',
                name='Improper Neutralization of Script in Error Message',
                description='Script injection in error messages',
                confidence_score=0.85
            )
        ]
    
    def test_initialization(self):
        """Test ContextualResponder initialization."""
        responder = ContextualResponder()
        assert responder.response_count == 0
        assert hasattr(responder, '_intent_handlers')
    
    def test_contextual_response_creation(self):
        """Test ContextualResponse object creation."""
        response = ContextualResponse(
            content="Test response content",
            confidence_score=0.95,
            context_used=True,
            metadata={'intent': 'test', 'cwe_id': 'CWE-79'}
        )
        
        assert response.content == "Test response content"
        assert response.confidence_score == 0.95
        assert response.context_used is True
        assert response.metadata['intent'] == 'test'
    
    def test_generate_contextual_response_related_cwes(self):
        """Test contextual response generation for related CWEs intent."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='related',
            confidence=0.9,
            matched_patterns=['related', 'similar']
        )
        
        response = self.responder.generate_contextual_response(
            query="What CWEs are related to this?",
            context_cwe_id="CWE-79",
            intent=intent,
            relationship_data=self.sample_relationship_data,
            related_results=self.sample_related_results
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.context_used is True
        assert response.confidence_score > 0.8
        assert 'CWE-79' in response.content
        assert 'related' in response.content.lower()
        assert 'CWE-80' in response.content
        assert 'CWE-81' in response.content
    
    def test_generate_contextual_response_consequences(self):
        """Test contextual response generation for consequences intent."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='consequences',
            confidence=0.85,
            matched_patterns=['consequences', 'impact']
        )
        
        response = self.responder.generate_contextual_response(
            query="What are the consequences of this vulnerability?",
            context_cwe_id="CWE-79",
            intent=intent,
            relationship_data=self.sample_relationship_data,
            related_results=[]
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.context_used is True
        assert 'consequences' in response.content.lower() or 'impact' in response.content.lower()
        assert 'Confidentiality' in response.content
        assert 'Integrity' in response.content
        assert 'Availability' in response.content
    
    def test_generate_contextual_response_prevention(self):
        """Test contextual response generation for prevention intent."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='prevention',
            confidence=0.9,
            matched_patterns=['prevent', 'mitigation']
        )
        
        response = self.responder.generate_contextual_response(
            query="How can I prevent this vulnerability?",
            context_cwe_id="CWE-79",
            intent=intent,
            relationship_data=self.sample_relationship_data,
            related_results=[]
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.context_used is True
        assert 'prevent' in response.content.lower() or 'mitigation' in response.content.lower()
        assert 'input validation' in response.content.lower()
    
    def test_generate_contextual_response_children(self):
        """Test contextual response generation for children CWEs intent."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='children',
            confidence=0.8,
            matched_patterns=['children', 'child']
        )
        
        response = self.responder.generate_contextual_response(
            query="What are the child CWEs?",
            context_cwe_id="CWE-79",
            intent=intent,
            relationship_data=self.sample_relationship_data,
            related_results=self.sample_related_results
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.context_used is True
        assert 'child' in response.content.lower() or 'specific' in response.content.lower()
        assert 'CWE-80' in response.content
        assert 'CWE-81' in response.content
    
    def test_generate_contextual_response_parents(self):
        """Test contextual response generation for parent CWEs intent."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='parents',
            confidence=0.8,
            matched_patterns=['parents', 'parent']
        )
        
        response = self.responder.generate_contextual_response(
            query="What are the parent CWEs?",
            context_cwe_id="CWE-79",
            intent=intent,
            relationship_data=self.sample_relationship_data,
            related_results=[]
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.context_used is True
        assert 'parent' in response.content.lower() or 'broader' in response.content.lower()
        assert 'CWE-20' in response.content
        assert 'CWE-707' in response.content
    
    def test_generate_contextual_response_tell_more(self):
        """Test contextual response generation for tell me more intent."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='tell_more',
            confidence=0.9,
            matched_patterns=['tell me more', 'more details']
        )
        
        response = self.responder.generate_contextual_response(
            query="Tell me more about this CWE",
            context_cwe_id="CWE-79",
            intent=intent,
            relationship_data=self.sample_relationship_data,
            related_results=[]
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.context_used is True
        assert len(response.content) > 200  # Should be comprehensive
        assert 'CWE-79' in response.content
        assert 'Extended technical description' in response.content
    
    def test_generate_contextual_response_examples(self):
        """Test contextual response generation for examples intent."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='examples',
            confidence=0.85,
            matched_patterns=['examples', 'show me']
        )
        
        response = self.responder.generate_contextual_response(
            query="Can you show me examples?",
            context_cwe_id="CWE-79",
            intent=intent,
            relationship_data=self.sample_relationship_data,
            related_results=[]
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.context_used is True
        assert 'example' in response.content.lower()
        assert 'CWE-79' in response.content
    
    def test_generate_contextual_response_general_followup(self):
        """Test contextual response generation for general follow-up intent."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='general_followup',
            confidence=0.7,
            matched_patterns=['it', 'this']
        )
        
        response = self.responder.generate_contextual_response(
            query="Can you explain it better?",
            context_cwe_id="CWE-79",
            intent=intent,
            relationship_data=self.sample_relationship_data,
            related_results=[]
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.context_used is True
        assert 'CWE-79' in response.content
        assert len(response.content) > 100
    
    def test_generate_contextual_response_no_context(self):
        """Test contextual response generation when no context is available."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='related',
            confidence=0.8,
            matched_patterns=['related']
        )
        
        response = self.responder.generate_contextual_response(
            query="What's related?",
            context_cwe_id=None,  # No context CWE
            intent=intent,
            relationship_data=None,
            related_results=[]
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.context_used is False
        assert response.confidence_score < 0.5  # Low confidence without context
        assert 'specific CWE' in response.content
    
    def test_generate_contextual_response_minimal_data(self):
        """Test contextual response generation with minimal data."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='consequences',
            confidence=0.8,
            matched_patterns=['consequences']
        )
        
        minimal_relationship_data = {
            'relationships': {},
            'consequences': [],
            'extended_description': None
        }
        
        response = self.responder.generate_contextual_response(
            query="What are the consequences?",
            context_cwe_id="CWE-123",
            intent=intent,
            relationship_data=minimal_relationship_data,
            related_results=[]
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.context_used is True
        assert 'general security impacts' in response.content.lower()
    
    def test_intent_handler_related_cwes(self):
        """Test specific intent handler for related CWEs."""
        handler_response = self.responder._handle_related_cwes_intent(
            "CWE-79",
            self.sample_relationship_data,
            self.sample_related_results
        )
        
        assert 'related' in handler_response.lower()
        assert 'CWE-80' in handler_response
        assert 'Basic XSS' in handler_response
        assert 'similarity' in handler_response.lower() or 'confidence' in handler_response.lower()
    
    def test_intent_handler_consequences(self):
        """Test specific intent handler for consequences."""
        handler_response = self.responder._handle_consequences_intent(
            "CWE-79",
            self.sample_relationship_data
        )
        
        assert 'consequences' in handler_response.lower() or 'impacts' in handler_response.lower()
        assert 'Confidentiality' in handler_response
        assert 'Information disclosure' in handler_response
    
    def test_intent_handler_prevention(self):
        """Test specific intent handler for prevention."""
        handler_response = self.responder._handle_prevention_intent("CWE-79")
        
        assert 'prevent' in handler_response.lower() or 'mitigate' in handler_response.lower()
        assert 'input validation' in handler_response.lower()
        assert 'sanitization' in handler_response.lower()
    
    def test_intent_handler_children_relationships(self):
        """Test specific intent handler for children relationships."""
        handler_response = self.responder._handle_children_intent(
            "CWE-79",
            self.sample_relationship_data,
            self.sample_related_results
        )
        
        assert 'child' in handler_response.lower() or 'specific' in handler_response.lower()
        assert 'CWE-80' in handler_response
        assert 'CWE-81' in handler_response
    
    def test_intent_handler_parents_relationships(self):
        """Test specific intent handler for parent relationships."""
        handler_response = self.responder._handle_parents_intent(
            "CWE-79",
            self.sample_relationship_data
        )
        
        assert 'parent' in handler_response.lower() or 'broader' in handler_response.lower()
        assert 'CWE-20' in handler_response
        assert 'CWE-707' in handler_response
    
    def test_intent_handler_tell_more(self):
        """Test specific intent handler for tell me more."""
        handler_response = self.responder._handle_tell_more_intent(
            "CWE-79",
            self.sample_relationship_data
        )
        
        assert len(handler_response) > 200  # Should be comprehensive
        assert 'CWE-79' in handler_response
        assert 'Extended technical description' in handler_response
    
    def test_intent_handler_examples(self):
        """Test specific intent handler for examples."""
        handler_response = self.responder._handle_examples_intent("CWE-79")
        
        assert 'example' in handler_response.lower()
        assert 'CWE-79' in handler_response
        assert 'vulnerability' in handler_response.lower()
    
    def test_intent_handler_general_followup(self):
        """Test specific intent handler for general follow-up."""
        handler_response = self.responder._handle_general_followup_intent(
            "CWE-79",
            self.sample_relationship_data
        )
        
        assert 'CWE-79' in handler_response
        assert len(handler_response) > 100
    
    def test_response_count_increment(self):
        """Test that response count increments properly."""
        initial_count = self.responder.response_count
        
        intent = FollowupIntent(
            is_followup=True,
            intent_type='related',
            confidence=0.8,
            matched_patterns=['related']
        )
        
        self.responder.generate_contextual_response(
            query="What's related?",
            context_cwe_id="CWE-79",
            intent=intent,
            relationship_data=self.sample_relationship_data,
            related_results=self.sample_related_results
        )
        
        assert self.responder.response_count == initial_count + 1
    
    def test_error_handling_invalid_intent_type(self):
        """Test error handling for invalid intent types."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='invalid_type',
            confidence=0.8,
            matched_patterns=['invalid']
        )
        
        response = self.responder.generate_contextual_response(
            query="Invalid intent query",
            context_cwe_id="CWE-79",
            intent=intent,
            relationship_data=self.sample_relationship_data,
            related_results=[]
        )
        
        # Should fallback to general handling
        assert isinstance(response, ContextualResponse)
        assert response.confidence_score < 1.0
        assert 'CWE-79' in response.content
    
    def test_metadata_preservation(self):
        """Test that response metadata is properly preserved."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='consequences',
            confidence=0.9,
            matched_patterns=['impact', 'consequences']
        )
        
        response = self.responder.generate_contextual_response(
            query="What are the impacts?",
            context_cwe_id="CWE-79",
            intent=intent,
            relationship_data=self.sample_relationship_data,
            related_results=[]
        )
        
        assert response.metadata['intent'] == 'consequences'
        assert response.metadata['original_cwe'] == 'CWE-79'
        assert response.metadata['has_relationship_data'] is True


@pytest.mark.integration
class TestContextualResponderIntegration:
    """Integration tests for contextual responder."""
    
    def setup_method(self):
        """Set up integration test fixtures."""
        self.responder = ContextualResponder()
    
    def test_full_contextual_workflow(self):
        """Test complete contextual response workflow."""
        # Simulate various follow-up intents in sequence
        base_cwe = "CWE-79"
        relationship_data = {
            'relationships': {'ChildOf': ['CWE-20'], 'ParentOf': ['CWE-80']},
            'consequences': [{'scope': 'Confidentiality', 'impact': 'Data exposure'}],
            'extended_description': 'Detailed vulnerability information.'
        }
        related_results = [
            CWEResult(cwe_id='CWE-80', name='Basic XSS', description='Basic XSS', confidence_score=0.9)
        ]
        
        # Test sequence of different intents
        intent_types = ['related', 'consequences', 'prevention', 'tell_more', 'children']
        
        responses = []
        for intent_type in intent_types:
            intent = FollowupIntent(
                is_followup=True,
                intent_type=intent_type,
                confidence=0.8,
                matched_patterns=[intent_type]
            )
            
            response = self.responder.generate_contextual_response(
                query=f"Show me {intent_type}",
                context_cwe_id=base_cwe,
                intent=intent,
                relationship_data=relationship_data,
                related_results=related_results
            )
            
            responses.append(response)
            assert isinstance(response, ContextualResponse)
            assert response.context_used is True
            assert base_cwe in response.content
        
        # Verify responses are different and contextually appropriate
        contents = [r.content for r in responses]
        assert len(set(contents)) == len(contents)  # All responses should be different
        
        # Verify intent-specific content
        assert 'related' in contents[0].lower() or 'similar' in contents[0].lower()
        assert 'consequences' in contents[1].lower() or 'impact' in contents[1].lower()
        assert 'prevent' in contents[2].lower() or 'mitigation' in contents[2].lower()
        assert len(contents[3]) > len(contents[0])  # tell_more should be longer
        assert 'child' in contents[4].lower() or 'specific' in contents[4].lower()