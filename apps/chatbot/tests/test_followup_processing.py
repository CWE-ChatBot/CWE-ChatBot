"""
Unit tests for Story 2.2 Follow-up Processing components.

Tests follow-up intent detection, contextual query processing, and response generation.
"""

import pytest
from unittest.mock import Mock, patch
from dataclasses import asdict

from src.processing.followup_processor import FollowupProcessor, FollowupIntent
from src.processing.contextual_responder import ContextualResponder, ContextualResponse
from src.retrieval.base_retriever import CWEResult


class TestFollowupProcessor:
    """Test follow-up query processing functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.processor = FollowupProcessor()
    
    def test_initialization(self):
        """Test FollowupProcessor initialization."""
        processor = FollowupProcessor()
        assert hasattr(processor, 'compiled_patterns')
        assert len(processor.compiled_patterns) > 0
        assert 'tell_more' in processor.compiled_patterns
        assert 'consequences' in processor.compiled_patterns
    
    def test_detect_tell_more_intent(self):
        """Test detection of 'tell me more' intent."""
        queries = [
            "tell me more",
            "give me more details", 
            "elaborate on this",
            "can you expand on that",
            "what else can you tell me"
        ]
        
        for query in queries:
            intent = self.processor.detect_followup_intent(query)
            assert intent.is_followup is True
            assert intent.intent_type == 'tell_more'
            assert intent.confidence >= self.processor.MEDIUM_CONFIDENCE_THRESHOLD
            assert len(intent.matched_patterns) > 0
    
    def test_detect_consequences_intent(self):
        """Test detection of consequences intent."""
        queries = [
            "what are its consequences",
            "what happens when this occurs",
            "what's the impact",
            "what effects does this have",
            "what damage can this cause"
        ]
        
        for query in queries:
            intent = self.processor.detect_followup_intent(query)
            assert intent.is_followup is True
            assert intent.intent_type == 'consequences'
            assert intent.confidence >= self.processor.MEDIUM_CONFIDENCE_THRESHOLD
    
    def test_detect_children_intent(self):
        """Test detection of children/subtypes intent."""
        queries = [
            "what are its children",
            "show me child CWEs",
            "what are the more specific types",
            "what variants exist",
            "what subtypes are there"
        ]
        
        for query in queries:
            intent = self.processor.detect_followup_intent(query)
            assert intent.is_followup is True
            assert intent.intent_type == 'children'
    
    def test_detect_related_intent(self):
        """Test detection of related CWEs intent."""
        queries = [
            "show me related CWEs",
            "what similar vulnerabilities exist",
            "what's connected to this", 
            "find comparable weaknesses",
            "what are analogous issues"
        ]
        
        for query in queries:
            intent = self.processor.detect_followup_intent(query)
            assert intent.is_followup is True
            assert intent.intent_type == 'related'
    
    def test_detect_prevention_intent(self):
        """Test detection of prevention/mitigation intent."""
        queries = [
            "how do I prevent this",
            "how can I fix this vulnerability",
            "what are the countermeasures",
            "how do I mitigate this risk",
            "what are the best practices"
        ]
        
        for query in queries:
            intent = self.processor.detect_followup_intent(query)
            assert intent.is_followup is True
            assert intent.intent_type == 'prevention'
    
    def test_non_followup_queries(self):
        """Test that non-follow-up queries are correctly identified."""
        queries = [
            "what is CWE-79",
            "explain SQL injection",
            "find buffer overflow vulnerabilities",
            "hello how are you",
            "the weather is nice today"
        ]
        
        for query in queries:
            intent = self.processor.detect_followup_intent(query)
            assert intent.is_followup is False
            assert intent.confidence < self.processor.MEDIUM_CONFIDENCE_THRESHOLD
    
    def test_empty_query_handling(self):
        """Test handling of empty or invalid queries."""
        empty_queries = ["", "   ", None]
        
        for query in [q for q in empty_queries if q is not None]:
            intent = self.processor.detect_followup_intent(query)
            assert intent.is_followup is False
            assert intent.intent_type == "none"
            assert intent.confidence == 0.0
    
    def test_process_followup_query_tell_more(self):
        """Test processing of 'tell me more' follow-up query."""
        query = "tell me more"
        context_cwe = "CWE-79"
        intent = FollowupIntent(
            is_followup=True,
            intent_type='tell_more',
            confidence=0.9,
            matched_patterns=['tell me more'],
            extracted_entities={}
        )
        
        result = self.processor.process_followup_query(query, context_cwe, intent)
        
        assert result['original_query'] == query
        assert result['context_cwe'] == context_cwe
        assert result['intent'] == intent
        assert result['is_contextual'] is True
        assert result['query_type'] == 'followup'
        assert 'enhanced_query' in result
        assert 'retrieval_strategy' in result
    
    def test_process_followup_query_with_relationships(self):
        """Test processing of relationship-based follow-up queries."""
        test_cases = [
            ('children', 'what are its children', 'relationship'),
            ('parents', 'what are its parents', 'relationship'),
            ('related', 'show me related CWEs', 'similarity')
        ]
        
        for intent_type, query, expected_strategy in test_cases:
            intent = FollowupIntent(
                is_followup=True,
                intent_type=intent_type,
                confidence=0.8,
                matched_patterns=[query.lower()],
                extracted_entities={}
            )
            
            result = self.processor.process_followup_query(query, "CWE-89", intent)
            
            assert result['retrieval_strategy'] == expected_strategy
            assert result['retrieval_params']['context_cwe'] == "CWE-89"
    
    def test_process_followup_without_context(self):
        """Test processing follow-up query without valid context."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='tell_more',
            confidence=0.9,
            matched_patterns=[],
            extracted_entities={}
        )
        
        # Test with no context CWE
        result = self.processor.process_followup_query("tell me more", None, intent)
        assert result['is_contextual'] is False
        assert result['query_type'] == 'general'
        
        # Test with non-followup intent
        non_followup_intent = FollowupIntent(
            is_followup=False,
            intent_type='none',
            confidence=0.1,
            matched_patterns=[],
            extracted_entities={}
        )
        
        result = self.processor.process_followup_query("tell me more", "CWE-79", non_followup_intent)
        assert result['is_contextual'] is False
    
    def test_entity_extraction(self):
        """Test entity extraction from follow-up queries."""
        queries_with_entities = [
            ("show me related CWEs like CWE-89", {'mentioned_cwes': ['CWE-89']}),
            ("what children does CWE-20 have", {'mentioned_cwes': ['CWE-20'], 'relationship_terms': ['child']}),
            ("give me code examples", {'wants_code_example': True}),
            ("show me language specific prevention", {'wants_language_specific': True})
        ]
        
        for query, expected_entities in queries_with_entities:
            intent = self.processor.detect_followup_intent(query)
            
            # Check if any expected entities were extracted
            for key, value in expected_entities.items():
                if key in intent.extracted_entities:
                    if isinstance(value, list):
                        assert any(item in intent.extracted_entities[key] for item in value)
                    else:
                        assert intent.extracted_entities[key] == value
    
    def test_get_supported_intents(self):
        """Test getting list of supported intent types."""
        intents = self.processor.get_supported_intents()
        
        expected_intents = ['tell_more', 'consequences', 'children', 'parents', 'related', 'examples', 'prevention', 'exploitation']
        
        for expected in expected_intents:
            assert expected in intents
    
    def test_pattern_examples(self):
        """Test getting pattern examples for intent types."""
        for intent_type in ['tell_more', 'consequences', 'children']:
            examples = self.processor.get_pattern_examples(intent_type)
            assert isinstance(examples, list)
            assert len(examples) > 0


class TestContextualResponder:
    """Test contextual response generation functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.responder = ContextualResponder()
        
        # Create mock CWE result for testing
        self.mock_cwe_result = CWEResult(
            cwe_id='CWE-79',
            name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            description='The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.',
            confidence_score=0.95,
            source_method='direct_comprehensive',
            extended_description='Cross-site scripting (XSS) vulnerabilities occur when an application includes untrusted data in a web page without proper validation or escaping.',
            abstraction='Base',
            status='Stable',
            relationships={'ChildOf': ['CWE-20'], 'ParentOf': ['CWE-80', 'CWE-81']},
            consequences=[
                {'scope': 'Confidentiality', 'impact': 'Read Application Data'},
                {'scope': 'Integrity', 'impact': 'Execute Unauthorized Code'}
            ]
        )
    
    def test_initialization(self):
        """Test ContextualResponder initialization."""
        responder = ContextualResponder()
        assert responder.response_count == 0
        assert hasattr(responder, 'RESPONSE_TEMPLATES')
    
    def test_generate_tell_more_response(self):
        """Test generation of 'tell me more' responses."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='tell_more',
            confidence=0.9,
            matched_patterns=['tell me more'],
            extracted_entities={}
        )
        
        relationship_data = {
            'relationships': self.mock_cwe_result.relationships,
            'consequences': self.mock_cwe_result.consequences,
            'extended_description': self.mock_cwe_result.extended_description
        }
        
        response = self.responder._generate_tell_more_response(
            'CWE-79', relationship_data, [self.mock_cwe_result]
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.response_type == 'followup'
        assert response.context_used is True
        assert 'CWE-79' in response.sources
        assert 'CWE-79' in response.content
        assert 'Detailed Description' in response.content or 'Extended Description' in response.content
        assert response.metadata['intent'] == 'tell_more'
    
    def test_generate_consequences_response(self):
        """Test generation of consequences-focused responses."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='consequences',
            confidence=0.8,
            matched_patterns=['consequences'],
            extracted_entities={}
        )
        
        relationship_data = {
            'consequences': self.mock_cwe_result.consequences
        }
        
        response = self.responder._generate_consequences_response('CWE-79', relationship_data)
        
        assert isinstance(response, ContextualResponse)
        assert response.response_type == 'followup'
        assert 'Consequences' in response.content
        assert 'Confidentiality' in response.content
        assert 'Integrity' in response.content
        assert response.metadata['consequence_count'] == 2
    
    def test_generate_relationship_response_children(self):
        """Test generation of children relationship responses."""
        intent = FollowupIntent(
            is_followup=True,
            intent_type='children',
            confidence=0.8,
            matched_patterns=['children'],
            extracted_entities={}
        )
        
        relationship_data = {
            'relationships': {'ParentOf': ['CWE-80', 'CWE-81']}
        }
        
        # Create mock child CWE results
        child_cwes = [
            CWEResult('CWE-80', 'Basic XSS', 'Basic cross-site scripting', 0.9, 'mock'),
            CWEResult('CWE-81', 'Reflected XSS', 'Reflected cross-site scripting', 0.9, 'mock')
        ]
        
        response = self.responder._generate_relationship_response(
            'CWE-79', 'children', relationship_data, child_cwes
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.response_type == 'relationship'
        assert 'Child CWEs' in response.content
        assert 'CWE-80' in response.content
        assert 'CWE-81' in response.content
        assert response.metadata['relationship_count'] == 2
    
    def test_generate_related_response(self):
        """Test generation of related CWEs responses."""
        similar_cwes = [
            CWEResult('CWE-89', 'SQL Injection', 'SQL injection vulnerability', 0.85, 'vector_similarity'),
            CWEResult('CWE-78', 'OS Command Injection', 'Command injection vulnerability', 0.80, 'vector_similarity')
        ]
        
        response = self.responder._generate_related_response('CWE-79', similar_cwes)
        
        assert isinstance(response, ContextualResponse)
        assert response.response_type == 'relationship'
        assert 'related to CWE-79' in response.content
        assert 'CWE-89' in response.content
        assert 'CWE-78' in response.content
        assert '85%' in response.content  # Similarity percentage
        assert '80%' in response.content
    
    def test_generate_examples_response(self):
        """Test generation of examples-focused responses."""
        relationship_data = {
            'extended_description': 'Detailed description with examples of XSS vulnerabilities...'
        }
        
        response = self.responder._generate_examples_response('CWE-79', relationship_data)
        
        assert isinstance(response, ContextualResponse)
        assert response.response_type == 'followup'
        assert 'Examples' in response.content
        assert 'Common Scenarios' in response.content
        assert response.metadata['has_extended_description'] is True
    
    def test_generate_prevention_response(self):
        """Test generation of prevention-focused responses."""
        relationship_data = {}
        
        response = self.responder._generate_prevention_response('CWE-79', relationship_data)
        
        assert isinstance(response, ContextualResponse)
        assert response.response_type == 'followup'
        assert 'Prevention strategies' in response.content
        assert 'Input Validation' in response.content
        assert 'Security Controls' in response.content
        assert 'Best Practices' in response.content
    
    def test_generate_direct_response(self):
        """Test generation of direct responses without context."""
        query = "what is CWE-79"
        results = [self.mock_cwe_result]
        
        response = self.responder._generate_direct_response(query, results)
        
        assert isinstance(response, ContextualResponse)
        assert response.response_type == 'direct'
        assert response.context_used is False
        assert 'CWE-79' in response.content
        assert self.mock_cwe_result.name in response.content
    
    def test_generate_error_response(self):
        """Test generation of error responses."""
        query = "invalid query"
        error_msg = "No information found"
        
        response = self.responder._generate_error_response(query, error_msg)
        
        assert isinstance(response, ContextualResponse)
        assert response.response_type == 'error'
        assert response.context_used is False
        assert len(response.sources) == 0
        assert error_msg in response.content
        assert query in response.content
    
    def test_contextual_response_integration(self):
        """Test full contextual response generation workflow."""
        query = "tell me more about the consequences"
        context_cwe = "CWE-79"
        intent = FollowupIntent(
            is_followup=True,
            intent_type='consequences',
            confidence=0.9,
            matched_patterns=['consequences'],
            extracted_entities={}
        )
        
        relationship_data = {
            'relationships': self.mock_cwe_result.relationships,
            'consequences': self.mock_cwe_result.consequences,
            'extended_description': self.mock_cwe_result.extended_description
        }
        
        response = self.responder.generate_contextual_response(
            query, context_cwe, intent, relationship_data, [self.mock_cwe_result]
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.context_used is True
        assert response.response_type == 'followup'
        assert context_cwe in response.sources
        assert 'consequences' in response.content.lower()
    
    def test_fallback_to_direct_response(self):
        """Test fallback to direct response when context is unavailable."""
        query = "what is this vulnerability"
        intent = FollowupIntent(is_followup=False, intent_type='none', confidence=0.0, matched_patterns=[], extracted_entities={})
        
        response = self.responder.generate_contextual_response(
            query, None, intent, {}, [self.mock_cwe_result]
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.response_type == 'direct'
        assert response.context_used is False


@pytest.mark.integration
class TestFollowupIntegration:
    """Integration tests for follow-up processing components."""
    
    def setup_method(self):
        """Set up integration test fixtures."""
        self.processor = FollowupProcessor()
        self.responder = ContextualResponder()
    
    def test_complete_followup_workflow(self):
        """Test complete follow-up processing workflow."""
        # Simulate a follow-up conversation flow
        
        # 1. User asks about CWE-79 initially (context established)
        initial_context_cwe = "CWE-79"
        
        # 2. User asks follow-up question
        followup_query = "what are its consequences"
        
        # 3. Detect follow-up intent
        intent = self.processor.detect_followup_intent(followup_query)
        assert intent.is_followup is True
        assert intent.intent_type == 'consequences'
        
        # 4. Process follow-up query
        processed_query = self.processor.process_followup_query(
            followup_query, initial_context_cwe, intent
        )
        
        assert processed_query['is_contextual'] is True
        assert processed_query['context_cwe'] == initial_context_cwe
        
        # 5. Generate contextual response
        mock_cwe_result = CWEResult(
            cwe_id='CWE-79',
            name='Cross-site Scripting',
            description='XSS vulnerability',
            confidence_score=0.95,
            source_method='direct',
            consequences=[
                {'scope': 'Confidentiality', 'impact': 'Read Application Data'}
            ]
        )
        
        relationship_data = {
            'consequences': mock_cwe_result.consequences,
            'relationships': {},
            'extended_description': None
        }
        
        response = self.responder.generate_contextual_response(
            followup_query, initial_context_cwe, intent, relationship_data, [mock_cwe_result]
        )
        
        assert isinstance(response, ContextualResponse)
        assert response.context_used is True
        assert response.response_type == 'followup'
        assert 'consequences' in response.content.lower()
        assert 'CWE-79' in response.sources
    
    def test_multiple_followup_intents(self):
        """Test handling multiple different follow-up intents in sequence."""
        context_cwe = "CWE-89"
        
        followup_scenarios = [
            ("tell me more", "tell_more"),
            ("what are its consequences", "consequences"), 
            ("show me related CWEs", "related"),
            ("how do I prevent this", "prevention"),
            ("what are its children", "children")
        ]
        
        for query, expected_intent in followup_scenarios:
            # Detect intent
            intent = self.processor.detect_followup_intent(query)
            assert intent.is_followup is True
            assert intent.intent_type == expected_intent
            
            # Process query
            processed = self.processor.process_followup_query(query, context_cwe, intent)
            assert processed['context_cwe'] == context_cwe
            assert processed['is_contextual'] is True
    
    def test_intent_confidence_thresholds(self):
        """Test that intent confidence thresholds work correctly."""
        # High confidence queries
        high_confidence_queries = [
            "tell me more",
            "what are the consequences", 
            "show me related CWEs"
        ]
        
        for query in high_confidence_queries:
            intent = self.processor.detect_followup_intent(query)
            assert intent.confidence >= self.processor.HIGH_CONFIDENCE_THRESHOLD
        
        # Medium confidence queries (still valid follow-ups)
        medium_confidence_queries = [
            "more info please",
            "what happens",
            "similar ones"
        ]
        
        for query in medium_confidence_queries:
            intent = self.processor.detect_followup_intent(query)
            assert intent.confidence >= self.processor.MEDIUM_CONFIDENCE_THRESHOLD
        
        # Low confidence queries (should not be treated as follow-ups)
        low_confidence_queries = [
            "hello",
            "the weather is nice",
            "completely unrelated question"
        ]
        
        for query in low_confidence_queries:
            intent = self.processor.detect_followup_intent(query)
            assert intent.confidence < self.processor.MEDIUM_CONFIDENCE_THRESHOLD
            assert intent.is_followup is False