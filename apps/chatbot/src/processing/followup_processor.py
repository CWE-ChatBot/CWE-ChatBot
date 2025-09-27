"""
Follow-up Query Processor for Story 2.2 - Contextual Query Understanding

This module handles detection and processing of follow-up questions that reference
previously discussed CWEs in the conversational context.

Key Features:
- Follow-up intent detection using pattern matching
- Context-aware query processing
- Integration with session management
- Support for various follow-up question types
"""

import logging
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FollowupIntent:
    """Data class for follow-up intent detection results."""
    is_followup: bool
    intent_type: str  # 'tell_more', 'consequences', 'children', 'examples', 'related', etc.
    confidence: float
    matched_patterns: List[str]
    extracted_entities: Dict[str, Any]


class FollowupProcessor:
    """
    Processes follow-up queries that reference previous conversational context.
    
    This class detects when a user's query is a follow-up to a previous CWE discussion
    and extracts the intent to provide contextually relevant responses.
    """
    
    # Follow-up patterns with their corresponding intents
    FOLLOWUP_PATTERNS = {
        'tell_more': [
            r'tell me more',
            r'more (detail|info|information)',
            r'elaborate',
            r'expand on (this|that|it)',
            r'give me more',
            r'what else',
            r'continue',
            r'go on'
        ],
        'consequences': [
            r'what are (its?|the) consequences',
            r'what (happens|occurs) when',
            r'impact',
            r'effects?',
            r'what.*damage',
            r'harm.*caused',
            r'result.*exploit'
        ],
        'children': [
            r'what are (its?|the) children',
            r'child.*cwes?',
            r'more specific',
            r'subtypes?',
            r'variants?',
            r'specific.*forms?',
            r'derived.*from'
        ],
        'parents': [
            r'what are (its?|the) parents?',
            r'parent.*cwes?',
            r'broader.*category',
            r'generalizations?',
            r'what.*category',
            r'belongs.*to'
        ],
        'related': [
            r'related.*cwes?',
            r'similar.*vulnerabilities',
            r'connected.*to',
            r'associated.*with',
            r'linked.*to',
            r'comparable',
            r'analogous'
        ],
        'examples': [
            r'give.*examples?',
            r'show.*examples?',
            r'for instance',
            r'such as',
            r'like what',
            r'demonstrate',
            r'illustrate'
        ],
        'prevention': [
            r'how.*prevent',
            r'how.*fix',
            r'how.*mitigate',
            r'remediation',
            r'countermeasures?',
            r'solutions?',
            r'best practices'
        ],
        'exploitation': [
            r'how.*exploit',
            r'attack.*vectors?',
            r'how.*attack',
            r'vulnerable.*to',
            r'exploit.*this',
            r'attack.*methods?'
        ]
    }
    
    # Confidence thresholds for different types of matches
    HIGH_CONFIDENCE_THRESHOLD = 0.8
    MEDIUM_CONFIDENCE_THRESHOLD = 0.5
    
    def __init__(self) -> None:
        """Initialize follow-up processor."""
        # Compile regex patterns for efficiency
        self.compiled_patterns = {}
        for intent_type, patterns in self.FOLLOWUP_PATTERNS.items():
            self.compiled_patterns[intent_type] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
        
        logger.info("FollowupProcessor initialized with pattern matching")
    
    def detect_followup_intent(self, query: str) -> FollowupIntent:
        """
        Detect if query is a follow-up and extract intent.
        
        Args:
            query: User query string
            
        Returns:
            FollowupIntent object with detection results
        """
        if not query or not query.strip():
            return FollowupIntent(
                is_followup=False,
                intent_type="none",
                confidence=0.0,
                matched_patterns=[],
                extracted_entities={}
            )
        
        query_cleaned = query.strip().lower()
        
        # Check each intent type for matches
        intent_scores = {}
        matched_patterns_all = {}
        
        for intent_type, patterns in self.compiled_patterns.items():
            matches = []
            for pattern in patterns:
                match = pattern.search(query_cleaned)
                if match:
                    matches.append(match.group(0))
            
            if matches:
                # Calculate confidence based on number and quality of matches
                confidence = min(1.0, len(matches) * 0.3 + 0.4)
                intent_scores[intent_type] = confidence
                matched_patterns_all[intent_type] = matches
        
        # Determine best intent match
        if not intent_scores:
            return FollowupIntent(
                is_followup=False,
                intent_type="none",
                confidence=0.0,
                matched_patterns=[],
                extracted_entities={}
            )
        
        # Get highest scoring intent
        best_intent = max(intent_scores.keys(), key=lambda k: intent_scores[k])
        best_confidence = intent_scores[best_intent]
        best_patterns = matched_patterns_all[best_intent]
        
        # Extract any additional entities from the query
        extracted_entities = self._extract_entities(query_cleaned, best_intent)
        
        is_followup = best_confidence >= self.MEDIUM_CONFIDENCE_THRESHOLD
        
        logger.debug(f"Follow-up detection: {query[:50]}... -> {best_intent} (confidence: {best_confidence})")
        
        return FollowupIntent(
            is_followup=is_followup,
            intent_type=best_intent,
            confidence=best_confidence,
            matched_patterns=best_patterns,
            extracted_entities=extracted_entities
        )
    
    def process_followup_query(
        self, 
        query: str, 
        context_cwe: str, 
        intent: FollowupIntent
    ) -> Dict[str, Any]:
        """
        Process follow-up query with context and intent.
        
        Args:
            query: Original user query
            context_cwe: CWE ID from current context
            intent: Detected follow-up intent
            
        Returns:
            Processed query information for retrieval
        """
        if not context_cwe or not intent.is_followup:
            return self._create_fallback_query(query)
        
        try:
            # Create context-enhanced query based on intent type
            enhanced_query = self._enhance_query_with_context(query, context_cwe, intent)
            
            # Determine appropriate retrieval strategy
            retrieval_strategy = self._get_retrieval_strategy(intent.intent_type)
            
            # Set retrieval parameters
            retrieval_params = self._get_retrieval_params(intent.intent_type, context_cwe)
            
            processed_query = {
                'original_query': query,
                'enhanced_query': enhanced_query,
                'context_cwe': context_cwe,
                'intent': intent,
                'retrieval_strategy': retrieval_strategy,
                'retrieval_params': retrieval_params,
                'query_type': 'followup',
                'is_contextual': True
            }
            
            logger.info(f"Processed follow-up query: {intent.intent_type} for {context_cwe}")
            return processed_query
            
        except Exception as e:
            logger.error(f"Follow-up query processing failed: {e}")
            return self._create_fallback_query(query)
    
    def _extract_entities(self, query: str, intent_type: str) -> Dict[str, Any]:
        """Extract relevant entities from the query based on intent type."""
        entities = {}
        
        try:
            # Extract CWE IDs mentioned in the query
            cwe_pattern = re.compile(r'cwe[-_]?(\d+)', re.IGNORECASE)
            cwe_matches = cwe_pattern.findall(query)
            if cwe_matches:
                entities['mentioned_cwes'] = [f"CWE-{cwe_id}" for cwe_id in cwe_matches]
            
            # Extract specific terms based on intent
            if intent_type in ['related', 'children', 'parents']:
                # Look for relationship terms
                relationship_terms = ['child', 'parent', 'sibling', 'peer', 'related']
                found_terms = [term for term in relationship_terms if term in query]
                if found_terms:
                    entities['relationship_terms'] = found_terms
            
            elif intent_type in ['prevention', 'examples']:
                # Look for context-specific terms
                if 'code' in query:
                    entities['wants_code_example'] = True
                if 'language' in query:
                    entities['wants_language_specific'] = True
            
            return entities
            
        except Exception as e:
            logger.error(f"Entity extraction failed: {e}")
            return {}
    
    def _enhance_query_with_context(
        self, 
        query: str, 
        context_cwe: str, 
        intent: FollowupIntent
    ) -> str:
        """Enhance the query with contextual information."""
        
        # Base enhancement with context CWE
        enhanced_parts = [context_cwe]
        
        # Add intent-specific enhancements
        if intent.intent_type == 'tell_more':
            enhanced_parts.extend(['detailed description', 'comprehensive information'])
        
        elif intent.intent_type == 'consequences':
            enhanced_parts.extend(['consequences', 'impact', 'effects', 'damage'])
        
        elif intent.intent_type == 'children':
            enhanced_parts.extend(['child CWEs', 'specific types', 'subtypes'])
        
        elif intent.intent_type == 'parents':
            enhanced_parts.extend(['parent CWEs', 'broader categories', 'generalizations'])
        
        elif intent.intent_type == 'related':
            enhanced_parts.extend(['related CWEs', 'similar vulnerabilities', 'connected'])
        
        elif intent.intent_type == 'examples':
            enhanced_parts.extend(['examples', 'code samples', 'demonstrations'])
        
        elif intent.intent_type == 'prevention':
            enhanced_parts.extend(['prevention', 'mitigation', 'countermeasures', 'fix'])
        
        elif intent.intent_type == 'exploitation':
            enhanced_parts.extend(['exploitation', 'attack vectors', 'attack methods'])
        
        # Combine with original query
        enhanced_query = f"{' '.join(enhanced_parts)} {query}"
        
        logger.debug(f"Enhanced query: {query} -> {enhanced_query}")
        return enhanced_query
    
    def _get_retrieval_strategy(self, intent_type: str) -> str:
        """Get appropriate retrieval strategy for intent type."""
        
        strategy_map = {
            'tell_more': 'direct',  # Get comprehensive data for specific CWE
            'consequences': 'direct',  # Get detailed CWE data
            'children': 'relationship',  # Use relationship queries
            'parents': 'relationship',
            'related': 'similarity',  # Use vector similarity
            'examples': 'direct',  # Get CWE data with examples
            'prevention': 'hybrid',  # Search for prevention content
            'exploitation': 'hybrid'  # Search for exploitation content
        }
        
        return strategy_map.get(intent_type, 'hybrid')
    
    def _get_retrieval_params(self, intent_type: str, context_cwe: str) -> Dict[str, Any]:
        """Get retrieval parameters specific to intent type."""
        
        params = {
            'context_cwe': context_cwe,
            'include_relationships': True,
            'k': 5
        }
        
        # Intent-specific parameters
        if intent_type == 'children':
            params.update({
                'relationship_type': 'ChildOf',
                'relationship_direction': 'children'
            })
        
        elif intent_type == 'parents':
            params.update({
                'relationship_type': 'ParentOf', 
                'relationship_direction': 'parents'
            })
        
        elif intent_type == 'related':
            params.update({
                'similarity_search': True,
                'k': 10  # Get more related items
            })
        
        elif intent_type in ['tell_more', 'consequences', 'examples']:
            params.update({
                'comprehensive_data': True,
                'k': 1  # Just need the specific CWE
            })
        
        return params
    
    def _create_fallback_query(self, query: str) -> Dict[str, Any]:
        """Create fallback query structure when follow-up processing fails."""
        return {
            'original_query': query,
            'enhanced_query': query,
            'context_cwe': None,
            'intent': FollowupIntent(
                is_followup=False,
                intent_type="none",
                confidence=0.0,
                matched_patterns=[],
                extracted_entities={}
            ),
            'retrieval_strategy': 'hybrid',
            'retrieval_params': {'k': 5},
            'query_type': 'general',
            'is_contextual': False
        }
    
    def get_supported_intents(self) -> List[str]:
        """Get list of supported follow-up intent types."""
        return list(self.FOLLOWUP_PATTERNS.keys())
    
    def get_pattern_examples(self, intent_type: str) -> List[str]:
        """Get example patterns for a specific intent type."""
        return self.FOLLOWUP_PATTERNS.get(intent_type, [])
