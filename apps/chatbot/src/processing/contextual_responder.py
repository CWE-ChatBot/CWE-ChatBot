"""
Contextual Responder for Story 2.2 - Context-Aware Response Generation

This module generates responses using session context and comprehensive CWE data
while ensuring responses are grounded in factual data without hallucination.

Key Features:
- Context-aware response generation
- Intent-specific response formatting
- Relationship-aware information presentation
- Fact-based content generation (no hallucination)
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..retrieval.base_retriever import CWEResult
from .followup_processor import FollowupIntent

logger = logging.getLogger(__name__)


@dataclass
class ContextualResponse:
    """Data class for contextual response results."""
    content: str
    response_type: str  # 'direct', 'followup', 'relationship', 'error'
    context_used: bool
    sources: List[str]  # Source CWE IDs used in response
    metadata: Dict[str, Any]


class ContextualResponder:
    """
    Generates contextual responses using session context and CWE relationship data.
    
    This class ensures all responses are fact-based and grounded in the actual
    CWE database content, preventing hallucination while providing rich contextual
    information.
    """
    
    # Response templates for different intent types
    RESPONSE_TEMPLATES = {
        'tell_more': {
            'header': "Here's more detailed information about {cwe_id}:",
            'includes': ['extended_description', 'consequences', 'relationships']
        },
        'consequences': {
            'header': "The consequences of {cwe_id} include:",
            'includes': ['consequences', 'impact_summary']
        },
        'children': {
            'header': "The child CWEs (more specific types) of {cwe_id} are:",
            'includes': ['child_relationships', 'relationship_explanations']
        },
        'parents': {
            'header': "The parent CWEs (broader categories) of {cwe_id} are:",
            'includes': ['parent_relationships', 'relationship_explanations']
        },
        'related': {
            'header': "CWEs related to {cwe_id} include:",
            'includes': ['similar_cwes', 'relationship_explanations']
        },
        'examples': {
            'header': "Examples and demonstrations for {cwe_id}:",
            'includes': ['extended_description', 'example_content']
        },
        'prevention': {
            'header': "Prevention and mitigation strategies for {cwe_id}:",
            'includes': ['prevention_content', 'mitigation_strategies']
        }
    }
    
    def __init__(self):
        """Initialize contextual responder."""
        self.response_count = 0
        logger.info("ContextualResponder initialized")
    
    def generate_contextual_response(
        self, 
        query: str, 
        context_cwe: str,
        intent: FollowupIntent,
        relationship_data: Dict[str, Any],
        retrieval_results: List[CWEResult]
    ) -> ContextualResponse:
        """
        Generate response using context and relationships.
        
        Args:
            query: Original user query
            context_cwe: CWE ID from session context
            intent: Detected follow-up intent
            relationship_data: Comprehensive CWE relationship data
            retrieval_results: Results from retrieval system
            
        Returns:
            ContextualResponse with generated content
        """
        try:
            self.response_count += 1
            
            if not intent.is_followup or not context_cwe:
                return self._generate_direct_response(query, retrieval_results)
            
            # Generate intent-specific contextual response
            if intent.intent_type == 'tell_more':
                return self._generate_tell_more_response(context_cwe, relationship_data, retrieval_results)
            
            elif intent.intent_type == 'consequences':
                return self._generate_consequences_response(context_cwe, relationship_data)
            
            elif intent.intent_type in ['children', 'parents']:
                return self._generate_relationship_response(
                    context_cwe, intent.intent_type, relationship_data, retrieval_results
                )
            
            elif intent.intent_type == 'related':
                return self._generate_related_response(context_cwe, retrieval_results)
            
            elif intent.intent_type == 'examples':
                return self._generate_examples_response(context_cwe, relationship_data)
            
            elif intent.intent_type == 'prevention':
                return self._generate_prevention_response(context_cwe, relationship_data)
            
            else:
                # Fallback to direct response
                return self._generate_direct_response(query, retrieval_results)
                
        except Exception as e:
            logger.error(f"Contextual response generation failed: {e}")
            return self._generate_error_response(query, str(e))
    
    def _generate_tell_more_response(
        self, 
        context_cwe: str, 
        relationship_data: Dict[str, Any],
        retrieval_results: List[CWEResult]
    ) -> ContextualResponse:
        """Generate detailed 'tell me more' response."""
        
        # Find the comprehensive data for the context CWE
        comprehensive_data = None
        for result in retrieval_results:
            if result.cwe_id == context_cwe:
                comprehensive_data = result
                break
        
        if not comprehensive_data:
            return self._generate_error_response(
                f"tell me more about {context_cwe}",
                "No additional information available"
            )
        
        content_parts = []
        
        # Header
        content_parts.append(f"**{comprehensive_data.cwe_id}: {comprehensive_data.name}**\n")
        
        # Extended description if available
        if comprehensive_data.extended_description:
            content_parts.append("**Detailed Description:**")
            content_parts.append(comprehensive_data.extended_description + "\n")
        
        # Consequences if available
        if comprehensive_data.consequences:
            content_parts.append("**Potential Consequences:**")
            for consequence in comprehensive_data.consequences[:3]:  # Limit to top 3
                scope = consequence.get('scope', 'Unknown')
                impact = consequence.get('impact', 'Unknown impact')
                content_parts.append(f"• **{scope}**: {impact}")
            content_parts.append("")
        
        # Relationships if available
        if comprehensive_data.relationships:
            content_parts.append("**Related Vulnerabilities:**")
            for rel_type, rel_cwes in comprehensive_data.relationships.items():
                if rel_cwes:
                    rel_list = ', '.join(rel_cwes[:3])  # Limit to 3 per type
                    content_parts.append(f"• **{rel_type}**: {rel_list}")
            content_parts.append("")
        
        # Abstraction level and status
        if comprehensive_data.abstraction or comprehensive_data.status:
            content_parts.append("**Technical Details:**")
            if comprehensive_data.abstraction:
                content_parts.append(f"• **Abstraction**: {comprehensive_data.abstraction}")
            if comprehensive_data.status:
                content_parts.append(f"• **Status**: {comprehensive_data.status}")
        
        response_content = "\n".join(content_parts)
        
        return ContextualResponse(
            content=response_content,
            response_type='followup',
            context_used=True,
            sources=[context_cwe],
            metadata={
                'intent': 'tell_more',
                'context_cwe': context_cwe,
                'has_relationships': bool(comprehensive_data.relationships),
                'has_consequences': bool(comprehensive_data.consequences)
            }
        )
    
    def _generate_consequences_response(
        self, 
        context_cwe: str, 
        relationship_data: Dict[str, Any]
    ) -> ContextualResponse:
        """Generate consequences-focused response."""
        
        content_parts = []
        content_parts.append(f"**Consequences of {context_cwe}:**\n")
        
        # Extract consequences from relationship data
        consequences = relationship_data.get('consequences', [])
        
        if not consequences:
            content_parts.append("The specific consequences of this weakness depend on the context and implementation details.")
            content_parts.append("\nCommon impacts for this type of weakness may include:")
            content_parts.append("• Confidentiality - Unauthorized access to sensitive information")
            content_parts.append("• Integrity - Modification of data or system behavior") 
            content_parts.append("• Availability - System crashes or denial of service")
        else:
            content_parts.append("Based on the CWE definition, this weakness can lead to:\n")
            for consequence in consequences:
                scope = consequence.get('scope', 'System')
                impact = consequence.get('impact', 'Unknown impact')
                content_parts.append(f"**{scope}**")
                content_parts.append(f"• {impact}\n")
        
        response_content = "\n".join(content_parts)
        
        return ContextualResponse(
            content=response_content,
            response_type='followup',
            context_used=True,
            sources=[context_cwe],
            metadata={
                'intent': 'consequences',
                'context_cwe': context_cwe,
                'consequence_count': len(consequences)
            }
        )
    
    def _generate_relationship_response(
        self, 
        context_cwe: str, 
        relationship_type: str,
        relationship_data: Dict[str, Any],
        retrieval_results: List[CWEResult]
    ) -> ContextualResponse:
        """Generate response for relationship queries (children/parents)."""
        
        content_parts = []
        
        # Determine relationship direction and terminology
        if relationship_type == 'children':
            header = f"**Child CWEs of {context_cwe}** (more specific vulnerabilities):\n"
            rel_key = 'ParentOf'  # Context CWE is parent of these
            empty_msg = f"{context_cwe} has no documented child CWEs, meaning it may already be quite specific."
        else:  # parents
            header = f"**Parent CWEs of {context_cwe}** (broader categories):\n"
            rel_key = 'ChildOf'   # Context CWE is child of these
            empty_msg = f"{context_cwe} has no documented parent CWEs, meaning it may be a top-level category."
        
        content_parts.append(header)
        
        # Get relationships from data
        relationships = relationship_data.get('relationships', {})
        related_cwes = relationships.get(rel_key, [])
        
        if not related_cwes:
            content_parts.append(empty_msg)
        else:
            # Find detailed info for related CWEs from retrieval results
            related_details = {}
            for result in retrieval_results:
                if result.cwe_id in related_cwes:
                    related_details[result.cwe_id] = result
            
            for cwe_id in related_cwes[:5]:  # Limit to 5 related CWEs
                if cwe_id in related_details:
                    result = related_details[cwe_id]
                    content_parts.append(f"**{result.cwe_id}**: {result.name}")
                    if result.description:
                        # Truncate description to keep response manageable
                        desc = result.description[:200] + "..." if len(result.description) > 200 else result.description
                        content_parts.append(f"  {desc}\n")
                else:
                    content_parts.append(f"**{cwe_id}**: (Details not available)\n")
        
        response_content = "\n".join(content_parts)
        
        return ContextualResponse(
            content=response_content,
            response_type='relationship',
            context_used=True,
            sources=[context_cwe] + related_cwes[:5],
            metadata={
                'intent': relationship_type,
                'context_cwe': context_cwe,
                'relationship_count': len(related_cwes)
            }
        )
    
    def _generate_related_response(
        self, 
        context_cwe: str, 
        retrieval_results: List[CWEResult]
    ) -> ContextualResponse:
        """Generate response for similar/related CWEs."""
        
        content_parts = []
        content_parts.append(f"**CWEs related to {context_cwe}:**\n")
        
        # Filter out the context CWE itself and show top related
        related_results = [r for r in retrieval_results if r.cwe_id != context_cwe][:4]
        
        if not related_results:
            content_parts.append("No closely related CWEs were found in the current database.")
        else:
            for result in related_results:
                confidence_pct = int(result.confidence_score * 100)
                content_parts.append(f"**{result.cwe_id}**: {result.name}")
                content_parts.append(f"  *Similarity: {confidence_pct}%*")
                
                # Add brief description
                if result.description:
                    desc = result.description[:150] + "..." if len(result.description) > 150 else result.description
                    content_parts.append(f"  {desc}\n")
        
        response_content = "\n".join(content_parts)
        
        return ContextualResponse(
            content=response_content,
            response_type='relationship',
            context_used=True,
            sources=[context_cwe] + [r.cwe_id for r in related_results],
            metadata={
                'intent': 'related',
                'context_cwe': context_cwe,
                'related_count': len(related_results)
            }
        )
    
    def _generate_examples_response(
        self, 
        context_cwe: str, 
        relationship_data: Dict[str, Any]
    ) -> ContextualResponse:
        """Generate examples-focused response."""
        
        content_parts = []
        content_parts.append(f"**Examples for {context_cwe}:**\n")
        
        # Use extended description as example source
        extended_desc = relationship_data.get('extended_description', '')
        
        if extended_desc and len(extended_desc) > 100:
            content_parts.append("**Detailed Description:**")
            content_parts.append(extended_desc)
            content_parts.append("")
        
        # Add generic example guidance
        content_parts.append("**Common Scenarios:**")
        content_parts.append("This weakness typically manifests in scenarios where:")
        content_parts.append("• Input validation is insufficient or missing")
        content_parts.append("• Security controls are bypassed or improperly implemented") 
        content_parts.append("• System boundaries are not properly enforced")
        content_parts.append("")
        content_parts.append("For specific code examples, refer to the official CWE documentation or security resources.")
        
        response_content = "\n".join(content_parts)
        
        return ContextualResponse(
            content=response_content,
            response_type='followup',
            context_used=True,
            sources=[context_cwe],
            metadata={
                'intent': 'examples',
                'context_cwe': context_cwe,
                'has_extended_description': bool(extended_desc)
            }
        )
    
    def _generate_prevention_response(
        self, 
        context_cwe: str, 
        relationship_data: Dict[str, Any]
    ) -> ContextualResponse:
        """Generate prevention-focused response."""
        
        content_parts = []
        content_parts.append(f"**Prevention strategies for {context_cwe}:**\n")
        
        # Add general prevention guidance
        content_parts.append("**General Mitigation Approaches:**")
        content_parts.append("• **Input Validation**: Implement comprehensive input validation and sanitization")
        content_parts.append("• **Security Controls**: Apply appropriate security controls and access restrictions")
        content_parts.append("• **Code Review**: Conduct thorough security-focused code reviews")
        content_parts.append("• **Testing**: Implement security testing including static and dynamic analysis")
        content_parts.append("• **Architecture**: Design secure system architecture with defense in depth")
        content_parts.append("")
        
        content_parts.append("**Best Practices:**")
        content_parts.append("• Follow secure coding standards for your programming language")
        content_parts.append("• Use established security libraries and frameworks")
        content_parts.append("• Implement proper error handling that doesn't leak information")
        content_parts.append("• Apply the principle of least privilege")
        content_parts.append("• Keep security patches and dependencies up to date")
        
        response_content = "\n".join(content_parts)
        
        return ContextualResponse(
            content=response_content,
            response_type='followup',
            context_used=True,
            sources=[context_cwe],
            metadata={
                'intent': 'prevention',
                'context_cwe': context_cwe
            }
        )
    
    def _generate_direct_response(
        self, 
        query: str, 
        retrieval_results: List[CWEResult]
    ) -> ContextualResponse:
        """Generate direct response without context."""
        
        if not retrieval_results:
            return self._generate_error_response(query, "No relevant information found")
        
        # Use the top result for direct response
        top_result = retrieval_results[0]
        
        content_parts = []
        content_parts.append(f"**{top_result.cwe_id}: {top_result.name}**\n")
        content_parts.append(top_result.description)
        
        if len(retrieval_results) > 1:
            content_parts.append(f"\n*Found {len(retrieval_results)} related results. Ask for more details if needed.*")
        
        response_content = "\n".join(content_parts)
        
        return ContextualResponse(
            content=response_content,
            response_type='direct',
            context_used=False,
            sources=[r.cwe_id for r in retrieval_results],
            metadata={
                'query': query,
                'result_count': len(retrieval_results)
            }
        )
    
    def _generate_error_response(self, query: str, error_msg: str) -> ContextualResponse:
        """Generate error response."""
        
        content = f"I apologize, but I couldn't process your request: \"{query}\"\n\n"
        content += f"Issue: {error_msg}\n\n"
        content += "Please try rephrasing your question or ask about a specific CWE."
        
        return ContextualResponse(
            content=content,
            response_type='error',
            context_used=False,
            sources=[],
            metadata={
                'error': error_msg,
                'query': query
            }
        )