#!/usr/bin/env python3
"""
Role-Aware Response Generator
Integrates role-based prompt templating with LLM response generation.
"""

import logging
from typing import Dict, List, Any, Optional
import asyncio
from dataclasses import dataclass

from ..prompts.role_templates import RolePromptTemplates
from ..user.role_manager import UserRole
from ..retrieval.base_retriever import CWEResult
from ..security.secure_logging import get_secure_logger
from ..security.input_sanitizer import InputSanitizer
from .confidence_manager import ConfidenceManager

logger = get_secure_logger(__name__)


@dataclass
class RoleAwareResponse:
    """Structure for role-aware response data."""
    content: str
    role: Optional[str]
    confidence_score: float
    citations: List[str]
    role_specific_emphasis: Dict[str, Any]
    confidence_display: Optional[str] = None  # Enhanced confidence display
    low_confidence_warning: Optional[str] = None  # Warning for low confidence


class RoleAwareResponder:
    """
    Generates role-tailored responses using prompt templates and retrieved CWE data.
    
    This component bridges the role management system with the LLM response generation,
    ensuring that responses are appropriately tailored to the user's selected role.
    """
    
    def __init__(self, mock_llm: bool = False):
        """
        Initialize the role-aware responder.
        
        Args:
            mock_llm: If True, use mock responses for testing (no actual LLM calls)
        """
        self.prompt_templates = RolePromptTemplates()
        self.confidence_manager = ConfidenceManager()
        self.input_sanitizer = InputSanitizer(max_length=2000, strict_mode=False)
        self.mock_llm = mock_llm
        logger.info("Initialized RoleAwareResponder with enhanced confidence scoring and input sanitization")
    
    async def generate_role_based_response(
        self,
        query: str,
        role: Optional[UserRole],
        cwe_results: List[CWEResult],
        confidence_score: float = 0.8
    ) -> RoleAwareResponse:
        """
        Generate a role-tailored response based on CWE data.
        
        Args:
            query: User's original query
            role: User's selected role (if any)
            cwe_results: Retrieved CWE data
            confidence_score: Confidence in the retrieval results
            
        Returns:
            RoleAwareResponse with tailored content
        """
        try:
            # Build context for prompt generation with sanitization
            context = self._build_context(query, cwe_results, confidence_score)
            
            # Apply comprehensive sanitization to all context data
            sanitized_context = self._sanitize_context_data(context)
            
            # Calculate enhanced confidence metrics
            query_type = sanitized_context.get('query_type', 'general')
            confidence_metrics = self.confidence_manager.calculate_confidence_metrics(
                confidence_score, query_type, len(cwe_results)
            )
            
            # Generate role-specific prompt with sanitized context
            role_prompt = self.prompt_templates.get_role_prompt(role, sanitized_context)
            
            # Add confidence-based guidance
            confidence_guidance = self.prompt_templates.get_confidence_guidance_prompt(confidence_score)
            full_prompt = role_prompt + confidence_guidance
            
            # Generate response (mock or real)
            if self.mock_llm:
                response_content = self._generate_mock_response(role, query, cwe_results, confidence_score)
            else:
                response_content = await self._generate_llm_response(full_prompt, sanitized_context)
            
            # Extract citations from CWE results
            citations = self._extract_citations(cwe_results)
            
            # Build role-specific emphasis metadata
            role_emphasis = self._build_role_emphasis(role, cwe_results)
            
            # Format confidence display
            confidence_display = self.confidence_manager.format_confidence_display(confidence_metrics)
            
            # Get low confidence warning if needed
            low_confidence_warning = self.confidence_manager.get_low_confidence_warning(confidence_metrics)
            
            return RoleAwareResponse(
                content=response_content,
                role=role.value if role else None,
                confidence_score=confidence_score,
                citations=citations,
                role_specific_emphasis=role_emphasis,
                confidence_display=confidence_display,
                low_confidence_warning=low_confidence_warning
            )
            
        except Exception as e:
            logger.error(f"Error generating role-based response: {e}")
            # Fallback response
            return RoleAwareResponse(
                content="I apologize, but I encountered an error generating a response. Please try again.",
                role=role.value if role else None,
                confidence_score=0.1,
                citations=[],
                role_specific_emphasis={}
            )
    
    def _build_context(
        self, 
        query: str, 
        cwe_results: List[CWEResult], 
        confidence_score: float
    ) -> Dict[str, Any]:
        """Build context dictionary for prompt generation."""
        context = {
            'query': query,
            'confidence_score': confidence_score,
            'num_results': len(cwe_results)
        }
        
        if cwe_results:
            primary_result = cwe_results[0]
            context['cwe_data'] = {
                'cwe_id': primary_result.cwe_id,
                'name': primary_result.name,
                'description': primary_result.description,
                'extended_description': getattr(primary_result, 'extended_description', ''),
                'consequences': getattr(primary_result, 'consequences', []),
                'likelihood': getattr(primary_result, 'likelihood', ''),
                'impact': getattr(primary_result, 'impact', ''),
            }
            
            # Determine query type
            if primary_result.cwe_id.upper() in query.upper():
                context['query_type'] = 'direct_cwe_lookup'
            else:
                context['query_type'] = 'concept_search'
        
        return context
    
    def _sanitize_context_data(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize all context data to prevent injection attacks.
        
        This method addresses MED-007 by ensuring consistent input sanitization
        across all role-specific response paths.
        
        Args:
            context: Raw context dictionary
            
        Returns:
            Sanitized context dictionary safe for prompt generation
        """
        sanitized_context = {}
        
        for key, value in context.items():
            if key == 'cwe_data' and isinstance(value, dict):
                # Sanitize CWE data fields specifically
                sanitized_context[key] = self._sanitize_cwe_data(value)
            elif isinstance(value, str):
                # Sanitize string values
                sanitized_value = self.input_sanitizer.sanitize(value)
                if sanitized_value != value:
                    logger.warning(f"Input sanitization applied to {key} field in role-aware responder")
                sanitized_context[key] = sanitized_value
            elif isinstance(value, list):
                # Sanitize list items
                sanitized_context[key] = [
                    self.input_sanitizer.sanitize(item) if isinstance(item, str) else item
                    for item in value
                ]
            else:
                # Keep other types as-is (numbers, booleans, etc.)
                sanitized_context[key] = value
        
        return sanitized_context
    
    def _sanitize_cwe_data(self, cwe_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize CWE data fields specifically.
        
        Args:
            cwe_data: Raw CWE data dictionary
            
        Returns:
            Sanitized CWE data dictionary
        """
        sanitized = {}
        
        # Define expected CWE fields and their sanitization requirements
        string_fields = ['cwe_id', 'name', 'description', 'extended_description', 'likelihood', 'impact']
        list_fields = ['consequences']
        
        for field in string_fields:
            if field in cwe_data and isinstance(cwe_data[field], str):
                original_value = cwe_data[field]
                sanitized_value = self.input_sanitizer.sanitize(original_value)
                
                if sanitized_value != original_value:
                    logger.warning(f"Sanitization applied to CWE field '{field}' - "
                                 f"original length: {len(original_value)}, "
                                 f"sanitized length: {len(sanitized_value)}")
                
                sanitized[field] = sanitized_value
            elif field in cwe_data:
                # Keep non-string values as-is
                sanitized[field] = cwe_data[field]
        
        # Handle list fields (like consequences)
        for field in list_fields:
            if field in cwe_data and isinstance(cwe_data[field], list):
                sanitized[field] = [
                    self.input_sanitizer.sanitize(item) if isinstance(item, str) else item
                    for item in cwe_data[field]
                ]
            elif field in cwe_data:
                sanitized[field] = cwe_data[field]
        
        return sanitized
    
    def _generate_mock_response(
        self, 
        role: Optional[UserRole], 
        query: str, 
        cwe_results: List[CWEResult],
        confidence_score: float
    ) -> str:
        """
        Generate a mock response for testing purposes.
        Simulates role-specific response variations without actual LLM calls.
        
        Note: Query is sanitized to prevent injection attacks in mock mode.
        """
        # Sanitize user query to prevent injection in mock responses (addresses MED-007)
        sanitized_query = self.input_sanitizer.sanitize(query)
        if sanitized_query != query:
            logger.warning("Query sanitization applied in mock response generation")
        if not cwe_results:
            return "No relevant CWE information found for your query."
        
        primary_cwe = cwe_results[0]
        base_info = f"**{primary_cwe.cwe_id}: {primary_cwe.name}**\n\n{primary_cwe.description}"
        
        if not role:
            return f"{base_info}\n\nThis is a general overview of the weakness."
        
        # Role-specific mock responses
        role_specific_additions = {
            UserRole.PSIRT: f"\n\n**Impact Assessment**: {primary_cwe.cwe_id} poses significant security risks that require immediate attention. Recommended for high-priority advisory.\n\n**Communication Strategy**: This weakness should be communicated to stakeholders with emphasis on business impact and remediation timeline.",
            
            UserRole.DEVELOPER: f"\n\n**Code-Level Remediation**: To prevent {primary_cwe.cwe_id}, implement input validation, use parameterized queries, and follow secure coding guidelines.\n\n**Implementation Notes**: Review existing code for similar patterns and consider automated testing tools to detect instances.",
            
            UserRole.ACADEMIC: f"\n\n**Taxonomic Context**: {primary_cwe.cwe_id} belongs to the CWE classification system and relates to fundamental security principles.\n\n**Research Implications**: This weakness has been extensively studied in academic literature and represents key challenges in software security.",
            
            UserRole.BUG_BOUNTY: f"\n\n**Exploitation Notes**: {primary_cwe.cwe_id} can be identified through careful analysis of application behavior and input handling.\n\n**Testing Methodology**: Use targeted payloads and observe application responses to confirm the presence of this weakness.",
            
            UserRole.PRODUCT_MANAGER: f"\n\n**Business Impact**: {primary_cwe.cwe_id} represents a security vulnerability that could affect customer trust and regulatory compliance.\n\n**Resource Planning**: Addressing this weakness requires development time and thorough testing to ensure complete remediation."
        }
        
        addition = role_specific_additions.get(role, "")
        confidence_note = ""
        
        if confidence_score < 0.7:
            confidence_note = f"\n\n*Confidence: {int(confidence_score * 100)}% - Please refine your query for more specific information.*"
        
        return f"{base_info}{addition}{confidence_note}"
    
    async def _generate_llm_response(self, prompt: str, context: Dict[str, Any]) -> str:
        """
        Generate actual LLM response (placeholder for now).
        In a full implementation, this would call the actual LLM service.
        """
        # TODO: Integrate with actual LLM service
        # For now, return a placeholder that indicates the system is working
        logger.debug("LLM integration placeholder - returning structured response")
        
        cwe_data = context.get('cwe_data', {})
        cwe_id = cwe_data.get('cwe_id', 'Unknown')
        
        return f"[Role-based response for {cwe_id} - LLM integration pending]"
    
    def _extract_citations(self, cwe_results: List[CWEResult]) -> List[str]:
        """Extract citation information from CWE results."""
        citations = []
        for result in cwe_results:
            citations.append(f"CWE-{result.cwe_id}: {result.name}")
        return citations
    
    def _build_role_emphasis(
        self, 
        role: Optional[UserRole], 
        cwe_results: List[CWEResult]
    ) -> Dict[str, Any]:
        """Build role-specific emphasis metadata for response formatting."""
        if not role or not cwe_results:
            return {}
        
        primary_cwe = cwe_results[0]
        
        emphasis_mapping = {
            UserRole.PSIRT: {
                'focus_areas': ['impact_assessment', 'advisory_language', 'risk_evaluation'],
                'priority_sections': ['Executive Summary', 'Risk Rating', 'Communication'],
                'tone': 'professional_advisory'
            },
            UserRole.DEVELOPER: {
                'focus_areas': ['code_remediation', 'technical_implementation', 'testing'],
                'priority_sections': ['Quick Fixes', 'Code Examples', 'Testing Methods'],
                'tone': 'technical_practical'
            },
            UserRole.ACADEMIC: {
                'focus_areas': ['comprehensive_analysis', 'taxonomy_relationships', 'research_context'],
                'priority_sections': ['Conceptual Foundation', 'Research Context', 'Methodology'],
                'tone': 'scholarly_comprehensive'
            },
            UserRole.BUG_BOUNTY: {
                'focus_areas': ['exploitation_techniques', 'discovery_methods', 'poc_development'],
                'priority_sections': ['Exploitation Overview', 'Testing Techniques', 'Reporting'],
                'tone': 'practical_hands_on'
            },
            UserRole.PRODUCT_MANAGER: {
                'focus_areas': ['business_impact', 'prevention_strategy', 'resource_planning'],
                'priority_sections': ['Business Impact', 'Strategic Prevention', 'Implementation'],
                'tone': 'business_strategic'
            }
        }
        
        return emphasis_mapping.get(role, {})
    
    def get_role_context_summary(self, role: Optional[UserRole]) -> str:
        """Get a summary of what the role focuses on for user understanding."""
        if not role:
            return "Providing general cybersecurity information."
        
        role_summaries = {
            UserRole.PSIRT: "Focusing on impact assessment, advisory language, and risk evaluation for security incident response.",
            UserRole.DEVELOPER: "Emphasizing code-level solutions, technical implementation details, and secure development practices.", 
            UserRole.ACADEMIC: "Providing comprehensive analysis, research context, and taxonomic relationships for academic study.",
            UserRole.BUG_BOUNTY: "Highlighting exploitation techniques, discovery methods, and ethical vulnerability research approaches.",
            UserRole.PRODUCT_MANAGER: "Focusing on business impact, strategic prevention, and resource planning for product security."
        }
        
        return role_summaries.get(role, "Providing general cybersecurity information.")