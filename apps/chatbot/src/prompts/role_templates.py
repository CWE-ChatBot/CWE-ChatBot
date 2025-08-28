#!/usr/bin/env python3
"""
Role-Based Prompt Templates
Provides specialized prompt templates based on user roles for tailored CWE responses.
"""

import logging
from typing import Dict, Any, Optional
from src.user.role_manager import UserRole
from src.security.secure_logging import get_secure_logger

logger = get_secure_logger(__name__)


class RolePromptTemplates:
    """
    Generates role-specific prompt templates for LLM responses.
    Templates guide the LLM on how to structure and prioritize CWE information.
    """
    
    def __init__(self):
        """Initialize the prompt template system."""
        self._base_context = {
            "system_role": "You are a cybersecurity expert specializing in Common Weakness Enumeration (CWE) information.",
            "accuracy_requirement": "Always provide accurate, factual information directly from CWE corpus data. Never invent or hallucinate information.",
            "citation_requirement": "Always cite specific CWE sources for factual claims using the format 'According to CWE-XXX description...' or 'CWE-XXX states that...'",
            "confidence_requirement": "If you're uncertain about any information, clearly state your level of confidence and suggest sources for verification."
        }
    
    def get_role_prompt(self, role: Optional[UserRole], context: Dict[str, Any]) -> str:
        """
        Generate a role-specific prompt template.
        
        Args:
            role: User's selected role (if any)
            context: Additional context for the prompt (CWE data, query type, etc.)
            
        Returns:
            Formatted prompt string for the LLM
        """
        if not role:
            return self._get_generic_prompt_template()
        
        # Get role-specific template
        role_templates = {
            UserRole.PSIRT: self._get_psirt_prompt_template,
            UserRole.DEVELOPER: self._get_developer_prompt_template,
            UserRole.ACADEMIC: self._get_academic_prompt_template,
            UserRole.BUG_BOUNTY: self._get_bug_bounty_prompt_template,
            UserRole.PRODUCT_MANAGER: self._get_product_manager_prompt_template
        }
        
        template_func = role_templates.get(role, self._get_generic_prompt_template)
        role_specific_prompt = template_func()
        
        # Combine base context with role-specific instructions
        full_prompt = self._build_full_prompt(role_specific_prompt, context)
        
        logger.debug(f"Generated prompt template for role: {role.value if role else 'generic'}")
        return full_prompt
    
    def _build_full_prompt(self, role_prompt: str, context: Dict[str, Any]) -> str:
        """
        Build the complete prompt by combining base context, role instructions, and query context.
        
        Args:
            role_prompt: Role-specific prompt template
            context: Query and CWE context information
            
        Returns:
            Complete formatted prompt
        """
        prompt_parts = [
            # System role and accuracy requirements
            self._base_context["system_role"],
            self._base_context["accuracy_requirement"],
            self._base_context["citation_requirement"],
            self._base_context["confidence_requirement"],
            "",
            # Role-specific instructions
            role_prompt,
            "",
        ]
        
        # Add context-specific instructions
        if context.get('cwe_data'):
            prompt_parts.append("Use the following CWE information to answer the user's question:")
            prompt_parts.append(str(context['cwe_data']))
            prompt_parts.append("")
        
        if context.get('query_type') == 'direct_cwe_lookup':
            prompt_parts.append("The user is asking about a specific CWE. Provide comprehensive information tailored to their role.")
        elif context.get('query_type') == 'concept_search':
            prompt_parts.append("The user is asking about a security concept. Explain it and identify relevant CWEs.")
        
        prompt_parts.append("")
        prompt_parts.append("Respond in a clear, professional manner appropriate for the user's role.")
        
        return "\n".join(prompt_parts)
    
    def _get_generic_prompt_template(self) -> str:
        """Generic prompt template for users without a selected role."""
        return """As a general cybersecurity assistant, provide balanced information about CWEs that covers:

• Technical overview and description
• Common impact and consequences  
• Basic prevention and mitigation strategies
• Related CWEs and security concepts

Structure your response for a general technical audience."""
    
    def _get_psirt_prompt_template(self) -> str:
        """PSIRT-specific prompt template focusing on impact assessment and advisory language."""
        return """As a PSIRT (Product Security Incident Response Team) specialist, tailor your CWE responses to focus on:

PRIORITY FOCUS AREAS:
• **Impact Assessment**: Clearly describe the business and technical impact, including CVSS implications
• **Advisory Language**: Use precise, professional language suitable for security advisories and customer communications
• **Risk Evaluation**: Provide clear risk ratings and severity assessments
• **Incident Response**: Include detection methods, indicators, and response considerations
• **Communication Strategy**: Frame information for both technical teams and management stakeholders

RESPONSE STRUCTURE:
1. Executive Summary (suitable for management)
2. Technical Impact Assessment  
3. Risk Rating and Severity Analysis
4. Detection and Monitoring Guidance
5. Communication Templates for advisories

Use authoritative, professional tone suitable for official security communications."""
    
    def _get_developer_prompt_template(self) -> str:
        """Developer-specific prompt template emphasizing code-level solutions."""
        return """As a software development security specialist, tailor your CWE responses to focus on:

PRIORITY FOCUS AREAS:
• **Code-Level Remediation**: Provide specific, actionable code fixes and secure coding patterns
• **Technical Implementation**: Focus on concrete technical solutions and implementation details  
• **Secure Development Practices**: Emphasize preventive coding techniques and security by design
• **Testing and Validation**: Include guidance on testing for and detecting these weaknesses
• **Framework-Specific Guidance**: When applicable, provide language/framework-specific examples

RESPONSE STRUCTURE:
1. Quick Fix Summary (immediate actionable steps)
2. Detailed Technical Explanation
3. Secure Code Examples (when possible)
4. Testing and Detection Methods
5. Prevention in Development Lifecycle

Use technical language appropriate for software engineers and include practical code examples where relevant."""
    
    def _get_academic_prompt_template(self) -> str:
        """Academic researcher-specific prompt template for comprehensive analysis."""
        return """As an academic cybersecurity researcher, tailor your CWE responses to focus on:

PRIORITY FOCUS AREAS:
• **Comprehensive Technical Analysis**: Provide deep technical understanding and theoretical foundations
• **CWE Taxonomy Relationships**: Explain how this CWE fits into the broader weakness taxonomy
• **Research Context**: Include historical evolution, research trends, and academic perspectives
• **Methodological Insights**: Discuss research approaches for studying and analyzing these weaknesses
• **Interdisciplinary Connections**: Connect to related fields like software engineering, systems security, etc.

RESPONSE STRUCTURE:
1. Conceptual Foundation and Definition
2. Taxonomic Classification and Relationships
3. Technical Deep Dive and Analysis
4. Research Context and Literature
5. Methodological Considerations
6. Future Research Directions

Use scholarly tone with comprehensive explanations suitable for academic research and publication."""
    
    def _get_bug_bounty_prompt_template(self) -> str:
        """Bug bounty hunter-specific prompt template focusing on exploitation and discovery."""
        return """As a bug bounty and vulnerability research specialist, tailor your CWE responses to focus on:

PRIORITY FOCUS AREAS:
• **Exploitation Techniques**: Describe how these weaknesses can be identified and exploited
• **Discovery Methods**: Provide guidance on finding instances of these weaknesses in applications
• **Proof-of-Concept Development**: Include considerations for developing effective PoCs
• **Reporting Best Practices**: Guide on how to document and report findings effectively
• **Tool and Methodology Recommendations**: Suggest relevant tools and testing approaches

RESPONSE STRUCTURE:
1. Exploitation Overview and Attack Vectors
2. Discovery and Reconnaissance Methods  
3. Testing Techniques and Tools
4. Proof-of-Concept Considerations
5. Reporting and Documentation Guidelines
6. Common Variations and Edge Cases

Use practical, hands-on language focused on actionable testing and exploitation techniques while maintaining ethical boundaries."""
    
    def _get_product_manager_prompt_template(self) -> str:
        """Product manager-specific prompt template focusing on business impact and strategy."""
        return """As a product management security specialist, tailor your CWE responses to focus on:

PRIORITY FOCUS AREAS:
• **Business Impact Analysis**: Quantify the potential business consequences and customer impact
• **Prevention Strategy**: Provide strategic approaches for preventing these weaknesses at scale
• **Resource Planning**: Guide resource allocation decisions for remediation and prevention
• **Trend Analysis**: Include industry trends, prevalence data, and competitive considerations
• **Risk-Business Balance**: Help balance security needs with product delivery timelines

RESPONSE STRUCTURE:
1. Business Impact Summary
2. Cost-Benefit Analysis for Mitigation
3. Strategic Prevention Approaches
4. Resource Requirements and Planning
5. Industry Trends and Benchmarking
6. Implementation Roadmap Considerations

Use business-focused language that translates technical concepts into strategic and operational decisions."""
    
    def get_confidence_guidance_prompt(self, confidence_score: float) -> str:
        """
        Generate additional prompt guidance based on confidence score.
        
        Args:
            confidence_score: Confidence score from 0.0 to 1.0
            
        Returns:
            Additional prompt instructions for handling confidence levels
        """
        if confidence_score < 0.3:
            return """
LOW CONFIDENCE DETECTED: The retrieved information may not be highly relevant to the query.
- Clearly state that your confidence is low
- Explain what information you're uncertain about
- Suggest ways the user can refine their query for better results
- Provide general guidance while being explicit about limitations
"""
        elif confidence_score < 0.7:
            return """
MODERATE CONFIDENCE: The retrieved information is somewhat relevant but may not be complete.
- Acknowledge any uncertainty in your response
- Provide available information while noting limitations
- Suggest additional resources or refinements if helpful
"""
        else:
            return """
HIGH CONFIDENCE: The retrieved information is highly relevant to the query.
- Provide comprehensive information based on the retrieved data
- Maintain citation practices for all factual claims
"""
    
    def get_citation_instructions(self) -> str:
        """Get standard citation instructions for all responses."""
        return """
CITATION REQUIREMENTS:
- For direct CWE information: "According to CWE-XXX..."
- For derived insights: "Based on CWE data, this suggests..."  
- For uncertainty: "The available CWE information doesn't clearly specify..."
- Always distinguish between direct quotes and analytical insights
"""