#!/usr/bin/env python3
"""
Role-Based Prompt Templates
Provides specialized prompt templates based on user roles for tailored CWE responses.
"""

import logging
import html
import re
from typing import Dict, Any, Optional, Union
from ..user_context import UserPersona
from ..security.secure_logging import get_secure_logger

logger = get_secure_logger(__name__)


class RolePromptTemplates:
    """
    Generates role-specific prompt templates for LLM responses.
    Templates guide the LLM on how to structure and prioritize CWE information.
    """
    
    def __init__(self) -> None:
        """Initialize the prompt template system."""
        self._base_context = {
            "system_role": "You are a cybersecurity expert specializing in Common Weakness Enumeration (CWE) information.",
            "accuracy_requirement": "Always provide accurate, factual information directly from CWE corpus data. Never invent or hallucinate information.",
            "citation_requirement": "Always cite specific CWE sources for factual claims using the format 'According to CWE-XXX description...' or 'CWE-XXX states that...'",
            "confidence_requirement": "If you're uncertain about any information, clearly state your level of confidence and suggest sources for verification."
        }
        
        # Prompt injection patterns to detect and neutralize
        self._injection_patterns = [
            r'ignore\s+all\s+(previous\s+)?instructions',
            r'ignore\s+the\s+above',
            r'disregard\s+all\s+instructions',
            r'forget\s+everything',
            r'new\s+instructions?:',
            r'system\s*:\s*',
            r'assistant\s*:\s*',
            r'human\s*:\s*',
            r'###\s*new\s*instructions',
            r'override\s+system',
            r'reveal\s+your\s+(system\s+)?instructions',
            r'reveal\s+your\s+system\s+configuration',
            r'show\s+me\s+your\s+prompt',
            r'tell\s+me\s+about\s+(internal\s+)?architecture',
            r'javascript\s*:',
            r'data\s*:',
            r'vbscript\s*:',
            r'on\w+\s*=',  # HTML event handlers
            r'drop\s+table',
            r'union\s+select',
            r'insert\s+into',
            r'delete\s+from',
            r'update\s+\w+\s+set',
            r';\s*(rm|del|rmdir|cat|type|more|less)',
            r'\|\s*(cat|type|more|less|grep)',
            r'&&\s*(whoami|pwd|ls|dir)',
            r'\.\.[\\/]',  # Directory traversal
            r'\$\{.*\}',   # Variable injection
            r'`[^`]+`'     # Command substitution
        ]
    
    def get_role_prompt(self, role: Optional[UserPersona], context: Dict[str, Any]) -> str:
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
        role_templates: Dict[UserPersona, Union[str, callable]] = {
            UserPersona.PSIRT_MEMBER: self._get_psirt_prompt_template,
            UserPersona.DEVELOPER: self._get_developer_prompt_template,
            UserPersona.ACADEMIC_RESEARCHER: self._get_academic_prompt_template,
            UserPersona.BUG_BOUNTY_HUNTER: self._get_bug_bounty_prompt_template,
            UserPersona.PRODUCT_MANAGER: self._get_product_manager_prompt_template
        }
        
        template_func = role_templates.get(role, self._get_generic_prompt_template)
        role_specific_prompt = template_func()
        
        # Combine base context with role-specific instructions
        full_prompt = self._build_full_prompt(role_specific_prompt, context)
        
        logger.debug(f"Generated prompt template for role: {role.value if role else 'generic'}")
        return full_prompt
    
    def _sanitize_context_data(self, data: Any) -> str:
        """
        Sanitize context data to prevent prompt injection attacks.
        
        This method implements multiple layers of protection:
        1. Data structure validation and field whitelisting
        2. Content length limiting 
        3. HTML encoding to prevent markup injection
        4. Pattern-based injection attempt detection
        5. Safe string conversion with truncation
        
        Args:
            data: Context data to sanitize (typically CWE data dict)
            
        Returns:
            Sanitized string safe for inclusion in LLM prompts
            
        Security Features:
            - Prevents prompt injection via malicious instructions
            - Limits data length to prevent prompt overflow
            - HTML encodes to prevent markup injection
            - Validates CWE ID format to prevent spoofing
            - Logs security events for monitoring
        """
        try:
            if isinstance(data, dict):
                # Whitelist approach - only include expected, validated fields
                safe_fields = {}
                
                # Validate and sanitize CWE ID
                if 'cwe_id' in data:
                    cwe_id = str(data['cwe_id']).strip()
                    # Strict CWE ID format validation - must be exactly CWE-<digits>
                    if re.match(r'^CWE-\d{1,6}$', cwe_id) and len(cwe_id) <= 20:
                        safe_fields['cwe_id'] = cwe_id
                    else:
                        logger.warning(f"Invalid CWE ID format rejected: {cwe_id[:50]}...")
                        safe_fields['cwe_id'] = "BLOCKED-INVALID-ID"
                else:
                    safe_fields['cwe_id'] = "UNKNOWN-CWE-ID"
                
                # Sanitize name field
                if 'name' in data:
                    name = str(data['name']).strip()[:100]  # Limit length
                    name = self._detect_and_neutralize_injection(name)
                    safe_fields['name'] = html.escape(name)  # HTML encode
                
                # Sanitize description field
                if 'description' in data:
                    desc = str(data['description']).strip()[:500]  # Limit length
                    desc = self._detect_and_neutralize_injection(desc)
                    safe_fields['description'] = html.escape(desc)  # HTML encode
                
                # Format as structured, safe output
                return self._format_safe_cwe_data(safe_fields)
            
            else:
                # For non-dict data, apply general sanitization
                sanitized = str(data).strip()[:200]  # Limit length
                sanitized = self._detect_and_neutralize_injection(sanitized)
                return html.escape(sanitized)  # HTML encode
                
        except Exception as e:
            logger.error(f"Error sanitizing context data: {e}")
            return "[CWE data sanitization failed - content not available]"
    
    def _detect_and_neutralize_injection(self, text: str) -> str:
        """
        Detect and neutralize prompt injection attempts.
        
        Args:
            text: Text to scan for injection patterns
            
        Returns:
            Text with injection attempts neutralized
        """
        original_text = text
        text_lower = text.lower()
        
        # Check for injection patterns
        for pattern in self._injection_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                logger.warning(f"Prompt injection attempt detected and blocked: {pattern}")
                # Replace with safe placeholder
                text = re.sub(pattern, '[BLOCKED-CONTENT]', text, flags=re.IGNORECASE)
        
        # Additional safety measures
        # Remove potential instruction separators
        dangerous_chars = ['###', '---', '```', '<|', '|>', '\n\n###', '\n---']
        for char_seq in dangerous_chars:
            if char_seq in text:
                text = text.replace(char_seq, ' ')
                logger.debug(f"Removed potential instruction separator: {char_seq}")
        
        # Log if modifications were made
        if text != original_text:
            logger.info(f"Content sanitization applied - original length: {len(original_text)}, sanitized length: {len(text)}")
        
        return text
    
    def _format_safe_cwe_data(self, safe_data: Dict[str, str]) -> str:
        """
        Format sanitized CWE data in a structured, safe manner.
        
        Args:
            safe_data: Dictionary of sanitized CWE fields
            
        Returns:
            Formatted string safe for LLM prompt inclusion
        """
        formatted_parts = []
        
        if safe_data.get('cwe_id'):
            formatted_parts.append(f"CWE Identifier: {safe_data['cwe_id']}")
        
        if safe_data.get('name'):
            formatted_parts.append(f"Weakness Name: {safe_data['name']}")
            
        if safe_data.get('description'):
            formatted_parts.append(f"Description: {safe_data['description']}")
        
        if not formatted_parts:
            return "[No valid CWE data available]"
        
        return "\n".join(formatted_parts)
    
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
        
        # Add context-specific instructions with secure sanitization
        if context.get('cwe_data'):
            prompt_parts.append("Use the following CWE information to answer the user's question:")
            # SECURITY FIX: Apply comprehensive sanitization to prevent prompt injection
            prompt_parts.append(self._sanitize_context_data(context['cwe_data']))
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
