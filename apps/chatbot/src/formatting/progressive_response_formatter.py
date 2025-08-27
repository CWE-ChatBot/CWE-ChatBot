"""
Progressive Response Formatter for Story 2.2 - Progressive Disclosure UI

This module implements progressive disclosure functionality, allowing users to
request more detailed information through interactive UI elements.

Key Features:
- Summary response generation with "tell me more" options
- Interactive Chainlit action buttons
- Detailed response formatting on demand
- Context preservation for progressive disclosure
"""

import logging
import re
from typing import Dict, List, Any, Optional, Tuple
import chainlit as cl

from ..retrieval.base_retriever import CWEResult
from ..processing.contextual_responder import ContextualResponse
from ..security.csrf_protection import get_csrf_protection
from ..security.secure_logging import get_secure_logger

logger = get_secure_logger(__name__)


class ProgressiveResponseFormatter:
    """
    Handles progressive disclosure of CWE information with interactive UI elements.
    
    This class creates responses that initially show concise summaries with
    options for users to request more detailed information through interactive
    buttons or follow-up questions.
    """
    
    # Response format configurations
    SUMMARY_MAX_LENGTH = 300  # Characters for summary descriptions
    DETAILED_MAX_LENGTH = 1500  # Characters for detailed descriptions
    
    # Action button configurations
    ACTION_BUTTON_CONFIGS = {
        'tell_more': {
            'name': 'tell_more',
            'label': '📖 Tell me more',
            'description': 'Get detailed information about this CWE',
            'icon': '📖'
        },
        'show_consequences': {
            'name': 'show_consequences', 
            'label': '⚠️ Show consequences',
            'description': 'View potential impacts and consequences',
            'icon': '⚠️'
        },
        'show_related': {
            'name': 'show_related',
            'label': '🔗 Show related CWEs',
            'description': 'Find similar and related vulnerabilities',
            'icon': '🔗'
        },
        'show_prevention': {
            'name': 'show_prevention',
            'label': '🛡️ Show prevention',
            'description': 'Learn how to prevent this vulnerability',
            'icon': '🛡️'
        }
    }
    
    def __init__(self, enable_csrf: bool = True):
        """Initialize progressive response formatter.
        
        Args:
            enable_csrf: Whether to enable CSRF protection for action buttons
        """
        self.response_count = 0
        self.enable_csrf = enable_csrf
        self.csrf_protection = get_csrf_protection() if enable_csrf else None
        logger.info(f"ProgressiveResponseFormatter initialized (CSRF: {enable_csrf})")
    
    def format_summary_response(
        self, 
        cwe_data: CWEResult, 
        include_actions: bool = True,
        session_id: Optional[str] = None
    ) -> Tuple[str, List[cl.Action]]:
        """
        Format concise summary response with 'more details' option.
        
        Args:
            cwe_data: CWE result data to format
            include_actions: Whether to include interactive action buttons
            session_id: Current session ID for CSRF protection
            
        Returns:
            Tuple of (summary_content, action_buttons)
        """
        try:
            self.response_count += 1
            
            # Create summary content
            summary_parts = []
            
            # Header with CWE ID and name
            summary_parts.append(f"## {cwe_data.cwe_id}: {cwe_data.name}\n")
            
            # Summary description (truncated if needed)
            if cwe_data.description:
                summary_desc = self._truncate_text(cwe_data.description, self.SUMMARY_MAX_LENGTH)
                summary_parts.append(f"{summary_desc}\n")
            
            # Basic metadata if available
            metadata_parts = []
            if cwe_data.abstraction:
                metadata_parts.append(f"**Abstraction**: {cwe_data.abstraction}")
            if cwe_data.status:
                metadata_parts.append(f"**Status**: {cwe_data.status}")
            
            if metadata_parts:
                summary_parts.append(" • ".join(metadata_parts) + "\n")
            
            # Add progressive disclosure hint
            summary_parts.append("*Use the buttons below or ask follow-up questions for more details.*")
            
            summary_content = "\n".join(summary_parts)
            
            # Create action buttons if requested
            actions = []
            if include_actions:
                actions = self._create_action_buttons(cwe_data, session_id)
            
            logger.debug(f"Created summary response for {cwe_data.cwe_id}")
            return summary_content, actions
            
        except Exception as e:
            logger.log_exception("Summary response formatting failed", e)
            fallback_content = f"**{cwe_data.cwe_id}**: {cwe_data.name}\n\nUnable to format detailed response."
            return fallback_content, []
    
    def format_detailed_response(
        self, 
        cwe_data: CWEResult, 
        detail_type: str = "comprehensive"
    ) -> str:
        """
        Format comprehensive detailed response.
        
        Args:
            cwe_data: CWE result data to format
            detail_type: Type of details to include ('comprehensive', 'consequences', 'related', 'prevention')
            
        Returns:
            Detailed response content
        """
        try:
            content_parts = []
            
            # Header
            content_parts.append(f"## {cwe_data.cwe_id}: {cwe_data.name}\n")
            
            if detail_type == "comprehensive":
                # Comprehensive detailed response
                content_parts.extend(self._format_comprehensive_details(cwe_data))
            
            elif detail_type == "consequences":
                # Consequences-focused response
                content_parts.extend(self._format_consequences_details(cwe_data))
            
            elif detail_type == "related":
                # Related CWEs response
                content_parts.extend(self._format_related_details(cwe_data))
            
            elif detail_type == "prevention":
                # Prevention-focused response
                content_parts.extend(self._format_prevention_details(cwe_data))
            
            else:
                # Default to comprehensive
                content_parts.extend(self._format_comprehensive_details(cwe_data))
            
            detailed_content = "\n".join(content_parts)
            
            logger.debug(f"Created detailed response ({detail_type}) for {cwe_data.cwe_id}")
            return detailed_content
            
        except Exception as e:
            logger.log_exception("Detailed response formatting failed", e)
            return f"**{cwe_data.cwe_id}**: {cwe_data.name}\n\nUnable to format detailed response."
    
    def format_contextual_summary(
        self,
        contextual_response: ContextualResponse,
        original_cwe_data: Optional[CWEResult] = None,
        session_id: Optional[str] = None
    ) -> Tuple[str, List[cl.Action]]:
        """
        Format summary for contextual responses (follow-up questions).
        
        Args:
            contextual_response: Generated contextual response
            original_cwe_data: Original CWE data for action creation
            session_id: Current session ID for CSRF protection
            
        Returns:
            Tuple of (content, actions)
        """
        try:
            # Use the contextual response content as-is (it's already formatted)
            content = contextual_response.content
            
            # Create relevant actions based on response type
            actions = []
            if contextual_response.context_used and original_cwe_data:
                actions = self._create_contextual_actions(contextual_response, original_cwe_data, session_id)
            
            return content, actions
            
        except Exception as e:
            logger.log_exception("Contextual summary formatting failed", e)
            return contextual_response.content, []
    
    def _create_action_buttons(self, cwe_data: CWEResult, session_id: Optional[str] = None) -> List[cl.Action]:
        """Create interactive action buttons for progressive disclosure.
        
        Args:
            cwe_data: CWE result data for button creation
            session_id: Current user session ID for CSRF protection
            
        Returns:
            List of Chainlit Action objects with CSRF protection
        """
        actions = []
        
        try:
            # Always include "Tell me more" action
            tell_more_value = self._create_secure_action_value(
                'tell_more', cwe_data.cwe_id, session_id
            )
            actions.append(cl.Action(
                name=self.ACTION_BUTTON_CONFIGS['tell_more']['name'],
                value=tell_more_value,
                description=self.ACTION_BUTTON_CONFIGS['tell_more']['description'],
                label=self.ACTION_BUTTON_CONFIGS['tell_more']['label']
            ))
            
            # Include consequences action if we have consequence data
            if cwe_data.consequences:
                consequences_value = self._create_secure_action_value(
                    'show_consequences', cwe_data.cwe_id, session_id
                )
                actions.append(cl.Action(
                    name=self.ACTION_BUTTON_CONFIGS['show_consequences']['name'],
                    value=consequences_value,
                    description=self.ACTION_BUTTON_CONFIGS['show_consequences']['description'],
                    label=self.ACTION_BUTTON_CONFIGS['show_consequences']['label']
                ))
            
            # Include related action if we have relationship data
            if cwe_data.relationships:
                related_value = self._create_secure_action_value(
                    'show_related', cwe_data.cwe_id, session_id
                )
                actions.append(cl.Action(
                    name=self.ACTION_BUTTON_CONFIGS['show_related']['name'],
                    value=related_value,
                    description=self.ACTION_BUTTON_CONFIGS['show_related']['description'],
                    label=self.ACTION_BUTTON_CONFIGS['show_related']['label']
                ))
            
            # Always include prevention action
            prevention_value = self._create_secure_action_value(
                'show_prevention', cwe_data.cwe_id, session_id
            )
            actions.append(cl.Action(
                name=self.ACTION_BUTTON_CONFIGS['show_prevention']['name'],
                value=prevention_value,
                description=self.ACTION_BUTTON_CONFIGS['show_prevention']['description'],
                label=self.ACTION_BUTTON_CONFIGS['show_prevention']['label']
            ))
            
            logger.debug(f"Created {len(actions)} action buttons for {cwe_data.cwe_id}")
            return actions
            
        except Exception as e:
            logger.log_exception("Action button creation failed", e)
            return []
    
    def _create_contextual_actions(
        self,
        contextual_response: ContextualResponse,
        cwe_data: CWEResult,
        session_id: Optional[str] = None
    ) -> List[cl.Action]:
        """Create actions relevant to the contextual response."""
        actions = []
        
        try:
            # Create actions based on what hasn't been shown yet
            intent = contextual_response.metadata.get('intent', '')
            
            if intent != 'tell_more':
                tell_more_value = self._create_secure_action_value(
                    'tell_more', cwe_data.cwe_id, session_id
                )
                actions.append(cl.Action(
                    name='tell_more',
                    value=tell_more_value,
                    description="Get comprehensive details",
                    label="📖 Tell me more"
                ))
            
            if intent != 'consequences' and cwe_data.consequences:
                consequences_value = self._create_secure_action_value(
                    'show_consequences', cwe_data.cwe_id, session_id
                )
                actions.append(cl.Action(
                    name='show_consequences',
                    value=consequences_value,
                    description="View consequences",
                    label="⚠️ Show consequences"
                ))
            
            if intent != 'related' and cwe_data.relationships:
                related_value = self._create_secure_action_value(
                    'show_related', cwe_data.cwe_id, session_id
                )
                actions.append(cl.Action(
                    name='show_related',
                    value=related_value,
                    description="Find related CWEs",
                    label="🔗 Show related"
                ))
            
            return actions[:3]  # Limit to 3 actions to avoid UI clutter
            
        except Exception as e:
            logger.log_exception("Contextual action creation failed", e)
            return []
    
    def _create_secure_action_value(
        self, 
        action_type: str, 
        cwe_id: str, 
        session_id: Optional[str] = None
    ) -> str:
        """Create a secure action value with CSRF protection.
        
        Args:
            action_type: Type of action (e.g., 'tell_more')
            cwe_id: CWE identifier
            session_id: Current session ID for CSRF token generation
            
        Returns:
            Secure action value string with format: action_type:cwe_id:csrf_token
        """
        if self.enable_csrf and self.csrf_protection and session_id:
            try:
                csrf_token = self.csrf_protection.generate_token(
                    session_id, action_type, cwe_id
                )
                return f"{action_type}:{cwe_id}:{csrf_token}"
            except Exception as e:
                logger.log_exception("CSRF token generation failed", e)
                # Fallback to basic format without CSRF protection
                return f"{action_type}:{cwe_id}"
        else:
            # No CSRF protection enabled or no session
            return f"{action_type}:{cwe_id}"
    
    def _format_comprehensive_details(self, cwe_data: CWEResult) -> List[str]:
        """Format comprehensive detailed information."""
        details = []
        
        # Extended description
        if cwe_data.extended_description:
            details.append("### Detailed Description")
            details.append(cwe_data.extended_description)
            details.append("")
        elif cwe_data.description:
            details.append("### Description")
            details.append(cwe_data.description)
            details.append("")
        
        # Consequences
        if cwe_data.consequences:
            details.append("### Potential Consequences")
            for i, consequence in enumerate(cwe_data.consequences[:5], 1):
                scope = consequence.get('scope', 'System')
                impact = consequence.get('impact', 'Unknown impact')
                details.append(f"{i}. **{scope}**: {impact}")
            details.append("")
        
        # Relationships
        if cwe_data.relationships:
            details.append("### Related Vulnerabilities")
            for rel_type, rel_cwes in cwe_data.relationships.items():
                if rel_cwes:
                    cwe_list = ', '.join(rel_cwes[:5])  # Limit to 5 per type
                    details.append(f"- **{rel_type}**: {cwe_list}")
            details.append("")
        
        # Technical details
        tech_details = []
        if cwe_data.abstraction:
            tech_details.append(f"**Abstraction Level**: {cwe_data.abstraction}")
        if cwe_data.status:
            tech_details.append(f"**Status**: {cwe_data.status}")
        
        if tech_details:
            details.append("### Technical Information")
            details.extend(tech_details)
        
        return details
    
    def _format_consequences_details(self, cwe_data: CWEResult) -> List[str]:
        """Format consequences-focused details."""
        details = []
        
        details.append("### Potential Consequences")
        
        if cwe_data.consequences:
            for consequence in cwe_data.consequences:
                scope = consequence.get('scope', 'System')
                impact = consequence.get('impact', 'Unknown impact')
                details.append(f"**{scope}**")
                details.append(f"- {impact}")
                details.append("")
        else:
            details.append("Specific consequences depend on the implementation context.")
            details.append("Common potential impacts include:")
            details.append("- **Confidentiality**: Unauthorized information disclosure")
            details.append("- **Integrity**: Unauthorized modification of data or behavior")
            details.append("- **Availability**: System disruption or denial of service")
        
        return details
    
    def _format_related_details(self, cwe_data: CWEResult) -> List[str]:
        """Format related CWEs details."""
        details = []
        
        details.append("### Related Vulnerabilities")
        
        if cwe_data.relationships:
            for rel_type, rel_cwes in cwe_data.relationships.items():
                if rel_cwes:
                    details.append(f"**{rel_type}**")
                    for cwe_id in rel_cwes[:5]:
                        details.append(f"- {cwe_id}")
                    details.append("")
        else:
            details.append("No specific relationships documented for this CWE.")
            details.append("You can ask about similar CWEs to find related vulnerabilities.")
        
        return details
    
    def _format_prevention_details(self, cwe_data: CWEResult) -> List[str]:
        """Format prevention-focused details."""
        details = []
        
        details.append("### Prevention Strategies")
        details.append("**General Mitigation Approaches:**")
        details.append("- Implement comprehensive input validation and sanitization")
        details.append("- Apply appropriate security controls and access restrictions")
        details.append("- Conduct thorough security-focused code reviews")
        details.append("- Implement security testing (SAST, DAST, penetration testing)")
        details.append("- Design secure system architecture with defense-in-depth")
        details.append("")
        
        details.append("**Best Practices:**")
        details.append("- Follow secure coding standards for your programming language")
        details.append("- Use established security libraries and frameworks")
        details.append("- Implement proper error handling without information leakage")
        details.append("- Apply the principle of least privilege")
        details.append("- Keep dependencies and security patches up to date")
        
        return details
    
    def _truncate_text(self, text: str, max_length: int) -> str:
        """Truncate text to specified length with ellipsis."""
        if len(text) <= max_length:
            return text
        
        # Find the last complete word before the limit
        truncated = text[:max_length]
        last_space = truncated.rfind(' ')
        
        if last_space > max_length * 0.8:  # If we found a space reasonably close
            return text[:last_space] + "..."
        else:
            return truncated + "..."
    
    def get_action_metadata(self, action_value: str, session_id: Optional[str] = None) -> Dict[str, any]:
        """Parse action value to get metadata with enhanced validation and CSRF checking.
        
        Args:
            action_value: Action value string to parse
            session_id: Current session ID for CSRF validation
            
        Returns:
            Dictionary with action metadata and CSRF validation status
        """
        try:
            # Enhanced input validation
            if not action_value or not isinstance(action_value, str):
                raise ValueError("Invalid action value: must be a non-empty string")
            
            if len(action_value) > 500:  # Increased limit to accommodate CSRF tokens
                raise ValueError("Action value too long: maximum 500 characters")
            
            # Parse action value format: action_type:cwe_id:csrf_token
            parts = action_value.split(':', 2)
            
            if len(parts) < 2:
                return {
                    'action_type': parts[0] if parts else 'unknown',
                    'cwe_id': None,
                    'csrf_token': None,
                    'csrf_valid': False,
                    'csrf_reason': 'No CSRF token provided'
                }
            
            action_type = parts[0]
            cwe_id = parts[1]
            csrf_token = parts[2] if len(parts) > 2 else None
            
            # Validate CWE ID format if present
            if cwe_id and not re.match(r'^CWE-\d+$', cwe_id):
                raise ValueError(f"Invalid CWE ID format: {cwe_id}")
            
            # Validate CSRF token if CSRF protection is enabled
            csrf_valid = False
            csrf_reason = "CSRF protection disabled"
            
            if self.enable_csrf and self.csrf_protection and csrf_token and session_id:
                csrf_valid, csrf_reason = self.csrf_protection.validate_token(
                    csrf_token, session_id, action_type, cwe_id
                )
            elif self.enable_csrf:
                csrf_reason = "Missing CSRF token or session ID"
            
            return {
                'action_type': action_type,
                'cwe_id': cwe_id,
                'csrf_token': csrf_token,
                'csrf_valid': csrf_valid,
                'csrf_reason': csrf_reason
            }
            
        except Exception as e:
            logger.log_exception("Action metadata parsing failed", e)
            return {
                'action_type': 'unknown',
                'cwe_id': None,
                'csrf_token': None,
                'csrf_valid': False,
                'csrf_reason': f'Parsing error: {type(e).__name__}'
            }