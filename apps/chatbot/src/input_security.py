#!/usr/bin/env python3
"""
Security Input Sanitization - Story 2.1
Provides input sanitization and validation to prevent prompt injection and other security attacks.
"""

import re
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class InputSanitizer:
    """
    Sanitizes user input to prevent prompt injection attacks and other security vulnerabilities.

    Features:
    - Prompt injection pattern detection and neutralization
    - Command injection prevention
    - Malicious payload filtering
    - Length validation and normalization
    - Safe character filtering
    """

    def __init__(self):
        """Initialize the input sanitizer with security patterns."""

        # Prompt injection patterns to detect and neutralize
        self.prompt_injection_patterns = [
            # Direct command injection attempts
            r'ignore\s+(?:all\s+)?(?:previous\s+)?instructions?',
            r'your\s+new\s+instructions?\s+are',
            r'system\s*:\s*',
            r'assistant\s*:\s*',
            r'human\s*:\s*',

            # Role-playing manipulation
            r'pretend\s+(?:to\s+be|you\s+are)',
            r'act\s+(?:as|like)\s+(?:a\s+)?',
            r'roleplay\s+(?:as\s+)?',
            r'simulate\s+(?:being\s+)?',

            # System prompt exposure attempts
            r'(?:show|tell|reveal|output)\s+(?:me\s+)?(?:your\s+)?(?:system\s+)?prompt',
            r'what\s+(?:are\s+)?(?:your\s+)?(?:initial\s+)?instructions',
            r'repeat\s+(?:your\s+)?(?:original\s+)?instructions',

            # Context manipulation
            r'forget\s+(?:everything|all|previous)',
            r'override\s+(?:your\s+)?(?:previous\s+)?',
            r'instead\s+of\s+(?:answering|responding)',

            # Jailbreak attempts
            r'developer\s+mode',
            r'jailbreak\s+mode',
            r'unrestricted\s+mode',
            r'bypass\s+(?:safety|security|restrictions)',
        ]

        # Compile patterns for efficiency
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in self.prompt_injection_patterns
        ]

        # Command injection patterns - refined to avoid false positives on legitimate security content
        self.command_patterns = [
            r'[\;\|\&\$\`](?!\w)',  # Shell metacharacters (not followed by word chars)
            r'\b(?:sudo|su|chmod|rm|del|format)\s+',  # Dangerous commands with space (actual command usage)
            r'\.\.[\\/]',  # Path traversal (../ or ..\)
        ]

        self.compiled_command_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.command_patterns
        ]

    def sanitize_input(self, user_input: str) -> Dict[str, Any]:
        """
        Sanitize user input and return results with security analysis.

        Args:
            user_input: Raw user input string

        Returns:
            Dictionary containing:
            - sanitized_input: Cleaned input safe for processing
            - security_flags: List of detected security issues
            - is_safe: Boolean indicating if input is safe to process
            - original_length: Length of original input
            - sanitized_length: Length after sanitization
        """
        if not user_input or not isinstance(user_input, str):
            return {
                "sanitized_input": "",
                "security_flags": ["empty_or_invalid_input"],
                "is_safe": False,
                "original_length": 0,
                "sanitized_length": 0
            }

        logger.debug(f"Sanitizing input of length {len(user_input)}")

        original_length = len(user_input)
        security_flags = []

        # Step 1: Length validation
        if len(user_input) > 2000:  # Reasonable limit for CWE queries
            security_flags.append("excessive_length")
            user_input = user_input[:2000]
            logger.warning(f"Input truncated from {original_length} to 2000 characters")

        # Step 2: Check for prompt injection patterns
        sanitized_input = user_input
        for pattern in self.compiled_patterns:
            if pattern.search(sanitized_input):
                security_flags.append("prompt_injection_detected")
                # Neutralize by adding warning context
                sanitized_input = self._neutralize_prompt_injection(sanitized_input, pattern)

        # Step 3: Check for command injection patterns
        for pattern in self.compiled_command_patterns:
            if pattern.search(sanitized_input):
                security_flags.append("command_injection_detected")
                # Remove dangerous characters
                sanitized_input = pattern.sub('', sanitized_input)

        # Step 4: Normalize whitespace and remove control characters
        sanitized_input = self._normalize_text(sanitized_input)

        # Step 5: Final safety check
        is_safe = not any(flag in ["prompt_injection_detected", "command_injection_detected"]
                         for flag in security_flags)

        if security_flags:
            logger.warning(f"Security flags detected: {security_flags}")

        return {
            "sanitized_input": sanitized_input,
            "security_flags": security_flags,
            "is_safe": is_safe,
            "original_length": original_length,
            "sanitized_length": len(sanitized_input)
        }

    def _neutralize_prompt_injection(self, text: str, pattern: re.Pattern) -> str:
        """
        Neutralize prompt injection attempts by adding context markers.

        Args:
            text: Input text containing injection attempt
            pattern: Regex pattern that matched

        Returns:
            Text with injection attempt neutralized
        """
        # Add clear context that this is user input, not system instruction
        matches = pattern.findall(text)
        if matches:
            # Replace the injection attempt with a neutralized version
            neutralized = pattern.sub(
                lambda m: f"[USER_INPUT: {m.group()}]",
                text
            )
            return f"The following is a user query about CWE topics: {neutralized}"
        return text

    def _normalize_text(self, text: str) -> str:
        """
        Normalize text by cleaning whitespace and removing control characters.

        Args:
            text: Input text to normalize

        Returns:
            Normalized text
        """
        # Remove control characters except common whitespace
        text = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', '', text)

        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text)

        # Strip leading/trailing whitespace
        text = text.strip()

        return text

    def validate_cwe_context(self, query: str) -> bool:
        """
        Validate that the query is CWE-related and appropriate for the system.

        Args:
            query: Sanitized user query

        Returns:
            True if query appears to be legitimate CWE-related content
        """
        if not query or len(query) < 3:
            return False

        # Look for CWE-related keywords
        cwe_keywords = [
            'cwe', 'weakness', 'vulnerability', 'security', 'exploit',
            'injection', 'xss', 'csrf', 'buffer', 'overflow', 'authentication',
            'authorization', 'cryptographic', 'input', 'validation', 'sql'
        ]

        query_lower = query.lower()
        cwe_keyword_count = sum(1 for keyword in cwe_keywords if keyword in query_lower)

        # Check for direct CWE ID references
        cwe_id_pattern = re.compile(r'cwe[-\s]*\d+', re.IGNORECASE)
        has_cwe_id = bool(cwe_id_pattern.search(query))

        # Consider query valid if it has CWE keywords or direct CWE ID reference
        return cwe_keyword_count > 0 or has_cwe_id

    def generate_fallback_message(self, security_flags: List[str], user_persona: str = "Developer") -> str:
        """
        Generate appropriate fallback message for unsafe or invalid input.

        Args:
            security_flags: List of security issues detected
            user_persona: User's persona for personalized message

        Returns:
            Safe fallback message
        """
        persona_messages = {
            "PSIRT Member": "I can only assist with legitimate CWE-related security advisory inquiries.",
            "Developer": "I can only help with CWE-related development and security questions.",
            "Academic Researcher": "I can only provide information about CWE research topics.",
            "Bug Bounty Hunter": "I can only assist with legitimate CWE-related security research.",
            "Product Manager": "I can only help with CWE-related product security planning."
        }

        base_message = persona_messages.get(user_persona, persona_messages["Developer"])

        if "prompt_injection_detected" in security_flags:
            return f"{base_message} Please rephrase your question to focus on Common Weakness Enumeration topics."
        elif "excessive_length" in security_flags:
            return f"{base_message} Please provide a more concise question about CWE topics."
        else:
            return f"{base_message} Please ask about specific CWE IDs, vulnerability types, or security weaknesses."


class SecurityValidator:
    """
    Additional security validation for the CWE chatbot system.

    Provides validation beyond input sanitization including:
    - Response validation before sending to user
    - Context validation for RAG responses
    - Security logging and monitoring
    """

    def __init__(self):
        """Initialize security validator."""
        self.input_sanitizer = InputSanitizer()

    def validate_response(self, response: str) -> Dict[str, Any]:
        """
        Validate generated response for security issues before sending to user.

        Args:
            response: Generated response to validate

        Returns:
            Validation results with safety assessment
        """
        if not response or not isinstance(response, str):
            return {
                "is_safe": False,
                "issues": ["empty_or_invalid_response"],
                "validated_response": "I apologize, but I couldn't generate a proper response. Please try rephrasing your question."
            }

        issues = []

        # Check for leaked system information - refined to avoid false positives on legitimate security content
        system_leak_patterns = [
            r'system\s+prompt',
            r'(?:my|the)\s+instructions?\s*:',  # More specific to actual prompt leaks
            r'internal\s+error',
            r'traceback',
            r'exception\s+occurred',
            r'api\s+key\s*[:=]',  # Actual API key exposure, not discussion
            r'(?:my|the)\s+secret\s*[:=]',  # Actual secret exposure, not CWE content about secrets
            r'(?:my|the)\s+password\s*[:=]'  # Actual password exposure, not vulnerability discussion
        ]

        for pattern in system_leak_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                issues.append("potential_information_disclosure")
                break

        # Check response length (increased limit for comprehensive CWE responses)
        if len(response) > 8000:  # Allow longer responses for detailed CWE information
            issues.append("excessive_response_length")
            response = response[:8000] + "... [Response truncated for safety]"

        is_safe = len(issues) == 0

        return {
            "is_safe": is_safe,
            "issues": issues,
            "validated_response": response if is_safe else "I apologize, but I couldn't generate a safe response. Please try rephrasing your question about CWE topics."
        }

    def log_security_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """
        Log security events for monitoring and analysis.

        Args:
            event_type: Type of security event
            details: Event details for logging
        """
        logger.warning(f"Security Event: {event_type}", extra={
            "event_type": event_type,
            "details": details,
            "timestamp": None  # Will be added by logging framework
        })