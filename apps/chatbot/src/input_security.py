#!/usr/bin/env python3
"""
Security Input Sanitization - Story 2.1
Provides input sanitization and validation to prevent prompt injection and other security attacks.
"""

import os
import re
import logging
from typing import Dict, List, Any, Optional, Tuple

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

    def __init__(self) -> None:
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

    def sanitize_input(self, user_input: str, user_persona: str = "Developer") -> Dict[str, Any]:
        """
        Sanitize user input and return results with security analysis.

        Args:
            user_input: Raw user input string
            user_persona: User's persona for context-specific handling

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
        security_flags: List[str] = []

        # Step 1: Length validation (flag only; do not truncate)
        if len(user_input) > 2000:  # Reasonable limit for CWE queries
            security_flags.append("excessive_length")
            logger.warning(
                f"Input exceeds recommended length ({len(user_input)} > 2000); flagged but not truncated"
            )

        # Step 2: Ignore fenced code blocks when checking for risky patterns
        sanitized_input = user_input
        text_for_scanning, _code_blocks = self._strip_fenced_code_for_scan(sanitized_input)

        # Step 3: Check for prompt injection patterns (flag only; do not rewrite semantics)
        prompt_hits = any(p.search(text_for_scanning) for p in self.compiled_patterns)
        if prompt_hits:
            security_flags.append("prompt_injection_detected")

        # Step 4: Check for command injection patterns (flag only; do not mutate text)
        command_hits = any(p.search(text_for_scanning) for p in self.compiled_command_patterns)
        if command_hits:
            security_flags.append("command_injection_detected")

        # Step 5: Normalize whitespace and remove control characters (safe, non-semantic)
        sanitized_input = self._normalize_text(sanitized_input)

        # Step 6: Final safety check
        # Under strict mode, any high-risk signal blocks. Otherwise require multiple signals to block.
        # Determine strictness from environment to avoid import-time coupling
        env_val = os.getenv("ENABLE_STRICT_SANITIZATION", "true").lower().strip()
        strict_mode = env_val in ("1", "true", "yes", "on")
        high_risk_categories = set()
        if prompt_hits:
            high_risk_categories.add("prompt")
        if command_hits:
            high_risk_categories.add("command")

        if strict_mode:
            is_safe = len(high_risk_categories) == 0
        else:
            is_safe = len(high_risk_categories) < 2  # require multiple distinct categories to block

        if security_flags:
            logger.warning(f"Security flags detected: {security_flags}")

        return {
            "sanitized_input": sanitized_input,
            "security_flags": security_flags,
            "is_safe": is_safe,
            "original_length": original_length,
            "sanitized_length": len(sanitized_input)
        }

    # Removed semantic rewriting; injection patterns are flagged, not rewritten

    def _strip_fenced_code_for_scan(self, text: str) -> Tuple[str, List[str]]:
        """
        Remove fenced code blocks (``` ... ```) from text for the purpose of scanning,
        returning the text without code and the list of code blocks removed.
        """
        code_blocks: List[str] = []
        pattern = re.compile(r"```[\s\S]*?```|~~~[\s\S]*?~~~", re.MULTILINE)

        def repl(m: re.Match) -> str:
            code_blocks.append(m.group(0))
            return "\n[code block]\n"

        return pattern.sub(repl, text), code_blocks

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

    def validate_cwe_context(self, query: str, user_persona: str = "Developer") -> bool:
        """
        Validate that the query is CWE-related and appropriate for the system.

        Args:
            query: Sanitized user query
            user_persona: User's persona for context-specific validation

        Returns:
            True if query appears to be legitimate CWE-related content
        """
        if not query or len(query) < 3:
            return False

        # Look for CWE-related keywords for other personas
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

    # Removed persona-specific CVE Creator validation; single policy for all personas

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
            "Product Manager": "I can only help with CWE-related product security planning.",
            "CWE Analyzer": "I can only assist with CVE-to-CWE mapping analysis and vulnerability assessment.",
            "CVE Creator": "I can only help create CVE descriptions from vulnerability information. Please provide your existing vulnerability research, patches, or security advisories."
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

    def __init__(self) -> None:
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
                "security_issues": ["empty_or_invalid_response"],
                "confidence_score": 0.0,
                "validated_response": "I apologize, but I couldn't generate a proper response. Please try rephrasing your question."
            }

        security_issues = []
        confidence_score = 1.0

        # Check for harmful content patterns
        harmful_patterns = [
            r'(?:hack|exploit|attack).*(?:tutorial|guide|instructions)',
            r'here\'s how to.*(?:break|bypass|crack)',
            r'use this.*(?:maliciously|illegally)',
            r'steal.*(?:data|information|credentials)',
            r'actual\s+(?:malware|virus)\s+code'
        ]

        for pattern in harmful_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                security_issues.append("harmful_content_detected")
                confidence_score -= 0.3
                break

        # Check for leaked system information
        system_leak_patterns = [
            r'system\s+prompt',
            r'(?:my|the)\s+instructions?\s*:',
            r'internal\s+error',
            r'traceback',
            r'api\s+key\s*[:=]',
            r'(?:my|the)\s+secret\s*[:=]',
            r'(?:my|the)\s+password\s*[:=]'
        ]

        for pattern in system_leak_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                security_issues.append("sensitive_information")
                confidence_score -= 0.2
                break

        # Check for potential sensitive information patterns and mask instead of hard-blocking
        sensitive_patterns = [
            r'\b(?:sk-[a-zA-Z0-9]{48})\b',  # API key pattern
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?)\b',  # Credit card pattern
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # IP address pattern
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Email pattern
        ]

        def _mask_sensitive(text: str) -> str:
            # Mask IPs and emails conservatively; leave context while removing exact values
            text = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[REDACTED_IP]', text)
            text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '[REDACTED_EMAIL]', text)
            # Coarse mask for API-like tokens
            text = re.sub(r'\b(?:sk-[A-Za-z0-9]{24,})\b', '[REDACTED_TOKEN]', text)
            # Credit card-like sequences
            text = re.sub(r'\b(?:4[0-9]{12}(?:[0-9]{3})?)\b', '[REDACTED_CC]', text)
            return text

        if any(re.search(p, response) for p in sensitive_patterns):
            security_issues.append("sensitive_information_masked")
            confidence_score -= 0.05
            response = _mask_sensitive(response)

        # Check response length
        if len(response) > 8000:
            security_issues.append("excessive_response_length")
            confidence_score -= 0.1
            response = response[:8000] + "... [Response truncated for safety]"

        # Ensure confidence score is within bounds
        confidence_score = max(0.0, min(1.0, confidence_score))

        is_safe = len(security_issues) == 0

        return {
            "is_safe": is_safe,
            "security_issues": security_issues,
            "confidence_score": confidence_score,
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
