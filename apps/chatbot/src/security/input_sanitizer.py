"""
Input sanitization module for preventing prompt injection attacks.
Implements security-first practices following python-secure-coding.md guidelines.
"""

import re
import logging
import unicodedata
from typing import List, Tuple


logger = logging.getLogger(__name__)


class InputSanitizer:
    """
    Security-focused input sanitization for RAG system.
    
    Prevents prompt injection attacks and ensures safe input processing
    following NIST SSDF practices (PW.4.1).
    """
    
    # Comprehensive prompt injection patterns
    INJECTION_PATTERNS = [
        # Direct instruction manipulation
        r'ignore\s+(?:all\s+)?(?:previous\s+)?instructions',
        r'forget\s+(?:all\s+)?(?:previous\s+)?(?:instructions|everything)',
        r'disregard\s+(?:all\s+)?(?:previous\s+)?(?:instructions|programming)',
        
        # System prompt revelation attempts
        r'system\s+prompt|initial\s+prompt|original\s+prompt',
        r'tell\s+me\s+your\s+(?:initial\s+)?prompt',
        r'reveal\s+your\s+(?:configuration|system\s+prompt|(?:initial\s+)?instructions)',
        r'what\s+(?:are|is)\s+your\s+(?:instructions|system\s+prompt)',
        r'show\s+me\s+your\s+(?:configuration|instructions)',
        
        # Role manipulation
        r'act\s+as|pretend\s+to\s+be|you\s+are\s+now',
        r'roleplay\s+as|role\s*play\s+as',
        r'your\s+new\s+(?:role|instructions?)\s+(?:are|is)',
        r'you\s+are\s+(?:now\s+)?(?:a\s+)?(?:different|another)',
        
        # Context injection
        r'\\n\\n###?\s+(?:new\s+)?(?:task|instruction|role)',
        r'---\s*(?:new\s+)?(?:task|instruction|override)',
        r'<\|.*?\|>',  # Special tokens
        
        # Developer/testing pretense
        r'(?:i\s+am|i\'m)\s+(?:a\s+)?(?:developer|admin|tester)',
        r'(?:this\s+is|for)\s+(?:testing|debugging|development)',
        r'i\s+am\s+your\s+(?:developer|creator)',
        
        # Translation/encoding tricks
        r'translate\s+(?:the\s+following|this)',
        r'decode\s+(?:the\s+following|this)',
        r'base64\s+decode',
        
        # Additional common patterns
        r'forget\s+everything\s+you\s+know',
        r'disregard\s+your\s+programming',
    ]
    
    # Compile patterns for efficiency
    _compiled_patterns = [re.compile(pattern, re.IGNORECASE | re.MULTILINE) 
                         for pattern in INJECTION_PATTERNS]
    
    # Maximum input length (following security guidelines)
    MAX_INPUT_LENGTH = 1000
    
    # Suspicious character sequences
    SUSPICIOUS_CHARS = [
        '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', 
        '\x08', '\x0b', '\x0c', '\x0e', '\x0f'
    ]
    
    def __init__(self, max_length: int = MAX_INPUT_LENGTH, strict_mode: bool = True):
        """
        Initialize the input sanitizer.
        
        Args:
            max_length: Maximum allowed input length
            strict_mode: If True, reject inputs with injection patterns
        """
        self.max_length = max_length
        self.strict_mode = strict_mode
        
    def sanitize(self, user_input: str) -> str:
        """
        Sanitize user input against prompt injection and malicious content.
        
        Args:
            user_input: Raw user input string
            
        Returns:
            Sanitized input string
            
        Raises:
            ValueError: If input is potentially malicious and strict_mode is True
        """
        if not isinstance(user_input, str):
            raise TypeError("Input must be a string")
        
        # Log original input length for monitoring
        logger.debug(f"Sanitizing input of length {len(user_input)}")
        
        # 1. Unicode normalization - prevents encoding-based bypass attempts
        normalized_input = self._normalize_unicode(user_input)
        
        # 2. Length validation (after normalization, as it may change length)
        if len(normalized_input) > self.max_length:
            if self.strict_mode:
                raise ValueError(f"Input exceeds maximum length of {self.max_length}")
            normalized_input = normalized_input[:self.max_length]
        
        # 3. Remove null bytes and control characters
        cleaned_input = self._remove_control_characters(normalized_input)
        
        # 4. Check for injection patterns
        injection_detected = self._detect_injection_patterns(cleaned_input)
        
        if injection_detected:
            logger.warning(f"Potential injection attempt detected: {injection_detected}")
            if self.strict_mode:
                raise ValueError("Input contains potentially malicious content")
            # In non-strict mode, neutralize but allow
            cleaned_input = self._neutralize_injection_patterns(cleaned_input)
        
        # 5. Normalize whitespace
        cleaned_input = self._normalize_whitespace(cleaned_input)
        
        logger.debug(f"Input sanitized successfully, final length: {len(cleaned_input)}")
        return cleaned_input.strip()
    
    def is_potentially_malicious(self, user_input: str) -> Tuple[bool, List[str]]:
        """
        Check if input contains potential injection attempts without modifying it.
        
        Args:
            user_input: Input string to analyze
            
        Returns:
            Tuple of (is_malicious, list_of_detected_patterns)
        """
        if not isinstance(user_input, str):
            return False, []
        
        detected_patterns = []
        
        # Check length
        if len(user_input) > self.max_length:
            detected_patterns.append("excessive_length")
        
        # Check for control characters
        if any(char in user_input for char in self.SUSPICIOUS_CHARS):
            detected_patterns.append("control_characters")
        
        # Check injection patterns
        for i, pattern in enumerate(self._compiled_patterns):
            if pattern.search(user_input):
                detected_patterns.append(f"injection_pattern_{i}")
        
        return len(detected_patterns) > 0, detected_patterns
    
    def _normalize_unicode(self, text: str) -> str:
        """
        Normalize Unicode text to prevent encoding-based bypass attempts.
        
        Uses NFKC normalization to:
        - Decompose characters into canonical forms
        - Convert compatibility characters to canonical equivalents
        - Compose characters back into canonical form
        
        This prevents attackers from using visually similar Unicode characters
        or compatibility forms to bypass injection detection.
        
        Args:
            text: Input text to normalize
            
        Returns:
            Unicode-normalized text
        """
        try:
            # NFKC (Normalization Form Canonical Composition) is most thorough
            # It decomposes, converts compatibility chars, then recomposes
            normalized = unicodedata.normalize('NFKC', text)
            
            # Log normalization if it changed the text (potential bypass attempt)
            if normalized != text:
                logger.debug(f"Unicode normalization applied - input contained non-canonical characters")
                
                # Additional check for potential homograph attacks
                if self._detect_suspicious_unicode(text, normalized):
                    logger.warning("Potential Unicode-based bypass attempt detected")
            
            return normalized
            
        except (UnicodeError, ValueError) as e:
            logger.warning(f"Unicode normalization failed: {type(e).__name__}")
            # Return original text if normalization fails
            return text
    
    def _detect_suspicious_unicode(self, original: str, normalized: str) -> bool:
        """
        Detect suspicious Unicode usage that might indicate bypass attempts.
        
        Args:
            original: Original input text
            normalized: Normalized text
            
        Returns:
            True if suspicious Unicode patterns are detected
        """
        # Check for significant length differences (could indicate hidden chars)
        if abs(len(original) - len(normalized)) > len(original) * 0.1:  # >10% difference
            return True
            
        # Check for mixed scripts (potential homograph attack)
        scripts = set()
        for char in normalized:
            if char.isalpha():  # Only check alphabetic characters
                script = unicodedata.name(char, '').split()[0] if unicodedata.name(char, '') else 'UNKNOWN'
                scripts.add(script)
                
                # If we have more than 3 different scripts, it's suspicious
                if len(scripts) > 3:
                    return True
        
        # Check for invisible/zero-width characters that survived normalization
        invisible_chars = {
            '\u200b',  # Zero Width Space
            '\u200c',  # Zero Width Non-Joiner
            '\u200d',  # Zero Width Joiner
            '\u2060',  # Word Joiner
            '\ufeff',  # Zero Width No-Break Space (BOM)
        }
        
        if any(char in normalized for char in invisible_chars):
            return True
            
        return False
    
    def _remove_control_characters(self, text: str) -> str:
        """Remove control characters and null bytes."""
        # First handle escaped sequences in test strings
        if '\\x' in text:
            # Convert escaped sequences to actual bytes for removal
            import codecs
            try:
                text = codecs.decode(text, 'unicode_escape')
            except:
                pass  # If decoding fails, continue with original text
        
        for char in self.SUSPICIOUS_CHARS:
            text = text.replace(char, '')
        return text
    
    def _detect_injection_patterns(self, text: str) -> List[str]:
        """Detect potential injection patterns in the text."""
        detected = []
        for i, pattern in enumerate(self._compiled_patterns):
            if pattern.search(text):
                detected.append(f"pattern_{i}")
        return detected
    
    def _neutralize_injection_patterns(self, text: str) -> str:
        """
        Neutralize detected injection patterns by replacing them.
        Used in non-strict mode.
        """
        # Replace common injection keywords with neutral alternatives
        neutralized = text
        replacements = {
            'ignore': 'consider',
            'forget': 'remember', 
            'disregard': 'regard',
            'system prompt': 'user query',
            'instructions': 'guidelines',
        }
        
        for malicious, neutral in replacements.items():
            neutralized = re.sub(malicious, neutral, neutralized, flags=re.IGNORECASE)
        
        return neutralized
    
    def _normalize_whitespace(self, text: str) -> str:
        """Normalize excessive whitespace while preserving structure."""
        # First handle escaped sequences
        if '\\n' in text or '\\t' in text:
            import codecs
            try:
                text = codecs.decode(text, 'unicode_escape')
            except:
                pass
        
        # Replace multiple whitespace with single spaces
        text = re.sub(r'\s+', ' ', text)
        # Remove excessive newlines
        text = re.sub(r'\n{3,}', '\n\n', text)
        return text