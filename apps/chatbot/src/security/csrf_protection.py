"""
CSRF Protection for CWE ChatBot Action Buttons

This module provides Cross-Site Request Forgery (CSRF) protection for 
interactive action buttons in the Chainlit interface.

Key Features:
- Secure CSRF token generation and validation
- Session-based token management
- Time-limited token expiration
- Thread-safe operations
"""

import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from typing import Dict, Optional, Tuple
from .secure_logging import get_secure_logger

logger = get_secure_logger(__name__)


class CSRFProtection:
    """
    CSRF protection manager for action button security.
    
    Provides token generation, validation, and session management
    to prevent Cross-Site Request Forgery attacks on action buttons.
    """
    
    def __init__(self, secret_key: Optional[str] = None, token_lifetime: int = 3600):
        """
        Initialize CSRF protection.
        
        Args:
            secret_key: Secret key for token signing (auto-generated if None)
            token_lifetime: Token lifetime in seconds (default: 1 hour)
        """
        self.secret_key = secret_key or secrets.token_hex(32)
        self.token_lifetime = token_lifetime
        self._tokens: Dict[str, Dict[str, any]] = {}
        self._lock = threading.RLock()
        
        logger.info("CSRF protection initialized")
    
    def generate_token(self, session_id: str, action_type: str, cwe_id: str) -> str:
        """
        Generate a secure CSRF token for an action button.
        
        Args:
            session_id: User session identifier
            action_type: Type of action (e.g., 'tell_more', 'show_consequences')
            cwe_id: CWE identifier associated with the action
            
        Returns:
            Base64-encoded CSRF token
        """
        try:
            with self._lock:
                # Clean up expired tokens first
                self._cleanup_expired_tokens()
                
                # Generate token data
                timestamp = int(time.time())
                nonce = secrets.token_hex(16)
                
                # Create token payload
                payload = {
                    'session_id': session_id,
                    'action_type': action_type,
                    'cwe_id': cwe_id,
                    'timestamp': timestamp,
                    'nonce': nonce
                }
                
                # Sign the payload
                payload_json = json.dumps(payload, sort_keys=True)
                signature = hmac.new(
                    self.secret_key.encode(),
                    payload_json.encode(),
                    hashlib.sha256
                ).hexdigest()
                
                # Create final token
                token_data = {
                    'payload': payload,
                    'signature': signature
                }
                
                # Encode as base64 for URL safety
                import base64
                token_json = json.dumps(token_data)
                token = base64.urlsafe_b64encode(token_json.encode()).decode()
                
                # Store token for validation
                self._tokens[token] = {
                    'session_id': session_id,
                    'action_type': action_type,
                    'cwe_id': cwe_id,
                    'timestamp': timestamp,
                    'used': False
                }
                
                logger.debug(f"Generated CSRF token for {session_id}:{action_type}:{cwe_id}")
                return token
                
        except Exception as e:
            logger.log_exception("CSRF token generation failed", e)
            # Return a safe fallback token that will fail validation
            return "invalid_token"
    
    def validate_token(
        self, 
        token: str, 
        session_id: str, 
        action_type: str, 
        cwe_id: str
    ) -> Tuple[bool, str]:
        """
        Validate a CSRF token.
        
        Args:
            token: CSRF token to validate
            session_id: Current session identifier
            action_type: Action type being performed
            cwe_id: CWE identifier for the action
            
        Returns:
            Tuple of (is_valid, reason)
        """
        try:
            with self._lock:
                # Clean up expired tokens
                self._cleanup_expired_tokens()
                
                # Check if token exists
                if token not in self._tokens:
                    return False, "Token not found or expired"
                
                token_info = self._tokens[token]
                
                # Check if token was already used (prevent replay attacks)
                if token_info['used']:
                    return False, "Token already used"
                
                # Validate token contents
                import base64
                try:
                    token_json = base64.urlsafe_b64decode(token.encode()).decode()
                    token_data = json.loads(token_json)
                except Exception:
                    return False, "Invalid token format"
                
                payload = token_data.get('payload', {})
                signature = token_data.get('signature', '')
                
                # Verify signature
                payload_json = json.dumps(payload, sort_keys=True)
                expected_signature = hmac.new(
                    self.secret_key.encode(),
                    payload_json.encode(),
                    hashlib.sha256
                ).hexdigest()
                
                if not hmac.compare_digest(signature, expected_signature):
                    return False, "Invalid token signature"
                
                # Verify token data matches request
                if (payload.get('session_id') != session_id or
                    payload.get('action_type') != action_type or
                    payload.get('cwe_id') != cwe_id):
                    return False, "Token data mismatch"
                
                # Check token expiration
                token_age = int(time.time()) - payload.get('timestamp', 0)
                if token_age > self.token_lifetime:
                    return False, "Token expired"
                
                # Mark token as used
                self._tokens[token]['used'] = True
                
                logger.debug(f"CSRF token validated for {session_id}:{action_type}:{cwe_id}")
                return True, "Valid token"
                
        except Exception as e:
            logger.log_exception("CSRF token validation failed", e)
            return False, f"Validation error: {str(e)}"
    
    def _cleanup_expired_tokens(self):
        """Clean up expired tokens from memory."""
        try:
            current_time = int(time.time())
            expired_tokens = []
            
            for token, token_info in self._tokens.items():
                token_age = current_time - token_info.get('timestamp', 0)
                if token_age > self.token_lifetime:
                    expired_tokens.append(token)
            
            for token in expired_tokens:
                del self._tokens[token]
            
            if expired_tokens:
                logger.debug(f"Cleaned up {len(expired_tokens)} expired CSRF tokens")
                
        except Exception as e:
            logger.log_exception("CSRF token cleanup failed", e)
    
    def get_token_count(self) -> int:
        """Get current number of active tokens (for monitoring)."""
        with self._lock:
            self._cleanup_expired_tokens()
            return len(self._tokens)


# Global CSRF protection instance
_csrf_protection = None
_csrf_lock = threading.Lock()


def get_csrf_protection() -> CSRFProtection:
    """Get the global CSRF protection instance (singleton pattern)."""
    global _csrf_protection
    
    if _csrf_protection is None:
        with _csrf_lock:
            if _csrf_protection is None:
                _csrf_protection = CSRFProtection()
    
    return _csrf_protection