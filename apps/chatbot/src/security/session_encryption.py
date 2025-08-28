#!/usr/bin/env python3
"""
Session Encryption Module for MED-006 Security Remediation
Provides encryption/decryption capabilities for sensitive session data.
"""

import base64
import hashlib
import json
import logging
from typing import Any, Dict, Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import chainlit as cl

from .secure_logging import get_secure_logger

logger = get_secure_logger(__name__)


class SessionEncryption:
    """
    Secure session data encryption for role information.
    
    Addresses MED-006 by encrypting sensitive session data to prevent
    information disclosure if session storage is compromised.
    
    Security Features:
    - AES-128 encryption using Fernet (CBC mode with HMAC)
    - PBKDF2 key derivation with 100,000 iterations
    - Session-specific encryption keys
    - Backward compatibility with plain text sessions
    - Secure error handling and fallback mechanisms
    """
    
    # Security configuration
    PBKDF2_ITERATIONS = 100000  # NIST recommended minimum
    SALT = b'cwe_chatbot_session_encryption_v1'  # Static salt for consistency
    KEY_SIZE = 32  # 256 bits for AES
    
    def __init__(self):
        """Initialize session encryption with session-specific cipher."""
        self._cipher: Optional[Fernet] = None
        self._initialize_cipher()
        
    def _initialize_cipher(self) -> None:
        """Initialize or refresh the encryption cipher."""
        try:
            session_id = self._get_session_identifier()
            key = self._derive_encryption_key(session_id)
            self._cipher = Fernet(key)
            logger.debug("Session encryption cipher initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize session encryption cipher: {e}")
            self._cipher = None
    
    def _get_session_identifier(self) -> str:
        """
        Get unique session identifier for key derivation.
        
        Returns:
            Session identifier string
        """
        try:
            # Try to get Chainlit session ID
            session_id = getattr(cl.user_session, 'id', None)
            if session_id:
                return str(session_id)
            
            # Fallback to a stored session identifier
            stored_id = cl.user_session.get('_encryption_session_id')
            if stored_id:
                return str(stored_id)
            
            # Generate and store a new session identifier
            import uuid
            new_id = str(uuid.uuid4())
            cl.user_session['_encryption_session_id'] = new_id
            logger.info("Generated new session encryption identifier")
            return new_id
            
        except Exception as e:
            logger.warning(f"Could not get session identifier, using default: {e}")
            return "default_session_encryption_key"
    
    def _derive_encryption_key(self, session_id: str) -> bytes:
        """
        Derive encryption key from session identifier using PBKDF2.
        
        Args:
            session_id: Session identifier for key derivation
            
        Returns:
            Base64-encoded encryption key suitable for Fernet
        """
        # Use session ID as password input
        password = session_id.encode('utf-8')
        
        # Create PBKDF2 key derivation function
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=self.SALT,
            iterations=self.PBKDF2_ITERATIONS,
        )
        
        # Derive key and encode for Fernet
        derived_key = kdf.derive(password)
        return base64.urlsafe_b64encode(derived_key)
    
    def encrypt_session_data(self, data: Union[str, Dict[str, Any]]) -> str:
        """
        Encrypt session data for secure storage.
        
        Args:
            data: String or dictionary data to encrypt
            
        Returns:
            Base64-encoded encrypted data string
            
        Raises:
            EncryptionError: If encryption fails
        """
        if not self._cipher:
            logger.warning("Cipher not available, attempting to reinitialize")
            self._initialize_cipher()
            if not self._cipher:
                raise EncryptionError("Session encryption cipher not available")
        
        try:
            # Convert data to JSON string if it's a dictionary
            if isinstance(data, dict):
                json_data = json.dumps(data, sort_keys=True)
            else:
                json_data = str(data)
            
            # Encrypt the data
            encrypted_bytes = self._cipher.encrypt(json_data.encode('utf-8'))
            
            # Encode as base64 for safe string storage
            encrypted_string = base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
            
            logger.debug(f"Successfully encrypted session data of length {len(json_data)}")
            return encrypted_string
            
        except Exception as e:
            logger.error(f"Session data encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt session data: {e}")
    
    def decrypt_session_data(self, encrypted_data: str, return_type: str = 'auto') -> Union[str, Dict[str, Any]]:
        """
        Decrypt session data from storage.
        
        Args:
            encrypted_data: Base64-encoded encrypted data string
            return_type: 'auto', 'str', or 'dict' - format to return data in
            
        Returns:
            Decrypted data as string or dictionary
            
        Raises:
            DecryptionError: If decryption fails
        """
        if not self._cipher:
            logger.warning("Cipher not available, attempting to reinitialize")
            self._initialize_cipher()
            if not self._cipher:
                raise DecryptionError("Session encryption cipher not available")
        
        try:
            # Decode from base64
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            
            # Decrypt the data
            decrypted_bytes = self._cipher.decrypt(encrypted_bytes)
            decrypted_string = decrypted_bytes.decode('utf-8')
            
            # Return in requested format
            if return_type == 'dict' or (return_type == 'auto' and decrypted_string.strip().startswith('{')):
                try:
                    return json.loads(decrypted_string)
                except json.JSONDecodeError:
                    logger.warning("Could not parse decrypted data as JSON, returning as string")
                    return decrypted_string
            else:
                return decrypted_string
                
        except Exception as e:
            logger.error(f"Session data decryption failed: {e}")
            raise DecryptionError(f"Failed to decrypt session data: {e}")
    
    def is_encrypted_data(self, data: str) -> bool:
        """
        Check if data appears to be encrypted by this module.
        
        Args:
            data: Data string to check
            
        Returns:
            True if data appears to be encrypted, False otherwise
        """
        try:
            # Encrypted data should be base64-encoded and longer than plain text
            if len(data) < 10:
                return False
                
            # Try to decode as base64
            base64.urlsafe_b64decode(data.encode('utf-8'))
            
            # If it decodes and looks like encrypted data, it probably is
            return len(data) > 50 and '=' in data[-4:]  # Base64 padding
            
        except Exception:
            return False
    
    def migrate_plain_text_data(self, plain_text_data: str) -> str:
        """
        Migrate plain text session data to encrypted format.
        
        Args:
            plain_text_data: Plain text data to encrypt
            
        Returns:
            Encrypted data string
        """
        logger.info("Migrating plain text session data to encrypted format")
        return self.encrypt_session_data(plain_text_data)


class EncryptionError(Exception):
    """Exception raised when encryption operations fail."""
    pass


class DecryptionError(Exception):
    """Exception raised when decryption operations fail."""
    pass


# Module-level utility functions for convenience
_encryption_instance: Optional[SessionEncryption] = None


def get_session_encryptor() -> SessionEncryption:
    """Get or create the global session encryption instance."""
    global _encryption_instance
    if _encryption_instance is None:
        _encryption_instance = SessionEncryption()
    return _encryption_instance


def encrypt_session_value(value: Union[str, Dict[str, Any]]) -> str:
    """Convenience function to encrypt a session value."""
    return get_session_encryptor().encrypt_session_data(value)


def decrypt_session_value(encrypted_value: str) -> Union[str, Dict[str, Any]]:
    """Convenience function to decrypt a session value."""
    return get_session_encryptor().decrypt_session_data(encrypted_value)


def is_session_value_encrypted(value: str) -> bool:
    """Convenience function to check if a session value is encrypted."""
    return get_session_encryptor().is_encrypted_data(value)