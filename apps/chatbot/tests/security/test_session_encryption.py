#!/usr/bin/env python3
"""
Comprehensive Security Test Suite for MED-006: Session Data Encryption
Tests session encryption implementation in role_manager.py and session_encryption.py
"""

import pytest
import base64
import json
from unittest.mock import Mock, MagicMock, patch
import sys
import os

# Add the project root to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Mock chainlit before importing our modules
mock_cl = Mock()
mock_user_session = {}
mock_cl.user_session = mock_user_session
sys.modules['chainlit'] = mock_cl

from src.user.role_manager import RoleManager, UserRole
from src.security.session_encryption import SessionEncryption, EncryptionError, DecryptionError


class TestSessionEncryptionCore:
    """Test the core SessionEncryption utility class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.encryptor = SessionEncryption()
    
    def test_encryption_decryption_cycle(self):
        """Test basic encryption/decryption functionality."""
        test_data = "psirt"
        
        # Encrypt the data
        encrypted = self.encryptor.encrypt_session_data(test_data)
        
        # Verify encrypted data is different from original
        assert encrypted != test_data
        assert len(encrypted) > len(test_data)
        
        # Decrypt the data
        decrypted = self.encryptor.decrypt_session_data(encrypted)
        
        # Verify decryption returns original data
        assert decrypted == test_data
    
    def test_encryption_produces_base64_output(self):
        """Test that encryption produces valid base64 encoded data."""
        test_data = "developer"
        encrypted = self.encryptor.encrypt_session_data(test_data)
        
        # Should be valid base64
        try:
            base64.urlsafe_b64decode(encrypted.encode('utf-8'))
            base64_valid = True
        except Exception:
            base64_valid = False
        
        assert base64_valid, "Encrypted data should be valid base64"
    
    def test_different_sessions_produce_different_encryption(self):
        """Test that same data produces different encryption with different session IDs."""
        test_data = "academic"
        
        # Create two encryptors with different session contexts
        encryptor1 = SessionEncryption()
        with patch.object(encryptor1, '_get_session_identifier', return_value='session-1'):
            encryptor1._initialize_cipher()
            encrypted1 = encryptor1.encrypt_session_data(test_data)
        
        encryptor2 = SessionEncryption()
        with patch.object(encryptor2, '_get_session_identifier', return_value='session-2'):
            encryptor2._initialize_cipher()
            encrypted2 = encryptor2.encrypt_session_data(test_data)
        
        # Different sessions should produce different encrypted data
        assert encrypted1 != encrypted2
    
    def test_is_encrypted_data_detection(self):
        """Test detection of encrypted vs plain text data."""
        # Plain text should not be detected as encrypted
        assert not self.encryptor.is_encrypted_data("psirt")
        assert not self.encryptor.is_encrypted_data("developer")
        assert not self.encryptor.is_encrypted_data("short")
        
        # Encrypted data should be detected
        encrypted = self.encryptor.encrypt_session_data("bug_bounty")
        assert self.encryptor.is_encrypted_data(encrypted)
    
    def test_encryption_error_handling(self):
        """Test proper error handling for encryption failures."""
        # Test with cipher failure - the system attempts to reinitialize
        with patch.object(self.encryptor, '_cipher', None):
            with patch.object(self.encryptor, '_initialize_cipher') as mock_init:
                mock_init.return_value = None  # Simulate initialization failure
                with pytest.raises(EncryptionError):
                    self.encryptor.encrypt_session_data("test")
    
    def test_decryption_error_handling(self):
        """Test proper error handling for decryption failures."""
        # Test with invalid encrypted data
        with pytest.raises(DecryptionError):
            self.encryptor.decrypt_session_data("invalid_encrypted_data")
        
        # Test with cipher failure
        with patch.object(self.encryptor, '_cipher', None):
            with pytest.raises(DecryptionError):
                self.encryptor.decrypt_session_data("some_data")


class TestRoleManagerEncryption:
    """Test encryption integration in RoleManager."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Clear mock session data
        mock_user_session.clear()
        self.role_manager = RoleManager()
    
    def test_role_storage_uses_encryption(self):
        """Test that role storage encrypts data before saving to session."""
        test_role = UserRole.PSIRT
        
        # Set the role
        result = self.role_manager.set_user_role(test_role)
        assert result is True
        
        # Check that session contains encrypted data (not plain text)
        stored_data = mock_user_session.get(self.role_manager.ROLE_SESSION_KEY)
        assert stored_data is not None
        assert stored_data != test_role.value  # Should not be plain text
        
        # Verify it's encrypted (base64 encoded, longer than original)
        assert len(stored_data) > len(test_role.value)
        
        # Verify it's valid base64
        try:
            base64.urlsafe_b64decode(stored_data.encode('utf-8'))
            is_base64 = True
        except Exception:
            is_base64 = False
        assert is_base64, "Stored role data should be base64 encoded"
    
    def test_role_retrieval_decrypts_data(self):
        """Test that role retrieval properly decrypts stored data."""
        test_role = UserRole.DEVELOPER
        
        # Store the role (encrypted)
        self.role_manager.set_user_role(test_role)
        
        # Retrieve the role (should decrypt automatically)
        retrieved_role = self.role_manager.get_current_role()
        
        # Should match original role
        assert retrieved_role == test_role
    
    def test_corrupted_session_data_handling(self):
        """Test handling of corrupted encrypted session data."""
        # Manually insert corrupted encrypted data
        mock_user_session[self.role_manager.ROLE_SESSION_KEY] = "corrupted_encrypted_data"
        mock_user_session[self.role_manager.ROLE_SET_FLAG] = True
        
        # Attempt to retrieve role should handle corruption gracefully
        retrieved_role = self.role_manager.get_current_role()
        
        # Should return None and clear corrupted data
        assert retrieved_role is None
        assert self.role_manager.ROLE_SESSION_KEY not in mock_user_session
        assert self.role_manager.ROLE_SET_FLAG not in mock_user_session
    
    def test_role_flag_consistency_with_encryption(self):
        """Test that role flag is properly set with encrypted role data."""
        test_role = UserRole.ACADEMIC
        
        # Initially no role should be selected
        assert not self.role_manager.is_role_selected()
        
        # Set role
        self.role_manager.set_user_role(test_role)
        
        # Role should be selected
        assert self.role_manager.is_role_selected()
        
        # Clear role
        self.role_manager.clear_role()
        
        # Role should no longer be selected
        assert not self.role_manager.is_role_selected()
    
    def test_all_role_types_encryption_support(self):
        """Test that all UserRole types can be encrypted and decrypted."""
        for role in UserRole:
            # Clear session
            mock_user_session.clear()
            
            # Set and retrieve each role type
            self.role_manager.set_user_role(role)
            retrieved_role = self.role_manager.get_current_role()
            
            assert retrieved_role == role, f"Role {role} failed encryption/decryption cycle"


class TestSessionEncryptionSecurity:
    """Security-focused tests for session encryption."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.encryptor = SessionEncryption()
    
    def test_encryption_key_derivation_security(self):
        """Test that encryption uses proper key derivation."""
        # Verify PBKDF2 parameters meet security standards
        assert self.encryptor.PBKDF2_ITERATIONS >= 100000, "PBKDF2 iterations should be >= 100,000"
        assert self.encryptor.KEY_SIZE == 32, "Key size should be 256 bits (32 bytes)"
        
        # Verify salt is consistent but not empty
        assert len(self.encryptor.SALT) > 16, "Salt should be at least 16 bytes"
    
    def test_encryption_produces_unique_output(self):
        """Test that encryption produces unique output for each call (due to Fernet nonce)."""
        test_data = "psirt"
        
        # Encrypt same data multiple times
        encrypted1 = self.encryptor.encrypt_session_data(test_data)
        encrypted2 = self.encryptor.encrypt_session_data(test_data)
        
        # Should be different due to random nonce in Fernet
        assert encrypted1 != encrypted2, "Repeated encryption should produce different outputs"
        
        # But both should decrypt to same original data
        assert self.encryptor.decrypt_session_data(encrypted1) == test_data
        assert self.encryptor.decrypt_session_data(encrypted2) == test_data
    
    def test_session_isolation(self):
        """Test that different sessions cannot decrypt each other's data."""
        test_data = "developer"
        
        # Encrypt with session 1
        encryptor1 = SessionEncryption()
        with patch.object(encryptor1, '_get_session_identifier', return_value='session-1'):
            encryptor1._initialize_cipher()
            encrypted_session1 = encryptor1.encrypt_session_data(test_data)
        
        # Try to decrypt with session 2
        encryptor2 = SessionEncryption()
        with patch.object(encryptor2, '_get_session_identifier', return_value='session-2'):
            encryptor2._initialize_cipher()
            
            # Should fail to decrypt data from different session
            with pytest.raises(DecryptionError):
                encryptor2.decrypt_session_data(encrypted_session1)
    
    def test_tampering_detection(self):
        """Test that tampered encrypted data is detected."""
        test_data = "academic"
        encrypted = self.encryptor.encrypt_session_data(test_data)
        
        # Tamper with encrypted data
        tampered = encrypted[:-1] + ('X' if encrypted[-1] != 'X' else 'Y')
        
        # Should fail to decrypt tampered data
        with pytest.raises(DecryptionError):
            self.encryptor.decrypt_session_data(tampered)


class TestMED006Remediation:
    """Integration tests specifically for MED-006 vulnerability remediation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        mock_user_session.clear()
        self.role_manager = RoleManager()
    
    def test_med006_role_data_never_stored_in_plaintext(self):
        """Test that role data is never stored in plain text (addresses MED-006)."""
        test_roles = [UserRole.PSIRT, UserRole.DEVELOPER, UserRole.ACADEMIC, UserRole.BUG_BOUNTY, UserRole.PRODUCT_MANAGER]
        
        for role in test_roles:
            # Clear session
            mock_user_session.clear()
            
            # Set role
            self.role_manager.set_user_role(role)
            
            # Verify plain text role value is NOT in session storage
            stored_data = mock_user_session.get(self.role_manager.ROLE_SESSION_KEY)
            assert stored_data != role.value, f"Role {role.value} should not be stored in plain text"
            
            # Verify stored data appears encrypted (base64, longer than original)
            assert len(stored_data) > len(role.value) * 1.5  # Encrypted should be significantly longer
    
    def test_med006_session_compromise_protection(self):
        """Test protection against session data compromise (core MED-006 concern)."""
        sensitive_role = UserRole.PSIRT
        self.role_manager.set_user_role(sensitive_role)
        
        # Simulate session storage compromise - attacker gets raw session data
        compromised_session_data = dict(mock_user_session)
        
        # Verify attacker cannot directly read role information
        role_data = compromised_session_data.get(self.role_manager.ROLE_SESSION_KEY)
        
        # Should be encrypted blob, not readable role value
        assert role_data != sensitive_role.value
        assert "psirt" not in role_data.lower()
        
        # Should not be JSON parseable (would indicate structured plain text)
        try:
            json.loads(role_data)
            is_json = True
        except (json.JSONDecodeError, TypeError):
            is_json = False
        assert not is_json, "Role data should not be stored as readable JSON"
    
    def test_med006_encryption_strength_verification(self):
        """Verify encryption meets security requirements for MED-006."""
        role_manager = RoleManager()
        encryptor = role_manager.session_encryptor
        
        # Verify encryption algorithm strength
        assert hasattr(encryptor, '_cipher'), "Should use proper encryption cipher"
        assert encryptor.PBKDF2_ITERATIONS >= 100000, "Should use strong key derivation"
        
        # Test that encrypted data cannot be easily reversed
        test_role = UserRole.BUG_BOUNTY
        role_manager.set_user_role(test_role)
        
        encrypted_data = mock_user_session[role_manager.ROLE_SESSION_KEY]
        
        # Common attack attempts should fail
        attack_attempts = [
            lambda: base64.urlsafe_b64decode(encrypted_data).decode('utf-8'),  # Direct decode
            lambda: encrypted_data[::-1],  # Reverse string
            lambda: ''.join(chr(ord(c) ^ 1) for c in encrypted_data),  # Simple XOR
        ]
        
        for attack in attack_attempts:
            try:
                result = attack()
                # If attack succeeds, verify it doesn't reveal the role
                assert test_role.value not in str(result).lower()
            except Exception:
                # Attack failing is expected and good
                pass


if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v", "--tb=short"])