"""
Authentication Security Tests for CWE ChatBot

This module provides comprehensive authentication and security validation tests
for the CWE ChatBot application, including CSRF protection, rate limiting,
and action button security.

Test Categories:
- CSRF token validation tests
- Rate limiting enforcement tests
- Session isolation tests
- Action button authentication tests
- Security boundary validation tests
"""

import pytest
import time
import asyncio
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List

# Mock Chainlit before importing main components
import sys
mock_cl = Mock()
mock_cl.Action = Mock(side_effect=lambda name, value, description, label: {
    'name': name, 'value': value, 'description': description, 'label': label
})
mock_cl.Message = Mock()
sys.modules['chainlit'] = mock_cl

from src.security.csrf_protection import CSRFProtection
from src.security.rate_limiting import RateLimiter, RateLimitExceeded, action_button_rate_limit
from src.formatting.progressive_response_formatter import ProgressiveResponseFormatter
from src.session.session_security import SessionSecurityValidator
from src.retrieval.base_retriever import CWEResult


class TestCSRFProtection:
    """Test CSRF protection for action buttons."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.csrf = CSRFProtection(secret_key="test_secret_key_12345", token_lifetime=3600)
        self.session_id = "test_session_123"
        self.action_type = "tell_more"
        self.cwe_id = "CWE-79"
    
    def test_csrf_token_generation(self):
        """Test CSRF token generation."""
        token = self.csrf.generate_token(self.session_id, self.action_type, self.cwe_id)
        
        assert isinstance(token, str)
        assert len(token) > 10  # Should be substantial length
        assert token != "invalid_token"
    
    def test_csrf_token_validation_success(self):
        """Test successful CSRF token validation."""
        token = self.csrf.generate_token(self.session_id, self.action_type, self.cwe_id)
        
        is_valid, reason = self.csrf.validate_token(
            token, self.session_id, self.action_type, self.cwe_id
        )
        
        assert is_valid is True
        assert reason == "Valid token"
    
    def test_csrf_token_validation_failure_wrong_session(self):
        """Test CSRF token validation failure with wrong session ID."""
        token = self.csrf.generate_token(self.session_id, self.action_type, self.cwe_id)
        
        is_valid, reason = self.csrf.validate_token(
            token, "wrong_session_456", self.action_type, self.cwe_id
        )
        
        assert is_valid is False
        assert "mismatch" in reason.lower()
    
    def test_csrf_token_validation_failure_wrong_action(self):
        """Test CSRF token validation failure with wrong action type."""
        token = self.csrf.generate_token(self.session_id, self.action_type, self.cwe_id)
        
        is_valid, reason = self.csrf.validate_token(
            token, self.session_id, "show_consequences", self.cwe_id
        )
        
        assert is_valid is False
        assert "mismatch" in reason.lower()
    
    def test_csrf_token_validation_failure_wrong_cwe(self):
        """Test CSRF token validation failure with wrong CWE ID."""
        token = self.csrf.generate_token(self.session_id, self.action_type, self.cwe_id)
        
        is_valid, reason = self.csrf.validate_token(
            token, self.session_id, self.action_type, "CWE-89"
        )
        
        assert is_valid is False
        assert "mismatch" in reason.lower()
    
    def test_csrf_token_replay_attack_prevention(self):
        """Test that tokens cannot be used twice (replay attack prevention)."""
        token = self.csrf.generate_token(self.session_id, self.action_type, self.cwe_id)
        
        # First validation should succeed
        is_valid, reason = self.csrf.validate_token(
            token, self.session_id, self.action_type, self.cwe_id
        )
        assert is_valid is True
        
        # Second validation should fail (token already used)
        is_valid, reason = self.csrf.validate_token(
            token, self.session_id, self.action_type, self.cwe_id
        )
        assert is_valid is False
        assert "already used" in reason.lower()
    
    def test_csrf_token_expiration(self):
        """Test CSRF token expiration."""
        # Create CSRF with short lifetime
        short_csrf = CSRFProtection(secret_key="test_secret", token_lifetime=1)
        token = short_csrf.generate_token(self.session_id, self.action_type, self.cwe_id)
        
        # Wait for expiration
        time.sleep(1.1)
        
        is_valid, reason = short_csrf.validate_token(
            token, self.session_id, self.action_type, self.cwe_id
        )
        
        assert is_valid is False
        assert "expired" in reason.lower()
    
    def test_csrf_invalid_token_format(self):
        """Test validation with invalid token format."""
        invalid_tokens = [
            "",
            "invalid_token",
            "not_base64_!@#",
            "dGVzdA==",  # Valid base64 but invalid JSON
        ]
        
        for invalid_token in invalid_tokens:
            is_valid, reason = self.csrf.validate_token(
                invalid_token, self.session_id, self.action_type, self.cwe_id
            )
            assert is_valid is False
    
    def test_csrf_token_cleanup(self):
        """Test automatic cleanup of expired tokens."""
        # Create multiple tokens
        tokens = []
        for i in range(5):
            token = self.csrf.generate_token(f"session_{i}", self.action_type, self.cwe_id)
            tokens.append(token)
        
        initial_count = self.csrf.get_token_count()
        assert initial_count == 5
        
        # Force cleanup by creating new token (triggers cleanup)
        time.sleep(0.1)
        self.csrf._cleanup_expired_tokens()
        
        # Tokens should still be there (not expired yet)
        assert self.csrf.get_token_count() == 5


class TestRateLimiting:
    """Test rate limiting functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.limiter = RateLimiter(max_requests=5, window_seconds=60)
        self.test_key = "test_user_123"
    
    def test_rate_limit_allows_within_limit(self):
        """Test that requests within limit are allowed."""
        for i in range(5):
            allowed, metadata = self.limiter.is_allowed(self.test_key)
            assert allowed is True
            assert metadata['remaining'] >= 0
    
    def test_rate_limit_blocks_over_limit(self):
        """Test that requests over limit are blocked."""
        # Use up the limit
        for i in range(5):
            allowed, _ = self.limiter.is_allowed(self.test_key)
            assert allowed is True
        
        # Next request should be blocked
        allowed, metadata = self.limiter.is_allowed(self.test_key)
        assert allowed is False
        assert metadata['remaining'] == 0
    
    def test_rate_limit_different_keys_independent(self):
        """Test that different keys have independent rate limits."""
        # Use up limit for first key
        for i in range(5):
            self.limiter.is_allowed("key1")
        
        # Second key should still be allowed
        allowed, metadata = self.limiter.is_allowed("key2")
        assert allowed is True
        assert metadata['remaining'] == 4
    
    def test_rate_limit_sliding_window(self):
        """Test sliding window behavior."""
        # Use up limit
        for i in range(5):
            self.limiter.is_allowed(self.test_key)
        
        # Should be blocked
        allowed, _ = self.limiter.is_allowed(self.test_key)
        assert allowed is False
        
        # Simulate time passing (in real test, this would need actual time)
        # For now, just verify the metadata indicates when reset occurs
        _, metadata = self.limiter.is_allowed(self.test_key)
        assert 'reset_time' in metadata
        assert metadata['reset_time'] > time.time()
    
    def test_rate_limit_decorator_success(self):
        """Test rate limiting decorator allows requests within limit."""
        @action_button_rate_limit(max_requests=3, window=60)
        def test_function(session_id="test_session"):
            return "success"
        
        # Should work within limit
        for i in range(3):
            result = test_function()
            assert result == "success"
    
    def test_rate_limit_decorator_blocks_excess(self):
        """Test rate limiting decorator blocks excess requests."""
        @action_button_rate_limit(max_requests=2, window=60)
        def test_function(session_id="test_session"):
            return "success"
        
        # Use up limit
        for i in range(2):
            result = test_function()
            assert result == "success"
        
        # Next call should raise exception
        with pytest.raises(RateLimitExceeded):
            test_function()
    
    def test_rate_limit_stats(self):
        """Test rate limiter statistics."""
        # Make some requests
        for i in range(3):
            self.limiter.is_allowed(f"key_{i}")
        
        stats = self.limiter.get_stats()
        assert stats['active_keys'] == 3
        assert stats['max_requests'] == 5
        assert stats['window_seconds'] == 60
        assert stats['total_tracked_requests'] == 3


class TestProgressiveFormatterSecurity:
    """Test security aspects of progressive response formatter."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.formatter = ProgressiveResponseFormatter(enable_csrf=True)
        self.session_id = "test_session_123"
        self.sample_cwe = CWEResult(
            cwe_id='CWE-79',
            name='Cross-site Scripting',
            description='XSS vulnerability',
            confidence_score=0.95,
            consequences=[{'scope': 'Confidentiality', 'impact': 'Information disclosure'}],
            relationships={'ChildOf': ['CWE-20']}
        )
    
    def test_action_metadata_csrf_validation_enabled(self):
        """Test action metadata parsing with CSRF validation enabled."""
        # Generate a valid action value with CSRF token
        with patch.object(self.formatter.csrf_protection, 'validate_token') as mock_validate:
            mock_validate.return_value = (True, "Valid token")
            
            metadata = self.formatter.get_action_metadata(
                "tell_more:CWE-79:valid_csrf_token", 
                self.session_id
            )
            
            assert metadata['action_type'] == 'tell_more'
            assert metadata['cwe_id'] == 'CWE-79'
            assert metadata['csrf_valid'] is True
            mock_validate.assert_called_once()
    
    def test_action_metadata_csrf_validation_failed(self):
        """Test action metadata parsing with CSRF validation failure."""
        with patch.object(self.formatter.csrf_protection, 'validate_token') as mock_validate:
            mock_validate.return_value = (False, "Invalid token")
            
            metadata = self.formatter.get_action_metadata(
                "tell_more:CWE-79:invalid_csrf_token", 
                self.session_id
            )
            
            assert metadata['action_type'] == 'tell_more'
            assert metadata['cwe_id'] == 'CWE-79'
            assert metadata['csrf_valid'] is False
            assert metadata['csrf_reason'] == "Invalid token"
    
    def test_action_metadata_without_session_id(self):
        """Test action metadata parsing without session ID."""
        metadata = self.formatter.get_action_metadata(
            "tell_more:CWE-79:csrf_token", 
            session_id=None
        )
        
        assert metadata['csrf_valid'] is False
        assert "Missing CSRF token or session ID" in metadata['csrf_reason']
    
    def test_secure_action_value_creation(self):
        """Test secure action value creation with CSRF tokens."""
        with patch.object(self.formatter.csrf_protection, 'generate_token') as mock_generate:
            mock_generate.return_value = "generated_csrf_token"
            
            action_value = self.formatter._create_secure_action_value(
                "tell_more", "CWE-79", self.session_id
            )
            
            assert action_value == "tell_more:CWE-79:generated_csrf_token"
            mock_generate.assert_called_once_with(self.session_id, "tell_more", "CWE-79")
    
    def test_action_buttons_include_csrf_tokens(self):
        """Test that action buttons include CSRF tokens when enabled."""
        with patch.object(self.formatter.csrf_protection, 'generate_token') as mock_generate:
            mock_generate.return_value = "csrf_token_123"
            
            actions = self.formatter._create_action_buttons(self.sample_cwe, self.session_id)
            
            assert len(actions) > 0
            for action in actions:
                assert ":csrf_token_123" in action['value']
            
            # Should have called generate_token for each action
            assert mock_generate.call_count == len(actions)
    
    def test_enhanced_input_validation(self):
        """Test enhanced input validation for action metadata."""
        # Test oversized input
        oversized_input = "a" * 501  # Over 500 char limit
        metadata = self.formatter.get_action_metadata(oversized_input)
        assert metadata['action_type'] == 'unknown'
        assert metadata['csrf_valid'] is False
        
        # Test invalid input types
        for invalid_input in [None, 123, [], {}]:
            metadata = self.formatter.get_action_metadata(invalid_input)
            assert metadata['action_type'] == 'unknown'
            assert metadata['csrf_valid'] is False
        
        # Test invalid CWE ID format
        metadata = self.formatter.get_action_metadata("tell_more:INVALID-ID:token")
        assert metadata['action_type'] == 'unknown'
        assert metadata['csrf_valid'] is False


class TestSessionSecurity:
    """Test session security validation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = SessionSecurityValidator()
        self.session_id = "test_session_123"
    
    def test_session_isolation_validation_success(self):
        """Test successful session isolation validation."""
        # First validation should succeed (establishes baseline)
        result = self.validator.validate_session_isolation(self.session_id)
        assert result is True
    
    def test_session_isolation_validation_failure(self):
        """Test session isolation validation failure detection."""
        # Establish baseline
        self.validator.validate_session_isolation(self.session_id)
        
        # Simulate context contamination
        with patch.object(self.validator, '_detect_context_contamination') as mock_detect:
            mock_detect.return_value = True
            
            result = self.validator.validate_session_isolation(self.session_id)
            assert result is False
    
    def test_security_violation_logging(self):
        """Test security violation logging with structured format."""
        with patch('src.session.session_security.logger') as mock_logger:
            self.validator._log_security_violation(
                self.session_id, 
                "isolation_failure", 
                "Test violation details"
            )
            
            # Should have logged an error with JSON structure
            mock_logger.error.assert_called_once()
            logged_data = mock_logger.error.call_args[0][0]
            
            # Should be valid JSON string
            import json
            parsed_log = json.loads(logged_data)
            
            assert parsed_log['event_type'] == 'security_violation'
            assert parsed_log['violation_type'] == 'isolation_failure'
            assert parsed_log['details'] == 'Test violation details'
            assert 'session_id' in parsed_log  # Should be hashed
            assert parsed_log['session_id'] != self.session_id  # Should be hashed
    
    def test_session_id_hashing_privacy(self):
        """Test that session IDs are hashed for privacy in logs."""
        hashed_1 = self.validator._hash_session_id("session_123")
        hashed_2 = self.validator._hash_session_id("session_456")
        hashed_3 = self.validator._hash_session_id("session_123")  # Same as first
        
        # Hashes should be consistent
        assert hashed_1 == hashed_3
        
        # Different sessions should have different hashes
        assert hashed_1 != hashed_2
        
        # Hashes should not reveal original session ID
        assert "session_123" not in hashed_1
        assert len(hashed_1) == 16  # Should be truncated MD5


class TestIntegratedSecurity:
    """Test integrated security across all components."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.formatter = ProgressiveResponseFormatter(enable_csrf=True)
        self.session_validator = SessionSecurityValidator()
        self.session_id = "integration_test_session"
    
    def test_full_security_validation_workflow(self):
        """Test complete security validation workflow."""
        # Step 1: Validate session isolation
        session_valid = self.session_validator.validate_session_isolation(self.session_id)
        assert session_valid is True
        
        # Step 2: Create secure action buttons
        sample_cwe = CWEResult(
            cwe_id='CWE-89',
            name='SQL Injection',
            description='SQL injection vulnerability',
            confidence_score=0.9,
            consequences=[{'scope': 'Confidentiality', 'impact': 'Data access'}]
        )
        
        with patch.object(self.formatter.csrf_protection, 'generate_token') as mock_generate:
            mock_generate.return_value = "secure_token_123"
            
            # Step 3: Generate action buttons with CSRF protection
            content, actions = self.formatter.format_summary_response(
                sample_cwe, include_actions=True, session_id=self.session_id
            )
            
            assert len(actions) > 0
            for action in actions:
                assert "secure_token_123" in action['value']
    
    def test_security_failure_handling(self):
        """Test handling of security validation failures."""
        # Test CSRF validation failure
        with patch.object(self.formatter.csrf_protection, 'validate_token') as mock_validate:
            mock_validate.return_value = (False, "Token expired")
            
            metadata = self.formatter.get_action_metadata(
                "tell_more:CWE-79:expired_token", 
                self.session_id
            )
            
            assert metadata['csrf_valid'] is False
            assert "Token expired" in metadata['csrf_reason']
    
    def test_rate_limit_with_csrf_integration(self):
        """Test rate limiting works with CSRF protection."""
        @action_button_rate_limit(max_requests=2, window=60)
        def secure_action_handler(session_id, action_value):
            # Validate CSRF
            metadata = self.formatter.get_action_metadata(action_value, session_id)
            if not metadata.get('csrf_valid', True):
                raise ValueError("CSRF validation failed")
            return f"Processed {metadata['action_type']} for {metadata['cwe_id']}"
        
        # Should work within rate limit
        with patch.object(self.formatter.csrf_protection, 'validate_token') as mock_validate:
            mock_validate.return_value = (True, "Valid token")
            
            result1 = secure_action_handler(self.session_id, "tell_more:CWE-79:valid_token")
            result2 = secure_action_handler(self.session_id, "tell_more:CWE-89:valid_token")
            
            assert "Processed tell_more for CWE-79" in result1
            assert "Processed tell_more for CWE-89" in result2
            
            # Third request should be rate limited
            with pytest.raises(RateLimitExceeded):
                secure_action_handler(self.session_id, "tell_more:CWE-120:valid_token")


@pytest.mark.asyncio
class TestAsyncSecurityValidation:
    """Test security validation in async context (simulating real app behavior)."""
    
    def setup_method(self):
        """Set up async test fixtures."""
        self.formatter = ProgressiveResponseFormatter(enable_csrf=True)
        self.session_id = "async_test_session"
    
    async def test_async_csrf_validation(self):
        """Test CSRF validation in async context."""
        async def validate_action(action_value, session_id):
            """Simulate async action validation."""
            metadata = self.formatter.get_action_metadata(action_value, session_id)
            
            if not metadata.get('csrf_valid', True):
                raise ValueError(f"CSRF validation failed: {metadata.get('csrf_reason')}")
            
            return metadata
        
        # Test successful validation
        with patch.object(self.formatter.csrf_protection, 'validate_token') as mock_validate:
            mock_validate.return_value = (True, "Valid token")
            
            metadata = await validate_action("tell_more:CWE-79:valid_token", self.session_id)
            assert metadata['action_type'] == 'tell_more'
            assert metadata['csrf_valid'] is True
        
        # Test failed validation
        with patch.object(self.formatter.csrf_protection, 'validate_token') as mock_validate:
            mock_validate.return_value = (False, "Invalid signature")
            
            with pytest.raises(ValueError, match="CSRF validation failed"):
                await validate_action("tell_more:CWE-79:invalid_token", self.session_id)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])