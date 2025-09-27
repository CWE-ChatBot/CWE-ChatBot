#!/usr/bin/env python3
"""
Unit test for ConversationManager P0 fix: get_user_context sync method
Verifies that ConversationManager.get_user_context exists as a synchronous method
and can be called without await.
"""

import pytest
import inspect
from unittest.mock import Mock, patch
from src.conversation import ConversationManager
from src.user_context import UserContext


class TestConversationManagerP0Fix:
    """Test ConversationManager.get_user_context sync method (P0 fix)."""

    def test_get_user_context_method_exists(self):
        """Test that get_user_context method exists on ConversationManager."""
        # Check that the method exists
        assert hasattr(ConversationManager, 'get_user_context')

        # Get the method
        method = getattr(ConversationManager, 'get_user_context')
        assert callable(method)

    def test_get_user_context_is_not_coroutine(self):
        """Test that get_user_context is a regular method, not a coroutine."""
        method = getattr(ConversationManager, 'get_user_context')

        # Should not be a coroutine function
        assert not inspect.iscoroutinefunction(method)

        # Should be a regular function
        assert inspect.isfunction(method) or inspect.ismethod(method)

    @patch('src.conversation.get_user_context')
    def test_get_user_context_calls_helper(self, mock_get_user_context):
        """Test that get_user_context calls the central helper function."""
        # Mock the helper function
        mock_context = Mock(spec=UserContext)
        mock_context.session_id = None
        mock_get_user_context.return_value = mock_context

        # Create minimal ConversationManager (mocking dependencies)
        with patch('src.conversation.CWEQueryHandler'), \
             patch('src.conversation.ResponseGenerator'), \
             patch('src.conversation.InputSanitizer'), \
             patch('src.conversation.SecurityValidator'), \
             patch('src.conversation.QueryProcessor'):

            manager = ConversationManager("mock://db", "mock_key")

            # Call get_user_context
            result = manager.get_user_context("test_session_123")

            # Should have called the helper
            mock_get_user_context.assert_called_once()

            # Should return the context
            assert result == mock_context

            # Should have set session_id on the context
            assert mock_context.session_id == "test_session_123"

    def test_get_user_context_signature(self):
        """Test that get_user_context has the correct method signature."""
        method = getattr(ConversationManager, 'get_user_context')

        # Get method signature
        sig = inspect.signature(method)

        # Should have 'self' and 'session_id' parameters
        params = list(sig.parameters.keys())
        assert 'self' in params
        assert 'session_id' in params

        # session_id should be required (no default)
        session_id_param = sig.parameters['session_id']
        assert session_id_param.default is inspect.Parameter.empty

        # Should return UserContext (check annotation if present)
        if sig.return_annotation != inspect.Parameter.empty:
            assert sig.return_annotation == UserContext

    def test_get_user_context_can_be_called_without_await(self):
        """Test that get_user_context can be called synchronously without await."""
        # This test verifies the fix - that the method is sync, not async

        with patch('src.conversation.get_user_context') as mock_helper, \
             patch('src.conversation.CWEQueryHandler'), \
             patch('src.conversation.ResponseGenerator'), \
             patch('src.conversation.InputSanitizer'), \
             patch('src.conversation.SecurityValidator'), \
             patch('src.conversation.QueryProcessor'):

            # Mock the helper to return a UserContext
            mock_context = Mock(spec=UserContext)
            mock_context.session_id = None
            mock_helper.return_value = mock_context

            manager = ConversationManager("mock://db", "mock_key")

            # This should work WITHOUT await - this is the key test
            # Before the P0 fix, this would have been: await manager.get_user_context(...)
            result = manager.get_user_context("test_session")

            # Should return UserContext immediately (not a coroutine)
            assert isinstance(result, Mock)  # Our mock UserContext
            assert result == mock_context

    @patch('src.conversation.get_user_context')
    def test_get_user_context_sets_session_id_when_missing(self, mock_get_user_context):
        """Test that get_user_context sets session_id on context when missing."""
        # Mock context without session_id
        mock_context = Mock(spec=UserContext)
        mock_context.session_id = None  # Missing session_id
        mock_get_user_context.return_value = mock_context

        with patch('src.conversation.CWEQueryHandler'), \
             patch('src.conversation.ResponseGenerator'), \
             patch('src.conversation.InputSanitizer'), \
             patch('src.conversation.SecurityValidator'), \
             patch('src.conversation.QueryProcessor'):

            manager = ConversationManager("mock://db", "mock_key")
            result = manager.get_user_context("new_session_456")

            # Should have set the session_id
            assert mock_context.session_id == "new_session_456"

    @patch('src.conversation.get_user_context')
    def test_get_user_context_preserves_existing_session_id(self, mock_get_user_context):
        """Test that get_user_context preserves existing session_id on context."""
        # Mock context with existing session_id
        mock_context = Mock(spec=UserContext)
        mock_context.session_id = "existing_session"
        mock_get_user_context.return_value = mock_context

        with patch('src.conversation.CWEQueryHandler'), \
             patch('src.conversation.ResponseGenerator'), \
             patch('src.conversation.InputSanitizer'), \
             patch('src.conversation.SecurityValidator'), \
             patch('src.conversation.QueryProcessor'):

            manager = ConversationManager("mock://db", "mock_key")
            result = manager.get_user_context("different_session")

            # Should preserve the existing session_id
            assert mock_context.session_id == "existing_session"

    def test_method_is_public_api(self):
        """Test that get_user_context is part of the public API (not private)."""
        method_name = 'get_user_context'

        # Should not start with underscore (not private)
        assert not method_name.startswith('_')

        # Should be accessible as public method
        assert hasattr(ConversationManager, method_name)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])