#!/usr/bin/env python3
"""
Unit tests for UnifiedMessagePath - R16 Implementation
Tests the unified message entry point for all transports (REST, WS, CLI).
"""

import pytest
from datetime import datetime, timezone
from typing import Dict, Any
from unittest.mock import AsyncMock, MagicMock, patch

# Import will fail until we create the module - this is TDD RED phase
from src.messaging.unified import MessageIn, MessageOut, UnifiedMessagePath


class TestUnifiedMessagePath:
    """Test suite for UnifiedMessagePath unified entry point."""

    @pytest.fixture
    def mock_conversation_manager(self):
        """Create a mock ConversationManager for testing."""
        cm = MagicMock()
        cm.process_user_message = AsyncMock(
            return_value={
                "response": "Test response",
                "tokens_in": 10,
                "tokens_out": 20,
                "retrieved_cwes": ["CWE-79"],
                "chunk_count": 5,
                "citations": {"sources": ["CWE-79"]},
            }
        )
        return cm

    @pytest.fixture
    def unified_path(self, mock_conversation_manager):
        """Create UnifiedMessagePath instance with mocked CM."""
        return UnifiedMessagePath(mock_conversation_manager)

    @pytest.mark.asyncio
    async def test_process_empty_message_returns_blank_out(self, unified_path):
        """
        Test that empty messages are dropped gracefully.

        RED: This test will fail because UnifiedMessagePath doesn't exist yet.
        GREEN: Implement minimal code to return MessageOut with empty fields.
        """
        # Arrange
        msg_in = MessageIn(
            user_id="test_user",
            user_email="test@example.com",
            session_id="session_123",
            persona="Developer",
            text="",  # Empty text
            correlation_id="corr_123",
            transport="rest",
            metadata=None,
        )

        # Act
        result = await unified_path.process(msg_in)

        # Assert
        assert result.text == ""
        assert result.tokens_in == 0
        assert result.tokens_out == 0
        assert result.latency_ms == 0
        assert result.correlation_id == "corr_123"
        assert result.session_id == "session_123"

    @pytest.mark.asyncio
    async def test_process_whitespace_message_returns_blank_out(self, unified_path):
        """Test that whitespace-only messages are treated as empty."""
        # Arrange
        msg_in = MessageIn(
            user_id="test_user",
            user_email="test@example.com",
            session_id="session_123",
            persona="Developer",
            text="   \n\t  ",  # Only whitespace
            correlation_id="corr_456",
            transport="rest",
            metadata=None,
        )

        # Act
        result = await unified_path.process(msg_in)

        # Assert
        assert result.text == ""
        assert result.tokens_in == 0
        assert result.tokens_out == 0

    @pytest.mark.asyncio
    @patch("src.messaging.unified.app_config")
    async def test_process_truncates_per_config(
        self, mock_config, unified_path, mock_conversation_manager
    ):
        """
        Test that messages longer than max_user_chars are truncated.

        Verifies that config.max_user_chars is respected and long input is truncated.
        """
        # Arrange
        mock_config.max_user_chars = 100
        long_text = "A" * 200  # 200 chars, should be truncated to 100
        expected_truncated = "A" * 100

        msg_in = MessageIn(
            user_id="test_user",
            user_email="test@example.com",
            session_id="session_789",
            persona="Developer",
            text=long_text,
            correlation_id="corr_789",
            transport="rest",
            metadata=None,
        )

        # Act
        result = await unified_path.process(msg_in)

        # Assert - verify CM was called with truncated text
        mock_conversation_manager.process_user_message.assert_called_once()
        call_kwargs = mock_conversation_manager.process_user_message.call_args.kwargs
        assert call_kwargs["message_content"] == expected_truncated
        assert len(call_kwargs["message_content"]) == 100

    @pytest.mark.asyncio
    async def test_process_maps_tokens_and_citations(
        self, unified_path, mock_conversation_manager
    ):
        """
        Test that tokens, citations, and metadata are correctly mapped from CM response.

        Verifies the contract between UnifiedMessagePath and ConversationManager.
        """
        # Arrange
        expected_response = {
            "response": "CWE-79: Cross-site Scripting",
            "tokens_in": 15,
            "tokens_out": 45,
            "retrieved_cwes": ["CWE-79", "CWE-80"],
            "chunk_count": 8,
            "citations": {
                "sources": ["CWE-79", "CWE-80"],
                "confidence": 0.95,
            },
        }
        mock_conversation_manager.process_user_message.return_value = expected_response

        msg_in = MessageIn(
            user_id="test_user",
            user_email="test@example.com",
            session_id="session_abc",
            persona="PSIRT Member",
            text="What is XSS?",
            correlation_id="corr_abc",
            transport="ws",
            metadata={"source": "chainlit", "ui_version": "2.0"},
        )

        # Act
        result = await unified_path.process(msg_in)

        # Assert - verify all fields mapped correctly
        assert result.text == "CWE-79: Cross-site Scripting"
        assert result.tokens_in == 15
        assert result.tokens_out == 45
        assert result.citations == {"sources": ["CWE-79", "CWE-80"], "confidence": 0.95}
        assert result.session_id == "session_abc"
        assert result.persona == "PSIRT Member"
        assert result.correlation_id == "corr_abc"
        assert result.latency_ms >= 0  # Latency tracked (may be 0 for fast mocks)

    @pytest.mark.asyncio
    async def test_process_sets_correlation_id(self, unified_path):
        """Test that correlation ID is set in observability context."""
        # Arrange
        msg_in = MessageIn(
            user_id="test_user",
            user_email="test@example.com",
            session_id="session_123",
            persona="Developer",
            text="Test query",
            correlation_id="corr_unique_123",
            transport="rest",
            metadata=None,
        )

        # Act
        with patch("src.messaging.unified.set_correlation_id") as mock_set_corr:
            result = await unified_path.process(msg_in)

            # Assert
            mock_set_corr.assert_called_once_with("corr_unique_123")

    @pytest.mark.asyncio
    async def test_process_calls_cm_with_correct_params(
        self, unified_path, mock_conversation_manager
    ):
        """Test that ConversationManager is called with correct parameters."""
        # Arrange
        msg_in = MessageIn(
            user_id="user_456",
            user_email="user456@example.com",
            session_id="session_xyz",
            persona="Bug Bounty Hunter",
            text="Find SQL injection",
            correlation_id="corr_xyz",
            transport="cli",
            metadata={"cli_version": "1.2.3"},
        )

        # Act
        result = await unified_path.process(msg_in)

        # Assert - verify CM called with exact params
        mock_conversation_manager.process_user_message.assert_called_once_with(
            session_id="session_xyz",
            message_content="Find SQL injection",
        )

    @pytest.mark.asyncio
    async def test_process_handles_missing_optional_fields(
        self, unified_path, mock_conversation_manager
    ):
        """Test that missing optional fields (email, metadata) are handled gracefully."""
        # Arrange
        msg_in = MessageIn(
            user_id="anonymous",
            user_email=None,  # No email
            session_id="session_anon",
            persona=None,  # No persona
            text="Generic query",
            correlation_id="corr_anon",
            transport="rest",
            metadata=None,  # No metadata
        )

        # Act
        result = await unified_path.process(msg_in)

        # Assert - should still work with minimal fields
        assert result.text == "Test response"
        assert result.session_id == "session_anon"
        assert result.persona is None

    @pytest.mark.asyncio
    async def test_process_logs_structured_events(self, unified_path, caplog):
        """Test that structured logging captures key events with proper fields."""
        # Arrange
        msg_in = MessageIn(
            user_id="test_user",
            user_email="test@example.com",
            session_id="session_log",
            persona="Developer",
            text="Test logging",
            correlation_id="corr_log",
            transport="rest",
            metadata={"test": "data"},
        )

        # Act
        with caplog.at_level("INFO"):
            result = await unified_path.process(msg_in)

        # Assert - verify structured log entries
        log_messages = [record.message for record in caplog.records]
        assert any("Unified message received" in msg for msg in log_messages)
        assert any("Unified message completed" in msg for msg in log_messages)

    @pytest.mark.asyncio
    async def test_process_exception_propagates_with_logging(
        self, unified_path, mock_conversation_manager
    ):
        """Test that exceptions from CM are logged and propagated."""
        # Arrange
        mock_conversation_manager.process_user_message.side_effect = Exception(
            "CM failure"
        )

        msg_in = MessageIn(
            user_id="test_user",
            user_email="test@example.com",
            session_id="session_err",
            persona="Developer",
            text="Trigger error",
            correlation_id="corr_err",
            transport="rest",
            metadata=None,
        )

        # Act & Assert
        with pytest.raises(Exception, match="CM failure"):
            await unified_path.process(msg_in)
