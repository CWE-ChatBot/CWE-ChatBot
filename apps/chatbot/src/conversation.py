#!/usr/bin/env python3
"""
Conversation Management - Story 2.1
Manages conversation flow, session state, and message handling for Chainlit integration.
"""

import logging
from typing import Dict, List, Any, Optional, AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime
import asyncio
import chainlit as cl

from user_context import UserContextManager, UserContext, UserPersona
from input_security import InputSanitizer, SecurityValidator
from query_handler import CWEQueryHandler
from response_generator import ResponseGenerator

logger = logging.getLogger(__name__)


@dataclass
class ConversationMessage:
    """Represents a single message in the conversation."""

    message_id: str
    session_id: str
    content: str
    message_type: str  # 'user', 'assistant', 'system'
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ConversationManager:
    """
    Manages conversation flow and integration with Chainlit.

    Handles:
    - Message processing and response generation
    - Session state management
    - Integration with query handler and response generator
    - Security validation and input sanitization
    - Error handling and graceful degradation
    """

    def __init__(
        self,
        database_url: str,
        gemini_api_key: str,
        context_manager: Optional[UserContextManager] = None
    ):
        """
        Initialize conversation manager with required components.

        Args:
            database_url: Database connection string for CWE retrieval
            gemini_api_key: Gemini API key for embeddings and response generation
            context_manager: Optional user context manager (creates new if None)
        """
        try:
            # Initialize core components
            self.context_manager = context_manager or UserContextManager()
            self.input_sanitizer = InputSanitizer()
            self.security_validator = SecurityValidator()
            self.query_handler = CWEQueryHandler(database_url, gemini_api_key)
            self.response_generator = ResponseGenerator(gemini_api_key)

            # Message storage for current session
            self.conversation_messages: Dict[str, List[ConversationMessage]] = {}

            logger.info("ConversationManager initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize ConversationManager: {e}")
            raise

    async def process_user_message(
        self,
        session_id: str,
        message_content: str,
        message_id: str
    ) -> Dict[str, Any]:
        """
        Process user message and generate response.

        Args:
            session_id: Chainlit session ID
            message_content: User's message content
            message_id: Unique message identifier

        Returns:
            Dictionary containing response and metadata
        """
        try:
            logger.info(f"Processing message for session {session_id}")

            # Get or create user context
            context = self.context_manager.get_session(session_id)
            if not context:
                # Create new session with default persona
                context = self.context_manager.create_session()
                session_id = context.session_id
                logger.info(f"Created new session {session_id}")

            # Store user message
            user_message = ConversationMessage(
                message_id=message_id,
                session_id=session_id,
                content=message_content,
                message_type="user"
            )
            self._add_message(session_id, user_message)

            # Sanitize input (pass persona for context-specific handling)
            sanitization_result = self.input_sanitizer.sanitize_input(message_content, context.persona)

            if not sanitization_result["is_safe"]:
                # Generate fallback response for unsafe input
                fallback_response = self.input_sanitizer.generate_fallback_message(
                    sanitization_result["security_flags"],
                    context.persona
                )

                # Log security event
                self.security_validator.log_security_event(
                    "unsafe_input_detected",
                    {
                        "session_id": session_id,
                        "security_flags": sanitization_result["security_flags"],
                        "persona": context.persona
                    }
                )

                return {
                    "response": fallback_response,
                    "session_id": session_id,
                    "is_safe": False,
                    "security_flags": sanitization_result["security_flags"]
                }

            sanitized_query = sanitization_result["sanitized_input"]

            # Validate CWE relevance (pass persona for context-specific validation)
            if not self.input_sanitizer.validate_cwe_context(sanitized_query, context.persona):
                fallback_response = self.input_sanitizer.generate_fallback_message(
                    ["non_cwe_query"],
                    context.persona
                )
                return {
                    "response": fallback_response,
                    "session_id": session_id,
                    "is_safe": True,
                    "is_cwe_relevant": False
                }

            # Handle CVE Creator differently - it doesn't need CWE database retrieval
            if context.persona == "CVE Creator":
                # CVE Creator works directly with user-provided vulnerability information
                response = await self.response_generator.generate_response(
                    sanitized_query,
                    [],  # Empty chunks - CVE Creator doesn't use CWE database
                    context.persona
                )
                retrieved_chunks = []
            else:
                # Process query using hybrid retrieval for other personas
                user_context_data = context.get_persona_preferences()
                retrieved_chunks = await self.query_handler.process_query(
                    sanitized_query,
                    user_context_data
                )

                if not retrieved_chunks:
                    # No relevant information found
                    fallback_response = self.response_generator._generate_fallback_response(
                        sanitized_query,
                        context.persona
                    )
                    return {
                        "response": fallback_response,
                        "session_id": session_id,
                        "is_safe": True,
                        "retrieved_chunks": 0
                    }

                # Generate persona-specific response
                response = await self.response_generator.generate_response(
                    sanitized_query,
                    retrieved_chunks,
                    context.persona
                )

            # Validate response security
            validation_result = self.security_validator.validate_response(response)
            final_response = validation_result["validated_response"]

            # Extract CWEs for context tracking
            retrieved_cwes = list(set(
                chunk["metadata"]["cwe_id"] for chunk in retrieved_chunks
            ))

            # Record interaction
            self.context_manager.record_interaction(
                session_id,
                sanitized_query,
                final_response,
                retrieved_cwes
            )

            # Store assistant message
            assistant_message = ConversationMessage(
                message_id=f"{message_id}_response",
                session_id=session_id,
                content=final_response,
                message_type="assistant",
                metadata={
                    "retrieved_cwes": retrieved_cwes,
                    "chunk_count": len(retrieved_chunks),
                    "persona": context.persona,
                    "security_validated": validation_result["is_safe"]
                }
            )
            self._add_message(session_id, assistant_message)

            return {
                "response": final_response,
                "session_id": session_id,
                "is_safe": validation_result["is_safe"],
                "retrieved_cwes": retrieved_cwes,
                "chunk_count": len(retrieved_chunks),
                "persona": context.persona
            }

        except Exception as e:
            logger.error(f"Error processing message: {e}")
            error_response = "I apologize, but I'm experiencing technical difficulties. Please try your question again in a moment."

            return {
                "response": error_response,
                "session_id": session_id,
                "is_safe": True,
                "error": str(e)
            }

    async def update_user_persona(self, session_id: str, new_persona: str) -> bool:
        """
        Update user persona for the session.

        Args:
            session_id: Session identifier
            new_persona: New persona to set

        Returns:
            True if successful, False otherwise
        """
        if not UserPersona.is_valid_persona(new_persona):
            logger.error(f"Invalid persona: {new_persona}")
            return False

        success = self.context_manager.update_persona(session_id, new_persona)
        if success:
            # Add system message about persona change
            system_message = ConversationMessage(
                message_id=f"persona_change_{datetime.now().timestamp()}",
                session_id=session_id,
                content=f"Persona updated to: {new_persona}",
                message_type="system",
                metadata={"persona_change": True, "new_persona": new_persona}
            )
            self._add_message(session_id, system_message)

        return success

    def get_conversation_history(self, session_id: str, limit: int = 20) -> List[ConversationMessage]:
        """
        Get conversation history for a session.

        Args:
            session_id: Session identifier
            limit: Maximum number of messages to return

        Returns:
            List of conversation messages
        """
        messages = self.conversation_messages.get(session_id, [])
        return messages[-limit:] if limit else messages

    def get_session_context(self, session_id: str) -> Optional[UserContext]:
        """
        Get user context for a session.

        Args:
            session_id: Session identifier

        Returns:
            UserContext if found, None otherwise
        """
        return self.context_manager.get_session(session_id)

    def record_feedback(self, session_id: str, message_id: str, rating: int) -> bool:
        """
        Record user feedback for a specific message.

        Args:
            session_id: Session identifier
            message_id: Message identifier
            rating: Feedback rating (1-5)

        Returns:
            True if recorded successfully, False otherwise
        """
        if not (1 <= rating <= 5):
            logger.error(f"Invalid rating: {rating}")
            return False

        context = self.context_manager.get_session(session_id)
        if not context:
            logger.error(f"Session not found: {session_id}")
            return False

        context.feedback_ratings.append(rating)
        # Keep only last 20 ratings
        if len(context.feedback_ratings) > 20:
            context.feedback_ratings = context.feedback_ratings[-20:]

        logger.info(f"Recorded feedback for session {session_id}: {rating}")
        return True

    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions and associated conversation data.

        Returns:
            Number of sessions cleaned up
        """
        # Get expired session IDs before cleanup
        expired_count = self.context_manager.cleanup_expired_sessions()

        # Clean up conversation messages for expired sessions
        active_session_ids = set(self.context_manager.active_sessions.keys())
        expired_message_sessions = [
            session_id for session_id in self.conversation_messages.keys()
            if session_id not in active_session_ids
        ]

        for session_id in expired_message_sessions:
            del self.conversation_messages[session_id]

        return expired_count

    def get_system_health(self) -> Dict[str, Any]:
        """
        Get system health information.

        Returns:
            System health status
        """
        health = self.query_handler.health_check()
        health.update({
            "active_sessions": self.context_manager.get_active_session_count(),
            "persona_distribution": self.context_manager.get_persona_distribution(),
            "total_conversations": sum(
                len(messages) for messages in self.conversation_messages.values()
            )
        })

        return health

    def _add_message(self, session_id: str, message: ConversationMessage):
        """Add message to conversation history."""
        if session_id not in self.conversation_messages:
            self.conversation_messages[session_id] = []

        self.conversation_messages[session_id].append(message)

        # Keep only last 50 messages per session for memory efficiency
        if len(self.conversation_messages[session_id]) > 50:
            self.conversation_messages[session_id] = self.conversation_messages[session_id][-50:]