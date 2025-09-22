#!/usr/bin/env python3
"""
Conversation Management - Story 2.1
Manages conversation flow, session state, and message handling for Chainlit integration.
"""

import logging
from typing import Dict, List, Any, Optional, AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime, timezone
import asyncio
import chainlit as cl

from src.user_context import UserContext, UserPersona
from src.input_security import InputSanitizer, SecurityValidator
from src.query_handler import CWEQueryHandler
from src.response_generator import ResponseGenerator
from src.security.secure_logging import get_secure_logger

logger = get_secure_logger(__name__)


@dataclass
class ConversationMessage:
    """Represents a single message in the conversation."""

    message_id: str
    session_id: str
    content: str
    message_type: str  # 'user', 'assistant', 'system'
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
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
        context_manager: Optional[Any] = None  # kept for backward-compat; no longer used
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
            self.context_manager = context_manager  # deprecated; state now in cl.user_session
            self.input_sanitizer = InputSanitizer()
            self.security_validator = SecurityValidator()
            self.query_handler = CWEQueryHandler(database_url, gemini_api_key)
            self.response_generator = ResponseGenerator(gemini_api_key)

            # No local message storage; rely on Chainlit's built-in persistence

            logger.info("ConversationManager initialized successfully")

        except Exception as e:
            logger.log_exception("Failed to initialize ConversationManager", e)
            raise

    # -----------------------------
    # Per-user context via cl.user_session
    # -----------------------------
    def _get_or_create_user_context(self, session_id: str) -> UserContext:
        """
        Retrieve the UserContext from cl.user_session, creating it if missing.
        Always binds the provided Chainlit session_id onto the context.
        """
        ctx: Optional[UserContext] = cl.user_session.get("user_context")
        if not ctx:
            ctx = UserContext()
            ctx.session_id = session_id
            cl.user_session.set("user_context", ctx)
            logger.info(f"Created new UserContext in user_session for session {session_id}")
        else:
            ctx.update_activity()
        return ctx

    async def process_user_message_streaming(
        self,
        session_id: str,
        message_content: str,
        message_id: str
    ) -> Dict[str, Any]:
        """
        Process user message and generate streaming response.

        Args:
            session_id: Chainlit session ID
            message_content: User's message content
            message_id: Unique message identifier

        Returns:
            Dictionary containing response metadata and message reference
        """
        try:
            logger.info(f"Processing streaming message for session {session_id}")

            # Get or create user context in cl.user_session
            context = self._get_or_create_user_context(session_id)

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

                # Send non-streaming fallback
                msg = cl.Message(content=fallback_response)
                await msg.send()

                return {
                    "response": fallback_response,
                    "session_id": session_id,
                    "is_safe": False,
                    "security_flags": sanitization_result["security_flags"],
                    "message": msg
                }

            sanitized_query = sanitization_result["sanitized_input"]

            # Validate CWE relevance (pass persona for context-specific validation)
            if not self.input_sanitizer.validate_cwe_context(sanitized_query, context.persona):
                fallback_response = self.input_sanitizer.generate_fallback_message(
                    ["non_cwe_query"],
                    context.persona
                )

                msg = cl.Message(content=fallback_response)
                await msg.send()

                return {
                    "response": fallback_response,
                    "session_id": session_id,
                    "is_safe": True,
                    "is_cwe_relevant": False,
                    "message": msg
                }

            # Handle CVE Creator differently - it doesn't need CWE database retrieval
            if context.persona == "CVE Creator":
                # CVE Creator works directly with user-provided vulnerability information
                async with cl.Step(name="Generate CVE Response", type="llm") as generate_step:
                    generate_step.input = f"Generating CVE analysis for: {sanitized_query[:100]}..."

                    # Create streaming message
                    msg = cl.Message(content="")
                    await msg.send()

                    response = await self.response_generator.generate_response_streaming(
                        sanitized_query,
                        [],  # Empty chunks - CVE Creator doesn't use CWE database
                        context.persona,
                        msg
                    )

                    generate_step.output = f"Generated CVE response ({len(response)} characters)"

                retrieved_chunks = []
            else:
                # Process query using hybrid retrieval for other personas
                async with cl.Step(name="Retrieve CWE Information", type="retrieval") as retrieval_step:
                    retrieval_step.input = f"Searching CWE database for: {sanitized_query[:100]}..."

                    user_context_data = context.get_persona_preferences()
                    retrieved_chunks = await self.query_handler.process_query(
                        sanitized_query,
                        user_context_data
                    )

                    if retrieved_chunks:
                        retrieved_cwes = list(set(chunk["metadata"]["cwe_id"] for chunk in retrieved_chunks))
                        retrieval_step.output = f"Found {len(retrieved_chunks)} relevant chunks from CWEs: {', '.join(retrieved_cwes[:5])}{'...' if len(retrieved_cwes) > 5 else ''}"
                    else:
                        retrieval_step.output = "No relevant CWE information found"

                if not retrieved_chunks:
                    # No relevant information found
                    fallback_response = self.response_generator._generate_fallback_response(
                        sanitized_query,
                        context.persona
                    )

                    msg = cl.Message(content=fallback_response)
                    await msg.send()

                    return {
                        "response": fallback_response,
                        "session_id": session_id,
                        "is_safe": True,
                        "retrieved_chunks": 0,
                        "message": msg
                    }

                # Generate persona-specific response with streaming
                async with cl.Step(name="Generate Response", type="llm") as generate_step:
                    generate_step.input = f"Generating {context.persona} response using {len(retrieved_chunks)} CWE chunks"

                    # Create streaming message
                    msg = cl.Message(content="")
                    await msg.send()

                    response = await self.response_generator.generate_response_streaming(
                        sanitized_query,
                        retrieved_chunks,
                        context.persona,
                        msg
                    )

                    generate_step.output = f"Generated response ({len(response)} characters) for {context.persona}"

            # Validate response security
            validation_result = self.security_validator.validate_response(response)
            final_response = validation_result["validated_response"]

            # Extract CWEs for context tracking
            retrieved_cwes = list(set(
                chunk["metadata"]["cwe_id"] for chunk in retrieved_chunks
            ))

            # Record interaction directly on the per-user context
            context.add_conversation_entry(sanitized_query, final_response, retrieved_cwes)

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
                "retrieved_chunks": retrieved_chunks,  # Include chunks for source elements
                "persona": context.persona,
                "message": msg
            }

        except Exception as e:
            logger.log_exception("Error processing streaming message", e)
            error_response = "I apologize, but I'm experiencing technical difficulties. Please try your question again in a moment."

            msg = cl.Message(content=error_response)
            await msg.send()

            return {
                "response": error_response,
                "session_id": session_id,
                "is_safe": True,
                "error": str(e),
                "message": msg
            }

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

            # Get or create user context in cl.user_session
            context = self._get_or_create_user_context(session_id)

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
                async with cl.Step(name="Generate CVE Response", type="llm") as generate_step:
                    generate_step.input = f"Generating CVE analysis for: {sanitized_query[:100]}..."

                    response = await self.response_generator.generate_response(
                        sanitized_query,
                        [],  # Empty chunks - CVE Creator doesn't use CWE database
                        context.persona
                    )

                    generate_step.output = f"Generated CVE response ({len(response)} characters)"

                retrieved_chunks = []
            else:
                # Process query using hybrid retrieval for other personas
                async with cl.Step(name="Retrieve CWE Information", type="retrieval") as retrieval_step:
                    retrieval_step.input = f"Searching CWE database for: {sanitized_query[:100]}..."

                    user_context_data = context.get_persona_preferences()
                    retrieved_chunks = await self.query_handler.process_query(
                        sanitized_query,
                        user_context_data
                    )

                    if retrieved_chunks:
                        retrieved_cwes = list(set(chunk["metadata"]["cwe_id"] for chunk in retrieved_chunks))
                        retrieval_step.output = f"Found {len(retrieved_chunks)} relevant chunks from CWEs: {', '.join(retrieved_cwes[:5])}{'...' if len(retrieved_cwes) > 5 else ''}"
                    else:
                        retrieval_step.output = "No relevant CWE information found"

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
                async with cl.Step(name="Generate Response", type="llm") as generate_step:
                    generate_step.input = f"Generating {context.persona} response using {len(retrieved_chunks)} CWE chunks"

                    response = await self.response_generator.generate_response(
                        sanitized_query,
                        retrieved_chunks,
                        context.persona
                    )

                    generate_step.output = f"Generated response ({len(response)} characters) for {context.persona}"

            # Validate response security
            validation_result = self.security_validator.validate_response(response)
            final_response = validation_result["validated_response"]
            # If validation altered the streamed content, update the message with the final text
            try:
                if 'msg' in locals() and final_response != response:
                    msg.content = final_response
                    await msg.update()
            except Exception as upd_err:
                logger.log_exception("Failed to update streamed message after validation", upd_err)

            # Extract CWEs for context tracking
            retrieved_cwes = list(set(
                chunk["metadata"]["cwe_id"] for chunk in retrieved_chunks
            ))

            # Record interaction directly on the per-user context
            context.add_conversation_entry(sanitized_query, final_response, retrieved_cwes)

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
                "retrieved_chunks": retrieved_chunks,  # Include chunks for source elements
                "persona": context.persona
            }

        except Exception as e:
            logger.log_exception("Error processing message", e)
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

        context = self._get_or_create_user_context(session_id)
        old_persona = context.persona
        context.persona = new_persona
        context.update_activity()
        # Add system message about persona change
        system_message = ConversationMessage(
            message_id=f"persona_change_{datetime.now(timezone.utc).timestamp()}",
            session_id=session_id,
            content=f"Persona updated to: {new_persona}",
            message_type="system",
            metadata={"persona_change": True, "new_persona": new_persona, "old_persona": old_persona}
        )
        self._add_message(session_id, system_message)
        return True

    def get_conversation_history(self, session_id: str, limit: int = 20) -> List[ConversationMessage]:
        """
        Get conversation history for a session.

        Args:
            session_id: Session identifier
            limit: Maximum number of messages to return

        Returns:
            List of conversation messages
        """
        # Chainlit UI shows persisted history; avoid duplicating storage here.
        return []

    def get_session_context(self, session_id: str) -> Optional[UserContext]:
        """
        Get user context for a session.

        Args:
            session_id: Session identifier

        Returns:
            UserContext if found, None otherwise
        """
        return cl.user_session.get("user_context")

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

        context = self._get_or_create_user_context(session_id)
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
        # cl.user_session is per-connection; nothing to clean here
        return 0

    def get_system_health(self) -> Dict[str, Any]:
        """
        Get system health information.

        Returns:
            System health status
        """
        health: Dict[str, Any] = self.query_handler.health_check()
        # Per-user data now lives in cl.user_session; global counts are not available here
        health.update({
            "active_sessions": None,
            "persona_distribution": {}
        })
        return health

    def _add_message(self, session_id: str, message: ConversationMessage) -> None:
        """No-op for local storage; Chainlit persists messages in its data layer."""
        logger.debug(f"Message recorded (type={message.message_type}) for session {session_id}")
