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
from src.processing.query_processor import QueryProcessor
from src.utils.session import get_user_context

from src.app_config_extended import config

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

    def __init__(self, database_url: str, gemini_api_key: str):
        """
        Initialize conversation manager with required components.

        Args:
            database_url: Database connection string for CWE retrieval
            gemini_api_key: Gemini API key for embeddings and response generation
            context_manager: Optional user context manager (creates new if None)
        """
        try:
            # Initialize core components
            # no local context manager; state now lives in cl.user_session
            self.input_sanitizer = InputSanitizer()
            self.security_validator = SecurityValidator()
            self.query_handler = CWEQueryHandler(database_url, gemini_api_key)
            self.response_generator = ResponseGenerator(gemini_api_key)
            self.query_processor = QueryProcessor()

            # No local message storage; rely on Chainlit's built-in persistence

            logger.info("ConversationManager initialized successfully")

        except Exception as e:
            logger.log_exception("Failed to initialize ConversationManager", e)
            raise

    # -----------------------------
    # Per-user context via cl.user_session
    # -----------------------------
    def _get_or_create_user_context(self, session_id: str) -> UserContext:
        """Back-compat shim: use central session helper and bind session id if missing."""
        ctx = get_user_context()
        if not getattr(ctx, "session_id", None):
            ctx.session_id = session_id
        # Seed persona from top-bar ChatProfile if available (first touch only)
        try:
            selected_profile = cl.user_session.get("chat_profile")
            if isinstance(selected_profile, str) and selected_profile in UserPersona.get_all_personas():
                if ctx.persona != selected_profile:
                    ctx.persona = selected_profile
        except Exception:
            pass
        ctx.update_activity()
        return ctx

    async def process_user_message_streaming(
        self,
        session_id: str,
        message_content: str,
        message_id: str
    ) -> Dict[str, Any]:
        """
        Streaming wrapper that delegates core logic to a single path.
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
                message_type="user",
            )
            self._add_message(session_id, user_message)

            processed = self.query_processor.process_with_context(
                message_content, context.get_session_context_for_processing()
            )
            if processed.get("security_check", {}).get("is_potentially_malicious", False):
                flags = processed.get("security_check", {}).get("detected_patterns", [])
                fallback_response = self.input_sanitizer.generate_fallback_message(flags, context.persona)

                self.security_validator.log_security_event(
                    "unsafe_input_detected",
                    {"session_id": session_id, "security_flags": flags, "persona": context.persona},
                )

                msg = cl.Message(content=fallback_response)
                await msg.send()

                return {
                    "response": fallback_response,
                    "session_id": session_id,
                    "is_safe": False,
                    "security_flags": flags,
                    "retrieved_cwes": [],
                    "chunk_count": 0,
                    "retrieved_chunks": [],
                    "persona": context.persona,
                    "message": msg,
                }

            # Evidence
            file_ctx = cl.user_session.get("uploaded_file_context")
            if file_ctx and isinstance(file_ctx, str) and file_ctx.strip():
                context.set_evidence(file_ctx[:config.max_file_evidence_length])

            # Merge a brief attachment summary into the query to aid retrieval
            sanitized_q = processed.get("sanitized_query", message_content)
            combined_query = sanitized_q
            attachment_snippet = None
            if context.file_evidence:
                attachment_snippet = self._summarize_attachment(context.file_evidence)
                combined_query = f"{sanitized_q}\n\n[Attachment Summary]\n{attachment_snippet}"

            # Retrieve with combined query
            user_context_data = context.get_persona_preferences()
            retrieved_chunks = await self.query_handler.process_query(
                combined_query, user_context_data
            )

            # Create message and stream tokens
            msg = cl.Message(content="")
            await msg.send()
            collected = ""
            try:
                async for token in self.response_generator.generate_response_streaming(
                    combined_query,
                    retrieved_chunks or [],
                    context.persona,
                    user_evidence=context.file_evidence,
                ):
                    if token:  # Ensure token is not None or empty
                        try:
                            await msg.stream_token(token)
                            collected += str(token)  # Ensure token is string
                        except Exception as e:
                            logger.warning(f"Failed to stream token: {e}")
                            collected += str(token)  # Still collect token for processing
            except Exception as e:
                logger.error(f"Streaming generation failed: {e}")
                # Fallback to basic error response if streaming completely fails
                if not collected:
                    collected = self.response_generator._generate_error_response(context.persona)

            # Validate final and update if masked
            validation_result = self.security_validator.validate_response(collected)
            final_response = validation_result["validated_response"]
            if final_response != collected:
                msg.content = final_response
                await msg.update()

            retrieved_cwes = list(set(
                ch.get("metadata", {}).get("cwe_id") for ch in (retrieved_chunks or [])
            )) if retrieved_chunks else []

            # Record interaction directly on the per-user context
            context.add_conversation_entry(combined_query, final_response, retrieved_cwes)
            context.clear_evidence()

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
                    "security_validated": validation_result["is_safe"],
                },
            )
            self._add_message(session_id, assistant_message)

            return {
                "response": final_response,
                "session_id": session_id,
                "is_safe": validation_result["is_safe"],
                "retrieved_cwes": retrieved_cwes,
                "chunk_count": len(retrieved_chunks),
                "retrieved_chunks": retrieved_chunks,
                "persona": context.persona,
                "message": msg,
            }
        
        except Exception as e:
            return await self._handle_processing_error(session_id, e)

    # Non-streaming path removed (streaming-only)

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

    def _summarize_attachment(self, text: str, *, limit: int = None) -> str:
        """Create a brief, safe attachment summary for retrieval/context."""
        if not text:
            return ""
        if limit is None:
            limit = config.max_attachment_summary_length
        t = text.strip()
        if len(t) > limit:
            t = t[:limit] + "..."
        return t

    async def _handle_processing_error(self, session_id: str, error: Exception) -> Dict[str, Any]:
        """Handle processing errors with consistent response pattern."""
        logger.log_exception("Error processing message", error)
        error_response = "I apologize, but I'm experiencing technical difficulties. Please try your question again in a moment."

        msg = cl.Message(content=error_response)
        await msg.send()

        return {
            "response": error_response,
            "session_id": session_id,
            "is_safe": True,
            "error": str(error),
            "message": msg
        }

    # _process_message_core removed; streaming and non-stream paths call shared components directly
