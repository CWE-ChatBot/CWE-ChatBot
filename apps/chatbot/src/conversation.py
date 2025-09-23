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
        # Seed persona from stored UI settings if available (first touch only)
        try:
            ui_settings = cl.user_session.get("ui_settings") or {}
            persona = ui_settings.get("persona")
            if persona and ctx.persona != persona:
                ctx.persona = persona
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

            core = await self._process_message_core(message_content)
            if core.get("status") == "blocked":
                flags = core.get("reasons", [])
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

            retrieved_chunks = list(core.get("retrieval") or [])
            response = core.get("response", "")

            # Validate and send once
            validation_result = self.security_validator.validate_response(response)
            final_response = validation_result["validated_response"] if validation_result["is_safe"] else response

            msg = cl.Message(content=final_response)
            await msg.send()

            retrieved_cwes = list(set(
                ch.get("metadata", {}).get("cwe_id") for ch in (retrieved_chunks or [])
            )) if retrieved_chunks else []

            # Record interaction directly on the per-user context
            context.add_conversation_entry(message_content, final_response, retrieved_cwes)

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
        Non-streaming wrapper that delegates to the core path.
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
                message_type="user",
            )
            self._add_message(session_id, user_message)

            core = await self._process_message_core(message_content)
            if core.get("status") == "blocked":
                flags = core.get("reasons", [])
                fallback_response = self.input_sanitizer.generate_fallback_message(flags, context.persona)
                return {
                    "response": fallback_response,
                    "session_id": session_id,
                    "is_safe": False,
                    "security_flags": flags,
                }

            response = core.get("response", "")
            retrieved_chunks = list(core.get("retrieval") or [])

            # Validate response security
            validation_result = self.security_validator.validate_response(response)
            final_response = validation_result["validated_response"]

            # Extract CWEs for context tracking
            retrieved_cwes = list(set(
                ch.get("metadata", {}).get("cwe_id") for ch in (retrieved_chunks or [])
            )) if retrieved_chunks else []

            # Record interaction directly on the per-user context
            context.add_conversation_entry(message_content, final_response, retrieved_cwes)

            return {
                "response": final_response,
                "session_id": session_id,
                "is_safe": validation_result["is_safe"],
                "retrieved_cwes": retrieved_cwes,
                "chunk_count": len(retrieved_chunks) if retrieved_chunks else 0,
                "retrieved_chunks": retrieved_chunks,  # Include chunks for source elements
                "persona": context.persona,
            }

        except Exception as e:
            logger.log_exception("Error processing message", e)
            error_response = "I apologize, but I'm experiencing technical difficulties. Please try your question again in a moment."

            return {
                "response": error_response,
                "session_id": session_id,
                "is_safe": True,
                "error": str(e),
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

    async def _process_message_core(self, message_content: str) -> Dict[str, Any]:
        """
        Unified core logic for processing a user message. Handles:
        - Input sanitization via QueryProcessor
        - Retrieval via QueryHandler
        - Optional evidence pseudo-chunk
        - Non-stream generation via ResponseGenerator
        Returns a normalized dict for both streaming and non-streaming wrappers.
        """
        ctx = get_user_context()
        processed = self.query_processor.process_with_context(
            message_content, ctx.get_session_context_for_processing()
        )

        sec = processed.get("security_check", {})
        is_safe = not sec.get("is_potentially_malicious", False)
        reasons = sec.get("detected_patterns", [])
        if not is_safe:
            return {"status": "blocked", "reasons": reasons}

        q = processed.get("sanitized_query", message_content)
        retrieval = await self.query_handler.process_query(q, ctx.get_persona_preferences())

        # Attach evidence pseudo-chunk if present
        file_ctx = cl.user_session.get("uploaded_file_context")
        evidence_chunk = None
        if file_ctx:
            file_ctx = f"<<FILE_CONTEXT_START>>\n{file_ctx}\n<<FILE_CONTEXT_END>>"
            evidence_chunk = {
                "document": file_ctx,
                "metadata": {"cwe_id": "EVIDENCE", "name": "Uploaded Evidence", "section": "Evidence"},
                "scores": {"hybrid": 0.01},
            }
        if not retrieval and evidence_chunk:
            retrieval = [evidence_chunk]
        elif retrieval and evidence_chunk:
            retrieval = list(retrieval) + [evidence_chunk]

        # Generate once (non-stream) for core path
        gen_text = await self.response_generator.generate_response(q, retrieval or [], ctx.persona)
        return {
            "status": "ok",
            "retrieval": retrieval or [],
            "response": gen_text,
            "meta": {"sanitized_query": q},
        }
