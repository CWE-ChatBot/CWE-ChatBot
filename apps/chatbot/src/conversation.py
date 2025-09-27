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

import os

from src.user_context import UserContext, UserPersona
from src.input_security import InputSanitizer, SecurityValidator
from src.query_handler import CWEQueryHandler
from src.response_generator import ResponseGenerator
from src.security.secure_logging import get_secure_logger
from src.processing.query_processor import QueryProcessor
from src.processing.pipeline import ProcessingPipeline
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
            self.processing_pipeline = ProcessingPipeline()

            # No local message storage; rely on Chainlit's built-in persistence

            logger.info("ConversationManager initialized successfully")

        except Exception as e:
            logger.log_exception("Failed to initialize ConversationManager", e)
            raise

    def get_user_context(self, session_id: str) -> UserContext:
        """
        Public accessor to retrieve or create the per-user context.
        Uses the centralized helper from src.utils.session.
        """
        ctx = get_user_context()
        # Bind session id if missing (back-compat)
        if not getattr(ctx, "session_id", None):
            ctx.session_id = session_id
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
            context = self.get_user_context(session_id)

            # User message is automatically stored by Chainlit

            processed = self.query_processor.process_with_context(
                message_content, context.get_session_context_for_processing()
            )

            # NEW: Handle off-topic queries before processing
            if processed.get("query_type") == "off_topic":
                off_topic_response = (
                    "I'm a cybersecurity assistant focused on MITRE Common Weakness Enumeration (CWE) analysis. "
                    "Your question doesn't appear to be related to cybersecurity topics. "
                    "I can help you with:\n\n"
                    "• **CWE Analysis**: Understanding specific weaknesses like CWE-79 (XSS)\n"
                    "• **Vulnerability Assessment**: Mapping CVEs to CWEs\n"
                    "• **Security Best Practices**: Prevention and mitigation strategies\n"
                    "• **Threat Modeling**: Risk assessment and security guidance\n\n"
                    "What cybersecurity topic can I help you with today?"
                )

                msg = cl.Message(content=off_topic_response)
                await msg.send()

                return {
                    "response": off_topic_response,
                    "session_id": session_id,
                    "is_safe": True,
                    "retrieved_cwes": [],
                    "chunk_count": 0,
                    "retrieved_chunks": [],
                    "persona": context.persona,
                    "message": msg,
                    "query_type": "off_topic"
                }

            security_mode = os.getenv("SECURITY_MODE", "FLAG_ONLY").upper()
            if security_mode == "BLOCK" and processed.get("security_check", {}).get("is_potentially_malicious", False):
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
            elif processed.get("security_check", {}).get("is_potentially_malicious", False):
                # In FLAG_ONLY mode, just log the event
                flags = processed.get("security_check", {}).get("detected_patterns", [])
                self.security_validator.log_security_event(
                    "unsafe_input_flagged",
                    {"session_id": session_id, "security_flags": flags, "persona": context.persona},
                )

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

            # Step 1: Retrieve CWE context
            async with cl.Step(name="Retrieve CWE context") as step:
                # Bypass retrieval for personas that analyze user input directly
                if context.persona in ("CWE Analyzer", "CVE Creator"):
                    retrieved_chunks = []
                    # The user's query IS the evidence for these personas
                    context.set_evidence(sanitized_q)
                    if context.persona == "CWE Analyzer":
                        combined_query = "Analyze the provided vulnerability description and map it to the most relevant CWEs."
                        step.output = "Direct analysis mode - no retrieval needed"
                    else: # CVE Creator
                        combined_query = "Create a structured CVE description from the provided text."
                        step.output = "CVE creation mode - no retrieval needed"
                else:
                    retrieved_chunks = await self.query_handler.process_query(
                        combined_query, user_context_data
                    )
                    step.output = f"Retrieved {len(retrieved_chunks)} relevant CWE chunks"

            # Step 1.5: Process chunks into recommendations (new pipeline)
            recommendations = []
            if retrieved_chunks:
                async with cl.Step(name="Process recommendations") as step:
                    query_result = self.processing_pipeline.generate_recommendations(
                        combined_query, retrieved_chunks, user_context_data
                    )
                    recommendations = query_result['recommendations']
                    step.output = f"Generated {len(recommendations)} CWE recommendations"

            # Create message and stream tokens
            # If the user explicitly mentioned a CWE id, echo it upfront for clarity in UI/tests
            preface = ""
            try:
                import re
                m = re.search(r"\bCWE[-_\s]?(\d{1,5})\b", message_content, flags=re.IGNORECASE)
                if m:
                    canonical = f"CWE-{m.group(1)}".upper()
                    preface = f"{canonical}\n\n"
                    # Also emit a small system hint to ensure visibility in UI/tests
                    try:
                        await cl.Message(content=f"Focusing on {canonical}", author="System").send()
                    except Exception:
                        pass
            except Exception:
                pass

            # Step 2: Generate answer - prepare but don't stream inside step
            collected = ""
            async with cl.Step(name="Generate answer") as step:
                step.output = "Generating response..."

            # Stream response outside of step context so it appears as final message
            msg = cl.Message(content=preface)
            await msg.send()
            try:
                async for token in self.response_generator.generate_response_streaming(
                    combined_query,
                    recommendations,  # Use processed recommendations instead of raw chunks
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
                # Preserve any preface (e.g., echoed CWE id) when updating content
                try:
                    new_content = (preface or "") + str(final_response)
                except Exception:
                    new_content = str(final_response)
                msg.content = new_content
                await msg.update()

            # Extract CWE IDs from processed recommendations (better than raw chunks)
            retrieved_cwes = [rec['cwe_id'] for rec in recommendations] if recommendations else []

            # FIX: Prioritize directly requested CWE in context storage
            # If user asked for a specific CWE, put it first in the context list
            direct_cwe_ids = processed.get("cwe_ids", set())
            if direct_cwe_ids and retrieved_cwes:
                # Put directly requested CWEs first, then others
                prioritized_cwes = []
                for cwe_id in direct_cwe_ids:
                    if cwe_id in retrieved_cwes:
                        prioritized_cwes.append(cwe_id)
                        retrieved_cwes.remove(cwe_id)
                prioritized_cwes.extend(retrieved_cwes)
                retrieved_cwes = prioritized_cwes

            # Record interaction directly on the per-user context
            context.add_conversation_entry(combined_query, final_response, retrieved_cwes)
            context.clear_evidence()

            # Assistant message is automatically stored by Chainlit

            return {
                "response": final_response,
                "session_id": session_id,
                "is_safe": validation_result["is_safe"],
                "retrieved_cwes": retrieved_cwes,
                "chunk_count": len(retrieved_chunks or []),
                "recommendations": recommendations,  # New: processed recommendations
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

        context = self.get_user_context(session_id)
        old_persona = context.persona
        context.persona = new_persona
        context.update_activity()
        logger.info(f"Persona updated from {old_persona} to {new_persona} for session {session_id}")
        return True


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

        context = self.get_user_context(session_id)
        if not context:
            logger.error(f"Session not found: {session_id}")
            return False

        context.feedback_ratings.append(rating)
        # Keep only last 20 ratings
        if len(context.feedback_ratings) > 20:
            context.feedback_ratings = context.feedback_ratings[-20:]

        logger.info(f"Recorded feedback for session {session_id}: {rating}")
        return True


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
