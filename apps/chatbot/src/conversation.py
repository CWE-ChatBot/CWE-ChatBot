#!/usr/bin/env python3
"""
Conversation Management - Story 2.1
Manages conversation flow, session state, and message handling for Chainlit integration.
"""

from typing import TYPE_CHECKING, Any, Dict, Optional

try:
    from sqlalchemy.engine import Engine
except ImportError:
    Engine = None

if TYPE_CHECKING:
    from src.processing.pipeline import PipelineResult
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

import chainlit as cl

from src.app_config import config
from src.input_security import InputSanitizer, SecurityValidator
from src.processing.pipeline import ProcessingPipeline
from src.processing.query_processor import QueryProcessor
from src.query_handler import CWEQueryHandler
from src.response_generator import ResponseGenerator
from src.security.secure_logging import get_secure_logger
from src.user_context import UserContext, UserPersona
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
        self, database_url: str, gemini_api_key: str, engine: Optional[Any] = None
    ):
        """
        Initialize conversation manager with required components.

        Args:
            database_url: Database connection string for CWE retrieval
            gemini_api_key: Gemini API key for embeddings and response generation
            engine: Optional SQLAlchemy engine for Cloud SQL Connector (Cloud Run mode)
        """
        try:
            # Initialize core components
            # no local context manager; state now lives in cl.user_session
            self.input_sanitizer = InputSanitizer()
            self.security_validator = SecurityValidator()
            self.query_handler = CWEQueryHandler(
                database_url, gemini_api_key, engine=engine
            )
            self.response_generator = ResponseGenerator(gemini_api_key)
            self.query_processor = QueryProcessor()

            # Initialize pipeline with dependencies for end-to-end processing
            self.processing_pipeline = ProcessingPipeline(
                self.query_handler, self.response_generator
            )

            # Initialize analyzer handler for CWE Analyzer persona
            from src.processing.analyzer_handler import AnalyzerModeHandler

            self.analyzer_handler = AnalyzerModeHandler(self.processing_pipeline)

            # No local message storage; rely on Chainlit's built-in persistence

            logger.info("ConversationManager initialized successfully")

        except Exception as e:
            logger.log_exception("Failed to initialize ConversationManager", e)
            raise

    # -----------------------------
    # Lightweight helpers
    # Method moved to AnalyzerModeHandler for better separation of concerns

    def get_user_context(self, session_id: str) -> UserContext:
        """
        Public accessor to retrieve or create the per-user context.

        For WebSocket sessions: Uses Chainlit's session storage
        For API sessions: Creates ephemeral context without Chainlit dependency
        """
        # Check if we're in a Chainlit WebSocket context
        try:
            import chainlit as cl

            # Try to access Chainlit context - will raise ChainlitContextException if not available
            _ = cl.user_session
            # WebSocket context available, use normal session storage
            ctx = get_user_context()
            if not getattr(ctx, "session_id", None):
                ctx.session_id = session_id
            return ctx
        except Exception:
            # No Chainlit context (API call) - create ephemeral context
            if not hasattr(self, "session_contexts"):
                self.session_contexts: Dict[str, UserContext] = {}
            if session_id not in self.session_contexts:
                ctx = UserContext()
                ctx.session_id = session_id
                self.session_contexts[session_id] = ctx
            return self.session_contexts[session_id]

    async def process_user_message_streaming(
        self, session_id: str, message_content: str, message_id: str
    ) -> Dict[str, Any]:
        """
        Simplified orchestration - delegates to specialized handlers.

        This method now serves as a pure orchestrator, delegating complex business
        logic to the ProcessingPipeline and specialized persona handlers.
        """
        try:
            logger.info(f"Processing streaming message for session {session_id}")

            # Get user context
            context = self.get_user_context(session_id)

            # Process query and security checks
            processed = self.query_processor.process_with_context(
                message_content, context.get_session_context_for_processing()
            )

            # Handle off-topic queries
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
                return self._build_response_dict(
                    off_topic_response, session_id, msg, context
                )

            # Security validation
            security_mode = os.getenv("SECURITY_MODE", "FLAG_ONLY").upper()
            if security_mode == "BLOCK" and processed.get("security_check", {}).get(
                "is_potentially_malicious", False
            ):
                flags = processed.get("security_check", {}).get("detected_patterns", [])
                fallback_response = self.input_sanitizer.generate_fallback_message(
                    flags, context.persona
                )

                self.security_validator.log_security_event(
                    "unsafe_input_detected",
                    {
                        "session_id": session_id,
                        "security_flags": flags,
                        "persona": context.persona,
                    },
                )

                msg = cl.Message(content=fallback_response)
                await msg.send()
                return self._build_response_dict(
                    fallback_response,
                    session_id,
                    msg,
                    context,
                    is_safe=False,
                    security_flags=flags,
                )

            elif processed.get("security_check", {}).get(
                "is_potentially_malicious", False
            ):
                # In FLAG_ONLY mode, just log the event
                flags = processed.get("security_check", {}).get("detected_patterns", [])
                self.security_validator.log_security_event(
                    "unsafe_input_flagged",
                    {
                        "session_id": session_id,
                        "security_flags": flags,
                        "persona": context.persona,
                    },
                )

            # Handle /exit command for analyzer modes
            if (
                hasattr(context, "analyzer_mode")
                and context.analyzer_mode
                and message_content.strip().lower() == "/exit"
            ):
                context.analyzer_mode = None
                from src.utils.session import set_user_context

                set_user_context(context)

                exit_response = "✅ **Exited analyzer mode.** You can now ask general CWE questions or start a new analysis."
                msg = cl.Message(content=exit_response)
                await msg.send()
                return self._build_response_dict(
                    exit_response, session_id, msg, context
                )

            # Set file evidence if present
            file_ctx = cl.user_session.get("uploaded_file_context")
            if file_ctx and isinstance(file_ctx, str) and file_ctx.strip():
                context.set_evidence(file_ctx[: config.max_file_evidence_length])

            sanitized_q = processed.get("sanitized_query", message_content)

            # Delegate to appropriate handler
            if context.persona == "CWE Analyzer":
                pipeline_result = await self.analyzer_handler.process(
                    sanitized_q, context
                )
            elif context.persona == "CVE Creator":
                # Keep existing CVE Creator logic - could be extracted to separate handler in future
                pipeline_result = await self._handle_cve_creator(sanitized_q, context)
            else:
                # Standard personas use pipeline directly
                pipeline_result = await self.processing_pipeline.process_user_request(
                    sanitized_q, context
                )

            # Handle mode switches (no streaming needed)
            if pipeline_result.metadata.get("mode_switch"):
                msg = cl.Message(content=pipeline_result.final_response_text)
                await msg.send()
                return self._build_response_dict_from_pipeline(
                    pipeline_result, session_id, msg, context
                )

            # Stream the final response
            msg = cl.Message(content="")
            await msg.send()

            try:
                # Stream the validated response token by token
                for char in pipeline_result.final_response_text:
                    await msg.stream_token(char)
            except Exception as e:
                logger.error(f"Streaming failed: {e}")
                msg.content = pipeline_result.final_response_text
                await msg.update()

            # Update context and return
            context.add_conversation_entry(
                sanitized_q,
                pipeline_result.final_response_text,
                pipeline_result.retrieved_cwes,
            )
            context.clear_evidence()

            return self._build_response_dict_from_pipeline(
                pipeline_result, session_id, msg, context
            )

        except Exception as e:
            return await self._handle_processing_error(session_id, e)

    async def process_user_message(
        self, session_id: str, message_content: str
    ) -> Dict[str, Any]:
        """
        Non-streaming version for REST API usage (no Chainlit context required).

        Processes user message without streaming, suitable for programmatic access
        via REST API where WebSocket context is not available.

        Args:
            session_id: Ephemeral session identifier
            message_content: User's query text

        Returns:
            Dict with response text, retrieved CWEs, chunk count, and metadata
        """
        try:
            logger.info(f"Processing API message for session {session_id}")

            # Get user context
            context = self.get_user_context(session_id)

            # Process query and security checks
            processed = self.query_processor.process_with_context(
                message_content, context.get_session_context_for_processing()
            )

            # Handle off-topic queries
            if processed.get("query_type") == "off_topic":
                off_topic_response = (
                    "I'm a cybersecurity assistant focused on MITRE Common Weakness Enumeration (CWE) analysis. "
                    "Your question doesn't appear to be related to cybersecurity topics."
                )
                return {
                    "response": off_topic_response,
                    "retrieved_cwes": [],
                    "chunk_count": 0,
                    "session_id": session_id,
                    "message": None,
                }

            # Security validation
            security_mode = os.getenv("SECURITY_MODE", "FLAG_ONLY").upper()
            if security_mode == "BLOCK" and processed.get("security_check", {}).get(
                "is_potentially_malicious", False
            ):
                flags = processed.get("security_check", {}).get("detected_patterns", [])
                fallback_response = self.input_sanitizer.generate_fallback_message(
                    flags, context.persona
                )

                self.security_validator.log_security_event(
                    "unsafe_input_detected",
                    {
                        "session_id": session_id,
                        "security_flags": flags,
                        "persona": context.persona,
                    },
                )

                return {
                    "response": fallback_response,
                    "retrieved_cwes": [],
                    "chunk_count": 0,
                    "session_id": session_id,
                    "message": None,
                    "is_safe": False,
                    "security_flags": flags,
                }

            elif processed.get("security_check", {}).get(
                "is_potentially_malicious", False
            ):
                # In FLAG_ONLY mode, just log the event
                flags = processed.get("security_check", {}).get("detected_patterns", [])
                self.security_validator.log_security_event(
                    "unsafe_input_flagged",
                    {
                        "session_id": session_id,
                        "security_flags": flags,
                        "persona": context.persona,
                    },
                )

            sanitized_q = processed.get("sanitized_query", message_content)

            # Delegate to appropriate handler
            if context.persona == "CWE Analyzer":
                pipeline_result = await self.analyzer_handler.process(
                    sanitized_q, context
                )
            elif context.persona == "CVE Creator":
                pipeline_result = await self._handle_cve_creator(sanitized_q, context)
            else:
                # Standard personas use pipeline directly
                pipeline_result = await self.processing_pipeline.process_user_request(
                    sanitized_q, context
                )

            # Update context
            context.add_conversation_entry(
                sanitized_q,
                pipeline_result.final_response_text,
                pipeline_result.retrieved_cwes,
            )
            context.clear_evidence()

            # Build response without Chainlit Message object
            return {
                "response": pipeline_result.final_response_text,
                "retrieved_cwes": pipeline_result.retrieved_cwes,
                "chunk_count": pipeline_result.chunk_count,
                "session_id": session_id,
                "message": None,
                "persona": context.persona,
                "is_low_confidence": pipeline_result.is_low_confidence,
            }

        except Exception as e:
            logger.log_exception(
                f"API message processing failed for session {session_id}", e
            )
            return {
                "response": "I encountered an error processing your request. Please try again.",
                "retrieved_cwes": [],
                "chunk_count": 0,
                "session_id": session_id,
                "message": None,
                "error": str(e),
            }

    async def _handle_cve_creator(self, query: str, context: Any) -> "PipelineResult":
        """Handle CVE Creator persona logic."""

        # Set evidence and create structured CVE description
        context.set_evidence(query)
        enhanced_query = "Create a structured CVE description from the provided text."

        # Use pipeline but with empty chunks for direct creation
        try:
            result = await self.processing_pipeline.process_user_request(
                enhanced_query, context
            )
            result.metadata["persona"] = "CVE Creator"
            return result
        except Exception as e:
            logger.log_exception("CVE Creator processing failed", e)
            return PipelineResult(
                final_response_text="I encountered an error creating the CVE description. Please try again.",
                is_low_confidence=True,
            )

    def _build_response_dict(
        self, response_text: str, session_id: str, msg: Any, context: Any, **kwargs: Any
    ) -> Dict[str, Any]:
        """Build standardized response dictionary."""
        return {
            "response": response_text,
            "session_id": session_id,
            "is_safe": kwargs.get("is_safe", True),
            "retrieved_cwes": kwargs.get("retrieved_cwes", []),
            "chunk_count": kwargs.get("chunk_count", 0),
            "recommendations": kwargs.get("recommendations", []),
            "persona": context.persona,
            "message": msg,
            **{
                k: v
                for k, v in kwargs.items()
                if k
                not in ["is_safe", "retrieved_cwes", "chunk_count", "recommendations"]
            },
        }

    def _build_response_dict_from_pipeline(
        self, result: "PipelineResult", session_id: str, msg: Any, context: Any
    ) -> Dict[str, Any]:
        """Build response dictionary from PipelineResult."""
        return {
            "response": result.final_response_text,
            "session_id": session_id,
            "is_safe": not result.is_low_confidence,  # Simplified mapping
            "retrieved_cwes": result.retrieved_cwes,
            "chunk_count": result.chunk_count,
            "recommendations": result.recommendations,
            "persona": context.persona,
            "message": msg,
        }

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

        # Clear analysis context when changing personas to avoid contamination
        context.last_chunks = []
        context.last_recommendations = []
        context.analyzer_mode = None  # Clear any active analyzer modes

        context.update_activity()
        logger.info(
            f"Persona updated from {old_persona} to {new_persona} for session {session_id}. Cleared analysis context."
        )
        return True

    def get_session_context(self, session_id: str) -> Optional[UserContext]:
        """
        Get user context for a session.

        Args:
            session_id: Session identifier

        Returns:
            UserContext if found, None otherwise
        """
        ctx = cl.user_session.get("user_context")
        try:
            return ctx if isinstance(ctx, UserContext) else None
        except Exception:
            return None

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
        health.update({"active_sessions": -1, "persona_distribution": {}})
        return health

    def _summarize_attachment(self, text: str, *, limit: Optional[int] = None) -> str:
        """Create a brief, safe attachment summary for retrieval/context."""
        if not text:
            return ""
        if limit is None:
            limit = config.max_attachment_summary_length
        t = text.strip()
        if len(t) > limit:
            t = t[:limit] + "..."
        return t

    # Removed actions helper; using slash-command hints instead.

    async def _handle_processing_error(
        self, session_id: str, error: Exception
    ) -> Dict[str, Any]:
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
            "message": msg,
        }
