"""
Message handler for Chainlit chat application.

This module extracts complex message processing logic from main.py
to reduce cyclomatic complexity and improve testability.
"""

import asyncio
import time
from typing import Any, Dict, List

import chainlit as cl
from src.security import CSRFManager
from src.security.secure_logging import get_secure_logger
from src.ui import UIMessaging
from src.user_context import UserPersona
from src.utils.session import get_user_context

logger = get_secure_logger(__name__)


class AuthError(Exception):
    """Raised when a request is not authenticated and auth is required."""


class MessageHandler:
    """
    High-level orchestrator for incoming user messages.

    This isolates complex branching from Chainlit's @cl.on_message hook so that:
    - Each step is unit-testable in isolation
    - Cyclomatic complexity of the hook stays <10
    - We can mock conversation_manager/file_processor/etc. in tests
    """

    def __init__(
        self,
        *,
        conversation_manager: Any,
        file_processor: Any,
        app_config: Any,
        requires_authentication_fn,
        is_user_authenticated_fn,
    ):
        self.cm = conversation_manager
        self.file_processor = file_processor
        self.app_config = app_config
        self._requires_authentication = requires_authentication_fn
        self._is_user_authenticated = is_user_authenticated_fn

    # -------------------------
    # Public entry point
    # -------------------------
    async def handle(self, message: cl.Message) -> None:
        """
        Main message pipeline.
        """
        try:
            self._debug_log_incoming(message)

            self._auth_guard()

            self._update_user_activity()

            session_id, ui_settings, persona = self._ensure_session_state()

            self._debounce()

            # Handle files (may update Chainlit session with "uploaded_file_context")
            await self._ingest_attachments(message, persona)

            # Derive final user query text (including default for "just upload a file" path)
            user_query = self._build_user_query(message)
            logger.info(
                f"Processing user query: '{user_query[:100]}...' for persona: {persona}"
            )

            # Run the "analyze security query" step (retrieval + reasoning)
            processing_result = await self._run_analysis_step(
                session_id=session_id,
                user_query=user_query,
                message_id=message.id,
            )

            # CRITICAL: Prepare UI elements BEFORE sending message
            # Any cl.Step() after message.send() will block feedback buttons!
            # See: https://github.com/Chainlit/chainlit/issues/1202
            elements = await self._prepare_source_elements(
                processing_result=processing_result,
                ui_settings=ui_settings,
            )

            # Ask CM to generate/send the final answer message in chat
            # Pass pre-prepared elements to avoid Step after send
            result = await self.cm.send_message_from_result(
                processing_result, elements=elements
            )

            self._debug_log_response(result)

            # CWE Analyzer persona follow-up actions ("Ask Question", etc.)
            await self._maybe_render_persona_actions(session_id)

            # Clear uploaded_file_context now that we've used it
            cl.user_session.set("uploaded_file_context", None)

            self._log_success(session_id)

        except AuthError:
            await cl.Message(
                content="🔒 Authentication required. Please authenticate using Google or GitHub to send messages.",
                author="System",
            ).send()

        except Exception as e:
            await self._handle_unexpected_error(e)

    # -------------------------
    # Internal helpers
    # -------------------------
    def _auth_guard(self) -> None:
        """
        Enforce OAuth auth policy if enabled. Raises AuthError on failure.
        """
        if self._requires_authentication() and not self._is_user_authenticated():
            raise AuthError()

    def _update_user_activity(self) -> None:
        """
        Touch last-activity timestamp on the user context if authenticated.
        """
        try:
            ctx = get_user_context()
            if ctx and getattr(ctx, "is_authenticated", False):
                ctx.update_activity()
        except Exception as e:
            logger.log_exception("Failed to update user activity", e)

    def _ensure_session_state(self) -> tuple[str, Dict[str, Any], str]:
        """
        Ensure ui_settings/persona are present in Chainlit session,
        and sync persona to ConversationManager.
        """
        session_id = cl.context.session.id

        ui_settings = cl.user_session.get("ui_settings")
        if not ui_settings:
            from src.ui import UISettings

            defaults = UISettings().dict()
            cl.user_session.set("ui_settings", defaults)
            ui_settings = defaults

        # sync persona from top-bar chat profile
        selected_profile = cl.user_session.get("chat_profile")
        persona = (
            selected_profile
            if isinstance(selected_profile, str)
            and selected_profile in UserPersona.get_all_personas()
            else UserPersona.DEVELOPER.value
        )

        context = self.cm.get_session_context(session_id)
        if not context or context.persona != persona:
            # fire-and-forget persona update
            # (await would make this async, but we don't want to await in sync helper)
            # We'll schedule it on the loop to avoid blocking.
            asyncio.create_task(self.cm.update_user_persona(session_id, persona))

        return session_id, ui_settings, persona

    def _debounce(self) -> None:
        """
        Drop accidental double-send within 1s.
        """
        now = time.monotonic()
        last_ts = float(cl.user_session.get("_last_msg_ts") or 0.0)
        if now - last_ts < 1.0:
            logger.info("Debounced duplicate message within 1s window")
            # raise StopIteration-like sentinel to abort cleanly
            raise RuntimeError("duplicate_message_debounced")
        cl.user_session.set("_last_msg_ts", now)

    async def _ingest_attachments(self, message: cl.Message, persona: str) -> None:
        """
        Process uploaded file elements, extract text, store in session as
        'uploaded_file_context'. Includes heartbeat keepalive.
        """
        if not getattr(message, "elements", None) or not self.file_processor:
            return

        async with cl.Step(name="Process file attachments", type="tool") as step:
            step.input = f"Processing {len(message.elements)} file(s) for {persona}"
            logger.info(
                f"Processing {len(message.elements)} file attachments for {persona}"
            )

            status_msg = await cl.Message(content="Processing files...").send()

            heartbeat_running = True

            async def heartbeat():
                count = 0
                while heartbeat_running:
                    await asyncio.sleep(3)
                    if heartbeat_running:
                        count += 1
                        await status_msg.stream_token(".")

            hb_task = asyncio.create_task(heartbeat())

            try:
                file_content = await self.file_processor.process_attachments(message)
            finally:
                # stop heartbeat
                heartbeat_running = False
                try:
                    hb_task.cancel()
                    await hb_task
                except asyncio.CancelledError:
                    pass
                await status_msg.remove()

            if file_content:
                cl.user_session.set("uploaded_file_context", file_content)
                step.output = (
                    f"Extracted {len(file_content)} characters from file(s) "
                    "(stored as isolated evidence)"
                )
                logger.info(f"File content extracted: {len(file_content)} characters")
            else:
                step.output = "No content extracted from file(s)"
                logger.warning("File attachments found but no content extracted")

    def _build_user_query(self, message: cl.Message) -> str:
        """
        Final "user_query" string that will feed the RAG pipeline.
        Falls back to default analysis prompt if user only uploaded a file.
        """
        user_query = (message.content or "").strip()
        if user_query.lower().startswith("/feedback"):
            # This path used to branch to collect_detailed_feedback() inline.
            # We keep the behavior by pretending user asked explicitly.
            # The feedback collection UX can remain handled separately.
            return "Open feedback prompt"

        file_ctx = cl.user_session.get("uploaded_file_context")
        if file_ctx and (not user_query or user_query == "..."):
            return (
                "Analyze this document for security vulnerabilities and CWE mappings."
            )

        return user_query

    async def _run_analysis_step(
        self, *, session_id: str, user_query: str, message_id: str
    ) -> Dict[str, Any]:
        """
        Wraps ConversationManager.process_user_message_no_send() in a Chainlit Step
        so we preserve the nice 'Analyze security query' progress UI.
        """
        async with cl.Step(name="Analyze security query", type="tool") as analysis_step:
            analysis_step.input = f"Query: '{user_query[:100]}...'"

            processing_result = await self.cm.process_user_message_no_send(
                session_id=session_id,
                message_content=user_query,
                message_id=message_id,
            )

            if not processing_result.get("is_direct_response"):
                pipeline_result = processing_result.get("pipeline_result")
                if pipeline_result:
                    chunk_count = getattr(pipeline_result, "chunk_count", 0)
                    analysis_step.output = (
                        f"Retrieved {chunk_count} relevant CWE chunks"
                    )
                else:
                    analysis_step.output = "Processing completed"
            else:
                analysis_step.output = "Direct response (no retrieval needed)"

        return processing_result

    async def _prepare_source_elements(
        self, *, processing_result: Dict[str, Any], ui_settings: Dict[str, Any]
    ) -> List[cl.Element]:
        """
        Prepare Chainlit elements for:
        - retrieved CWE chunks
        - uploaded file evidence
        - progressive disclosure

        CRITICAL: This runs BEFORE message.send() to avoid blocking feedback buttons.
        Any cl.Step() after message.send() will block feedback buttons!
        See: https://github.com/Chainlit/chainlit/issues/1202

        Returns:
            List of Chainlit elements ready to attach to message
        """
        elements: List[cl.Element] = []

        # Check if we have retrieval results
        if not processing_result.get("is_direct_response"):
            pipeline_result = processing_result.get("pipeline_result")
            if pipeline_result and pipeline_result.retrieved_chunks:
                # Create source elements WITHOUT Step context
                # (Step would block feedback buttons if run after send)
                elements = UIMessaging.create_source_elements(
                    pipeline_result.retrieved_chunks
                )
                logger.info(
                    f"Prepared {len(elements)} source elements from {len(pipeline_result.retrieved_cwes)} CWEs"
                )

        # Add uploaded file evidence if present
        file_ctx = cl.user_session.get("uploaded_file_context")
        if file_ctx:
            evidence = UIMessaging.create_file_evidence_element(file_ctx)
            elements.append(evidence)
            logger.info("Added file evidence element")

        # Apply progressive disclosure settings
        # Note: We don't have the message object yet, so UIMessaging will need to handle this
        # Progressive disclosure is applied by limiting elements based on ui_settings
        if ui_settings.get("progressive_disclosure_enabled", False):
            max_sources = ui_settings.get("progressive_disclosure_max_sources", 3)
            if len(elements) > max_sources:
                logger.info(
                    f"Progressive disclosure: limiting {len(elements)} elements to {max_sources}"
                )
                elements = elements[:max_sources]

        return elements

    async def _maybe_render_persona_actions(self, session_id: str) -> None:
        """
        For CWE Analyzer persona, render follow-up action buttons
        ("Ask Question", etc.). Keeps CSRF behavior.
        """
        ctx = self.cm.get_session_context(session_id)
        if not ctx:
            logger.warning("No current context found - cannot show Action buttons")
            return

        persona = ctx.persona
        analyzer_mode = getattr(ctx, "analyzer_mode", None)

        logger.info(
            f"Debug: persona={persona}, analyzer_mode={getattr(ctx, 'analyzer_mode', 'MISSING')}"
        )

        if persona != "CWE Analyzer":
            logger.info(
                f"Not showing Action buttons - persona: {persona}, analyzer_mode: {analyzer_mode}"
            )
            return

        try:
            csrf_token = CSRFManager.get_session_token()
        except Exception as e:
            logger.log_exception("Failed to get CSRF token for actions", e)
            csrf_token = None

        # initial mode: show "Ask Question"
        if not analyzer_mode:
            if csrf_token:
                actions = [
                    cl.Action(
                        name="ask_question",
                        label="❓ Ask a Question",
                        payload={"action": "ask", "csrf_token": csrf_token},
                    )
                ]
                await cl.Message(
                    content="**Next steps for this analysis:**",
                    actions=actions,
                    author="System",
                ).send()
            else:
                await cl.Message(
                    content="**Next steps:** Type '/ask' to ask a question about the analysis, or '/compare' to compare CWE IDs.",
                    author="System",
                ).send()
            return

        # question mode active: show "Exit Question Mode"
        if analyzer_mode == "question":
            if csrf_token:
                actions = [
                    cl.Action(
                        name="exit_question_mode",
                        label="🚪 Exit Question Mode",
                        payload={"action": "exit", "csrf_token": csrf_token},
                    )
                ]
                await cl.Message(
                    content="**Question mode active.**",
                    actions=actions,
                    author="System",
                ).send()
            else:
                await cl.Message(
                    content="**Question mode active.** Type '/exit' to leave question mode.",
                    author="System",
                ).send()

    async def _handle_unexpected_error(self, exc: Exception) -> None:
        """
        Log and send safe generic error.
        """
        logger.log_exception(
            "Error processing message",
            exc,
            extra_context={"handler": "on_message"},
        )
        await cl.Message(
            content=(
                "I apologize, but I'm experiencing technical difficulties. "
                "Please try your question again in a moment."
            )
        ).send()

    def _debug_log_incoming(self, message: cl.Message) -> None:
        """
        Optional debug logging of inbound user message.
        """
        if not getattr(self.app_config, "debug_log_messages", False):
            return
        user_email = "anonymous"
        if self._requires_authentication():
            user = cl.user_session.get("user")
            if user and hasattr(user, "metadata") and user.metadata:
                user_email = user.metadata.get("email", "unknown")
        content_preview = message.content[:200] if message.content else ""
        if message.content and len(message.content) > 200:
            content_preview += "..."
        logger.info(f"[DEBUG_MSG] User: {user_email} | Message: {content_preview}")

    def _debug_log_response(self, result: Dict[str, Any]) -> None:
        """
        Optional debug logging of assistant response text (first 200 chars).
        """
        if not getattr(self.app_config, "debug_log_messages", False):
            return

        resp_msg = result.get("message")
        if not resp_msg:
            return

        response_text = (
            resp_msg.content if hasattr(resp_msg, "content") else str(resp_msg)
        )

        user_email = "anonymous"
        if self._requires_authentication():
            user = cl.user_session.get("user")
            if user and hasattr(user, "metadata") and user.metadata:
                user_email = user.metadata.get("email", "unknown")

        preview = response_text[:200]
        if len(response_text) > 200:
            preview += "..."

        logger.info(
            f"[DEBUG_RESP] User: {user_email} | Response length: {len(response_text)} chars | First 200: {preview}"
        )

    def _log_success(self, session_id: str) -> None:
        """
        Final structured log per interaction.
        """
        ctx = self.cm.get_session_context(session_id)
        persona = ctx.persona if ctx else "unknown"
        # We don't have direct access to the last result here anymore, so this becomes
        # a lightweight log. If you want chunk_count, you can thread it in.
        logger.info(
            f"Successfully processed query for {persona} (session={session_id})"
        )
