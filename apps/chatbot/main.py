#!/usr/bin/env python3
"""
CWE ChatBot - Story 2.1 Implementation
Chainlit application with NLU, security sanitization, and RAG response generation.
Integrates with Story 1.5 production infrastructure.
"""

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, Literal
import time

import chainlit as cl
from chainlit.input_widget import Select, Switch
from chainlit import ChatProfile, AskFileMessage
from pydantic import BaseModel, Field

from src.user_context import UserPersona, UserContext
from src.conversation import ConversationManager
from src.input_security import InputSanitizer, SecurityValidator
from src.file_processor import FileProcessor
from src.security.secure_logging import get_secure_logger
from src.app_config import config as app_config


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = get_secure_logger(__name__)

# Pydantic Chat Settings for native UI
class UISettings(BaseModel):
    persona: Literal["PSIRT Member", "Developer", "Academic Researcher", "Bug Bounty Hunter", "Product Manager", "CWE Analyzer", "CVE Creator"] = Field(
        default="Developer",
        description="Your cybersecurity role - determines response focus and depth"
    )
    detail_level: Literal["basic", "standard", "detailed"] = Field(
        default="standard",
        description="Level of detail in responses"
    )
    include_examples: bool = Field(
        default=True,
        description="Include code examples and practical demonstrations"
    )
    include_mitigations: bool = Field(
        default=True,
        description="Include prevention and mitigation guidance"
    )

# Global components (initialized on startup)
conversation_manager: Optional[ConversationManager] = None
input_sanitizer: Optional[InputSanitizer] = None
security_validator: Optional[SecurityValidator] = None
file_processor: Optional[FileProcessor] = None
_init_ok: bool = False


def initialize_components() -> bool:
    """Initialize all Story 2.1 chatbot components with error handling."""
    global conversation_manager, input_sanitizer, security_validator, file_processor, _init_ok

    try:
        # Validate config once; if it fails, we will surface a UI error and disable handlers
        try:
            app_config.validate_config()
        except Exception as cfg_err:
            logger.log_exception("Configuration validation failed", cfg_err, extra_context={
                "component": "startup",
            })
            _init_ok = False
            # Still attempt partial initialization to provide a helpful UI message
        
        # Prefer explicit URLs if provided (for dev/prod parity)
        database_url = os.getenv('DATABASE_URL') or os.getenv('LOCAL_DATABASE_URL')
        gemini_api_key = os.getenv('GEMINI_API_KEY') or app_config.gemini_api_key
        offline_ai = os.getenv('DISABLE_AI') == '1' or os.getenv('GEMINI_OFFLINE') == '1'

        if not database_url:
            # Derive URL from POSTGRES_* if available
            if app_config.pg_user and app_config.pg_password:
                database_url = f"postgresql://{app_config.pg_user}:{app_config.pg_password}@{app_config.pg_host}:{app_config.pg_port}/{app_config.pg_database}"
        if not database_url:
            raise ValueError("Missing required configuration: database URL")
        if not gemini_api_key and not offline_ai:
            raise ValueError("Missing required configuration: GEMINI_API_KEY (set DISABLE_AI=1 for offline mode)")

        logger.info(f"Initializing with database: {database_url[:50]}...")

        # Initialize security components
        input_sanitizer = InputSanitizer()
        security_validator = SecurityValidator()
        file_processor = FileProcessor()

        # Initialize conversation manager with all Story 2.1 components
        conversation_manager = ConversationManager(
            database_url=database_url,
            gemini_api_key=gemini_api_key
        )

        # Test database connection
        health = conversation_manager.get_system_health()
        if not health.get('database', False):
            raise RuntimeError("Database health check failed")

        logger.info("Story 2.1 components initialized successfully")
        logger.info(f"Database health: {health}")
        _init_ok = True
        return _init_ok
    except Exception as e:
        logger.log_exception("Component initialization failed", e, extra_context={"component": "startup"})
        _init_ok = False
        return _init_ok


@cl.set_chat_profiles
def set_profiles():
    """Expose personas as top-bar chat profiles for quick access."""
    profiles = []
    for p in UserPersona:
        profiles.append(ChatProfile(name=p.value, markdown_description=f"Persona: {p.value}"))
    return profiles


@cl.on_chat_start
async def start():
    """Initialize the chat session with settings-based persona configuration."""
    global conversation_manager

    if not conversation_manager or not _init_ok:
        await cl.Message(content="Startup error: configuration missing or database unavailable. Please check environment (GEMINI_API_KEY/DB).").send()
        return

    # Initialize default settings and expose a Settings panel
    default_settings = UISettings()

    # If a chat profile (top bar) is selected, use it as the persona
    selected_profile = cl.user_session.get("chat_profile")
    if isinstance(selected_profile, str) and selected_profile in UserPersona.get_all_personas():
        default_settings.persona = selected_profile

    cl.user_session.set("ui_settings", default_settings.dict())

    # Build and display the Chainlit settings panel
    try:
        settings_panel = cl.ChatSettings(
            [
                Select(
                    id="detail_level",
                    label="Detail Level",
                    values=["basic", "standard", "detailed"],
                    initial_index=["basic", "standard", "detailed"].index(default_settings.detail_level),
                    description="How much detail to include"
                ),
                Switch(
                    id="include_examples",
                    label="Include Code Examples",
                    initial=default_settings.include_examples,
                ),
                Switch(
                    id="include_mitigations",
                    label="Include Mitigations",
                    initial=default_settings.include_mitigations,
                ),
            ]
        )
        await settings_panel.send()
    except Exception as e:
        # Non-fatal if UI widgets API changes; continue without settings panel
        logger.log_exception("Failed to render settings panel", e)

    # One-time UI hint for this session (points to header selector & gear)
    try:
        if not cl.user_session.get("ui_hint_shown"):
            tip = (
                "Use the Persona selector in the top bar to switch roles, "
                "and the gear next to the input to adjust detail level, examples, and mitigations."
            )
            await cl.Message(content=f"💡 {tip}", author="System").send()
            cl.user_session.set("ui_hint_shown", True)
    except Exception as e:
        logger.log_exception("Failed to send UI hint", e)

    # Initialize per-user context in Chainlit with default persona
    session_id = cl.context.session.id
    await conversation_manager.update_user_persona(session_id, default_settings.persona)

    # Welcome message that guides users to the settings panel
    welcome_message = """Welcome to the CWE ChatBot! 🛡️

I'm here to help you with Common Weakness Enumeration (CWE) information.

**Configure your experience using the top Persona selector** (header dropdown) and the Settings panel (gear icon in the input area) to:
• Select your cybersecurity role/persona (top dropdown)
• Adjust detail level and preferences
• Customize response format

**Available Personas:**
• **PSIRT Member** - Impact assessment and advisory creation
• **Developer** - Remediation steps and code examples
• **Academic Researcher** - Comprehensive analysis and relationships
• **Bug Bounty Hunter** - Exploitation patterns and testing techniques
• **Product Manager** - Business impact and prevention strategies
• **CWE Analyzer** - CVE-to-CWE mapping analysis with confidence scoring
• **CVE Creator** - Structured CVE vulnerability descriptions

Once configured, ask me anything about cybersecurity weaknesses!"""

    await cl.Message(content=welcome_message).send()

    # Provide a quick action to attach files (useful for CVE Creator)
    try:
        attach_action = [
            cl.Action(
                name="attach_files",
                value="attach_files",
                label="Attach Files (PDF)",
                payload={"source": "welcome"}
            )
        ]
        await cl.Message(content="You can attach relevant documents if needed.", actions=attach_action, author="System").send()
    except Exception as e:
        logger.log_exception("Failed to render attach files action", e)


@cl.on_message
async def main(message: cl.Message):
    """Handle incoming messages with Story 2.1 NLU and RAG pipeline."""

    # Check if components are initialized
    if not conversation_manager or not _init_ok:
        await cl.Message(content="Startup error: configuration missing or database unavailable. Please check environment (GEMINI_API_KEY/DB).").send()
        return

    # Get current settings and ensure session exists
    session_id = cl.context.session.id
    ui_settings = cl.user_session.get("ui_settings")

    if not ui_settings:
        # Initialize with defaults if missing
        default_settings = UISettings()
        ui_settings = default_settings.dict()
        cl.user_session.set("ui_settings", ui_settings)

    # Ensure conversation context exists with current persona (settings panel drives persona)
    context = conversation_manager.get_session_context(session_id)
    if not context or context.persona != ui_settings["persona"]:
        await conversation_manager.update_user_persona(session_id, ui_settings["persona"])

    try:
        # Prevent accidental double-send with a 1s debounce
        now = time.monotonic()
        last_ts = cl.user_session.get("_last_msg_ts") or 0.0
        if now - float(last_ts) < 1.0:
            logger.info("Debounced duplicate message within 1s window")
            return
        cl.user_session.set("_last_msg_ts", now)

        user_query = message.content.strip()

        # If user uploaded files via the Attach Files action earlier, merge their content
        pending_upload = cl.user_session.get("uploaded_file_content")
        if pending_upload:
            if user_query:
                user_query = f"{user_query}\n\n--- Attached File Content ---\n{pending_upload}"
            else:
                user_query = f"--- Attached File Content ---\n{pending_upload}"
            cl.user_session.set("uploaded_file_content", None)

        # Process file attachments if present (especially for CVE Creator)
        if hasattr(message, 'elements') and message.elements and file_processor:
            async with cl.Step(name="Process file attachments", type="tool") as file_step:
                file_step.input = f"Processing {len(message.elements)} file(s) for {ui_settings['persona']}"

                logger.info(f"Processing {len(message.elements)} file attachments for {ui_settings['persona']}")
                file_content = await file_processor.process_attachments(message)

                if file_content:
                    # Combine user query with file content
                    if user_query:
                        user_query = f"{user_query}\n\n--- Attached File Content ---\n{file_content}"
                    else:
                        user_query = f"--- Attached File Content ---\n{file_content}"

                    file_step.output = f"Extracted {len(file_content)} characters from file(s)"
                    logger.info(f"File content extracted: {len(file_content)} characters")
                else:
                    file_step.output = "No content extracted from file(s)"
                    logger.warning("File attachments found but no content extracted")

        logger.info(f"Processing user query: '{user_query[:100]}...' for persona: {ui_settings['persona']}")

        # Process message using conversation manager with streaming
        result = await conversation_manager.process_user_message_streaming(
            session_id=session_id,
            message_content=user_query,
            message_id=message.id
        )

        # Create source cards as Chainlit Elements if we have retrieved chunks
        elements = []
        if result.get("retrieved_cwes") and result.get("chunk_count", 0) > 0:
            # Get the retrieved chunks to create source elements
            retrieved_chunks = result.get("retrieved_chunks", [])

            # Group chunks by CWE and create source cards
            cwe_groups = {}
            for chunk in retrieved_chunks:
                cwe_id = chunk["metadata"]["cwe_id"]
                if cwe_id not in cwe_groups:
                    cwe_groups[cwe_id] = {
                        "name": chunk["metadata"]["name"],
                        "chunks": []
                    }
                cwe_groups[cwe_id]["chunks"].append(chunk)

            # Create source elements for each CWE
            for cwe_id, cwe_info in list(cwe_groups.items())[:3]:  # Limit to top 3 CWEs
                # Get best scoring chunk for this CWE
                best_chunk = max(cwe_info["chunks"], key=lambda x: x.get("scores", {}).get("hybrid", 0.0))
                score = best_chunk.get("scores", {}).get("hybrid", 0.0)

                # Create source content showing the CWE information
                source_content = f"**{cwe_id}: {cwe_info['name']}**\n\n"
                source_content += f"**Relevance Score:** {score:.3f}\n\n"

                # Add section content from the best chunk
                section = best_chunk["metadata"].get("section", "Content")
                source_content += f"**{section}:**\n"
                document_text = best_chunk["document"]

                # Truncate if too long
                if len(document_text) > 500:
                    source_content += document_text[:500] + "..."
                else:
                    source_content += document_text

                # Create Chainlit Text element for the source
                source_element = cl.Text(
                    name=f"Source: {cwe_id}",
                    content=source_content,
                    display="side"  # Display in sidebar
                )
                elements.append(source_element)

        # Add metadata for debugging if needed
        if not result.get("is_safe", True):
            logger.warning(f"Security flags detected: {result.get('security_flags', [])}")

        # The response was already streamed, just update the message with elements if needed
        if elements and result.get("message"):
            result["message"].elements = elements
            await result["message"].update()

        # Log successful interaction
        current_persona = ui_settings["persona"]
        logger.info(f"Successfully processed query for {current_persona}, retrieved {result.get('chunk_count', 0)} chunks")

    except Exception as e:
        # Secure error handling - never expose internal details
        logger.log_exception("Error processing message", e, extra_context={"handler": "on_message"})
        error_response = "I apologize, but I'm experiencing technical difficulties. Please try your question again in a moment."
        await cl.Message(content=error_response).send()


@cl.on_settings_update
async def on_settings_update(settings: Dict[str, Any]):
    """Handle settings updates from the native Chainlit settings panel."""
    global conversation_manager

    if not conversation_manager:
        return

    try:
        session_id = cl.context.session.id

        # Normalize settings to our UISettings model and persist.
        # Merge with existing stored settings so missing fields (like persona when using top profiles)
        # are preserved rather than reset to defaults.
        existing = cl.user_session.get("ui_settings") or {}
        merged = {**existing, **(settings or {})}
        model = UISettings(**merged)
        cl.user_session.set("ui_settings", model.dict())

        # Update persona in conversation manager if it changed
        current_context = conversation_manager.get_session_context(session_id)
        if current_context and current_context.persona != model.persona:
            success = await conversation_manager.update_user_persona(session_id, model.persona)
            if success:
                logger.info(f"Updated persona to {model.persona} for session {session_id}")

                # Send confirmation message
                await cl.Message(
                    content=f"✅ Settings updated! Now responding as **{model.persona}** with **{model.detail_level}** detail level.",
                    author="System"
                ).send()
            else:
                logger.error(f"Failed to update persona to {model.persona}")

    except Exception as e:
        logger.log_exception("Settings update failed", e)


@cl.on_feedback
async def on_feedback(feedback):
    """Handle user feedback on messages."""
    global conversation_manager

    if not conversation_manager:
        logger.warning("Feedback received but conversation manager not initialized")
        return

    try:
        session_id = cl.context.session.id

        # Get message ID from feedback object
        # In current Chainlit, feedback has 'forId' attribute pointing to the message
        message_id = getattr(feedback, 'forId', getattr(feedback, 'for_id', None))

        if not message_id:
            logger.error("Feedback received but no message ID found")
            return

        # Convert Chainlit feedback to our rating system (1-5 scale)
        # Chainlit feedback.value is typically 1 (thumbs up) or 0 (thumbs down)
        feedback_value = getattr(feedback, 'value', None)
        if feedback_value is None:
            logger.error("Feedback received but no value found")
            return

        rating = 5 if feedback_value == 1 else 2  # Map thumbs up to 5, thumbs down to 2

        # Record feedback in conversation manager
        success = conversation_manager.record_feedback(session_id, message_id, rating)

        if success:
            logger.info(f"Recorded feedback for message {message_id}: rating {rating} (feedback value: {feedback_value})")
            # Optional: Send a brief acknowledgment (disabled to avoid noise)
            # await cl.Message(
            #     content="👍 Thank you for your feedback!",
            #     author="System"
            # ).send()
        else:
            logger.error(f"Failed to record feedback for message {message_id}")

    except Exception as e:
        logger.log_exception("Error processing feedback", e)
        # Log feedback object structure for debugging
        logger.debug(f"Feedback object attributes: {dir(feedback) if feedback else 'None'}")


# Action: Attach Files
@cl.action_callback("attach_files")
async def on_attach_files(action):
    """Handle file attachment via a guided prompt; stores extracted content for next message."""
    global file_processor
    try:
        # Prompt the user to upload PDF files (up to 10MB each, max 3)
        ask = AskFileMessage(
            content="Upload PDF(s) with vulnerability details (max 3 files, 10MB each).",
            accept=["application/pdf"],
            max_files=3,
            max_size_mb=10,
            timeout=600,
        )
        files = await ask.send()

        if not files:
            await cl.Message(content="No files uploaded.", author="System").send()
            return

        # Reuse FileProcessor on a temporary message wrapper to extract content
        class _Tmp:
            pass
        tmp = _Tmp()
        tmp.elements = files

        content = await file_processor.process_attachments(tmp) if file_processor else None
        if content:
            cl.user_session.set("uploaded_file_content", content)
            await cl.Message(content="📎 Files received. I will use them in your next prompt.", author="System").send()
        else:
            await cl.Message(content="Unable to extract text from the uploaded files. Please ensure they are text-based PDFs.", author="System").send()
    except Exception as e:
        logger.log_exception("Attach files flow failed", e)
        await cl.Message(content="File upload failed. Please try again or use smaller PDFs.", author="System").send()




def main_cli():
    """CLI entry point for running the Story 2.1 application."""
    # Initialize components on startup
    if not initialize_components():
        logger.error("Failed to initialize Story 2.1 components. Exiting.")
        sys.exit(1)

    logger.info("CWE ChatBot Story 2.1 is ready to serve requests")


# Initialize components when module loads for Chainlit
initialize_components()


@cl.on_stop
async def on_stop() -> None:
    """Gracefully close resources when the app stops."""
    try:
        if conversation_manager and getattr(conversation_manager, "query_handler", None):
            qh = conversation_manager.query_handler
            close_fn = getattr(qh, "close", None)
            if callable(close_fn):
                close_fn()
                logger.info("Closed retriever/database resources")
    except Exception as e:
        logger.log_exception("Shutdown cleanup failed", e)

if __name__ == "__main__":
    # This allows running the app directly with: python main.py
    main_cli()

    # Note: Use 'poetry run chainlit run apps/chatbot/main.py' to start the application
    logger.info("To start the application, run: poetry run chainlit run apps/chatbot/main.py")
