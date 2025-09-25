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
from chainlit import ChatProfile
from pydantic import BaseModel, Field

from src.user_context import UserPersona, UserContext
from src.conversation import ConversationManager
from src.input_security import InputSanitizer, SecurityValidator
from src.file_processor import FileProcessor
from src.security.secure_logging import get_secure_logger
# Use the extended config which loads from environment files automatically
from src.app_config_extended import config as app_config


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = get_secure_logger(__name__)

# Pydantic Chat Settings for native UI
class UISettings(BaseModel):
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


def create_progressive_response(content: str, detail_level: str) -> list:
    """
    Create progressive disclosure response based on detail level setting.
    Story 3.4: Progressive Disclosure Implementation
    """
    if detail_level == "basic" and len(content) > 300:
        # Create summary with expandable details
        summary = content[:300] + "..."
        remaining = content[300:]

        # Use Chainlit's Text element with expandable content
        return [
            cl.Text(name="Summary", content=summary, display="inline"),
            cl.Text(name="Detailed Information", content=remaining, display="side")
        ]
    elif detail_level == "detailed":
        # Show full content with additional context
        return [cl.Text(name="Detailed Response", content=content, display="inline")]
    else:
        # Standard level - show full content normally
        return [cl.Text(name="Response", content=content, display="inline")]


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
    cl.user_session.set("ui_settings", default_settings.dict())
    selected_profile = cl.user_session.get("chat_profile")
    persona = (
        selected_profile
        if isinstance(selected_profile, str) and selected_profile in UserPersona.get_all_personas()
        else UserPersona.DEVELOPER.value
    )

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
    await conversation_manager.update_user_persona(session_id, persona)

    # Enhanced onboarding welcome message with progressive introduction
    welcome_message = """Welcome to the CWE ChatBot! 🛡️

I'm here to help you with Common Weakness Enumeration (CWE) information. Let me guide you through getting started:

**🎯 Step 1: Choose Your Role**
Use the Persona selector in the top bar to select your cybersecurity role for tailored responses.

**⚙️ Step 2: Customize Settings**
Click the gear icon next to the input to adjust:
• **Detail Level**: Basic (summaries), Standard (balanced), or Detailed (comprehensive)
• **Examples**: Toggle code examples and demonstrations
• **Mitigations**: Include/exclude prevention guidance"""

    await cl.Message(content=welcome_message).send()

    # Send persona information as a separate expandable message
    persona_info = """**Available Personas:**

• **PSIRT Member** 🛡️ - Impact assessment and security advisory creation
• **Developer** 💻 - Remediation steps and secure coding examples
• **Academic Researcher** 🎓 - Comprehensive analysis and CWE relationships
• **Bug Bounty Hunter** 🔍 - Exploitation patterns and testing techniques
• **Product Manager** 📊 - Business impact and prevention strategies
• **CWE Analyzer** 🔬 - CVE-to-CWE mapping analysis with confidence scoring
• **CVE Creator** 📝 - Structured CVE vulnerability descriptions

Each persona provides responses tailored to your specific needs and expertise level."""

    # Create expandable element for persona details
    persona_element = cl.Text(
        name="Persona Guide",
        content=persona_info,
        display="side"
    )

    # Send example queries as a third guided step
    examples_message = """**🚀 Step 3: Try Example Queries**

Here are some questions to get you started:

• *"What is CWE-79 and how do I prevent it?"*
• *"Map this vulnerability to appropriate CWEs"*
• *"Show me SQL injection prevention techniques"*
• *"Analyze the security impact of buffer overflows"*

**Ready to begin!** Select your persona above and ask your first question."""

    await cl.Message(content=examples_message, elements=[persona_element]).send()

    # Users can upload files via Chainlit's spontaneous file upload feature (config.toml)


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

    # Ensure persona follows the top-bar ChatProfile (not settings)
    context = conversation_manager.get_session_context(session_id)
    selected_profile = cl.user_session.get("chat_profile")
    if isinstance(selected_profile, str) and selected_profile in UserPersona.get_all_personas():
        if not context or context.persona != selected_profile:
            await conversation_manager.update_user_persona(session_id, selected_profile)

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
            # Do not append raw file text into the prompt; store as separate context
            cl.user_session.set("uploaded_file_context", pending_upload)
            cl.user_session.set("uploaded_file_content", None)

        # Process file attachments if present
        if hasattr(message, 'elements') and message.elements and file_processor:
            async with cl.Step(name="Process file attachments", type="tool") as file_step:
                current_ctx = conversation_manager.get_session_context(session_id)
                current_persona = (current_ctx.persona if current_ctx else UserPersona.DEVELOPER.value)
                file_step.input = f"Processing {len(message.elements)} file(s) for {current_persona}"
                logger.info(f"Processing {len(message.elements)} file attachments for {current_persona}")
                file_content = await file_processor.process_attachments(message)

                if file_content:
                    # SECURITY: do not merge evidence into the prompt; store for isolated use
                    cl.user_session.set("uploaded_file_context", file_content)
                    file_step.output = f"Extracted {len(file_content)} characters from file(s) (stored as isolated evidence)"
                    logger.info(f"File content extracted: {len(file_content)} characters")
                else:
                    file_step.output = "No content extracted from file(s)"
                    logger.warning("File attachments found but no content extracted")

        current_ctx = conversation_manager.get_session_context(session_id)
        current_persona = (current_ctx.persona if current_ctx else UserPersona.DEVELOPER.value)
        logger.info(f"Processing user query: '{user_query[:100]}...' for persona: {current_persona}")

        # Process message using conversation manager with streaming (true streaming)
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

            # Create source elements for each CWE (skip evidence pseudo-source)
            filtered = [(cid, info) for cid, info in cwe_groups.items() if cid not in ("EVIDENCE", "FILE")]
            for cwe_id, cwe_info in filtered[:3]:  # Limit to top 3 CWEs
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

        # Add uploaded file evidence as a side element (if present)
        file_ctx = cl.user_session.get("uploaded_file_context")
        if file_ctx:
            # Truncate for display; full text already passed as isolated context
            preview = file_ctx
            if len(preview) > 800:
                preview = preview[:800] + "..."
            evidence = cl.Text(
                name="Uploaded Evidence",
                content=preview,
                display="side"
            )
            elements.append(evidence)

        # Add metadata for debugging if needed
        if not result.get("is_safe", True):
            logger.warning(f"Security flags detected: {result.get('security_flags', [])}")

        # Apply progressive disclosure based on UI settings and update message with elements
        if result.get("message"):
            # Apply progressive disclosure if configured
            detail_level = ui_settings.get("detail_level", "standard")
            if detail_level == "basic" and hasattr(result["message"], 'content'):
                # Create progressive disclosure for long responses
                content = result["message"].content
                if len(content) > 300:
                    # Split into summary and details
                    summary = content[:300] + "..."
                    details = content[300:]

                    # Update the main message to show summary
                    result["message"].content = summary

                    # Add detailed content as a side element
                    detail_element = cl.Text(
                        name="Detailed Information",
                        content=details,
                        display="side"
                    )
                    elements.append(detail_element)

            # Update message with all elements
            if elements:
                result["message"].elements = elements
                await result["message"].update()

        # Clear file context after use to avoid unbounded growth (ConversationManager clears its own context copy)
        if file_ctx:
            cl.user_session.set("uploaded_file_context", None)

        # Log successful interaction
        current_ctx = conversation_manager.get_session_context(session_id)
        current_persona = current_ctx.persona if current_ctx else persona
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

        # Acknowledge settings update (persona is driven by ChatProfile, not settings)
        await cl.Message(
            content=f"✅ Settings updated! Detail level: **{model.detail_level}**; Examples: **{'on' if model.include_examples else 'off'}**; Mitigations: **{'on' if model.include_mitigations else 'off'}**.",
            author="System",
        ).send()

    except Exception as e:
        logger.log_exception("Settings update failed", e)


async def collect_detailed_feedback():
    """
    Collect detailed feedback from user using Chainlit's native components.
    Story 3.4: Enhanced Feedback Integration
    """
    try:
        # Use Chainlit's AskUserMessage for structured feedback collection
        feedback_prompt = await cl.AskUserMessage(
            content="**Help us improve! 🚀** Please share your feedback about this response:\n\n• Was the information accurate and helpful?\n• Did the detail level match your needs?\n• Any suggestions for improvement?",
            timeout=60,
        ).send()

        if feedback_prompt:
            # Store detailed feedback for analysis
            session_id = cl.context.session.id
            cl.user_session.set("detailed_feedback", {
                "timestamp": time.time(),
                "content": feedback_prompt.content,
                "session_id": session_id
            })

            # Send acknowledgment
            await cl.Message(
                content="🙏 Thank you for your detailed feedback! Your input helps us improve the CWE ChatBot experience.",
                author="System"
            ).send()

    except Exception as e:
        logger.log_exception("Detailed feedback collection failed", e)


@cl.on_feedback
async def on_feedback(feedback):
    """Enhanced feedback handler with detailed feedback collection option."""
    global conversation_manager

    if not conversation_manager:
        logger.warning("Feedback received but conversation manager not initialized")
        return

    try:
        session_id = cl.context.session.id

        # Get message ID from feedback object
        message_id = getattr(feedback, 'forId', getattr(feedback, 'for_id', None))

        if not message_id:
            logger.error("Feedback received but no message ID found")
            return

        # Convert Chainlit feedback to our rating system (1-5 scale)
        feedback_value = getattr(feedback, 'value', None)
        if feedback_value is None:
            logger.error("Feedback received but no value found")
            return

        rating = 5 if feedback_value == 1 else 2  # Map thumbs up to 5, thumbs down to 2

        # Record feedback in conversation manager
        success = conversation_manager.record_feedback(session_id, message_id, rating)

        if success:
            logger.info(f"Recorded feedback for message {message_id}: rating {rating} (feedback value: {feedback_value})")

            # For negative feedback, offer detailed feedback collection
            if feedback_value == 0:  # thumbs down
                # Create action for detailed feedback
                detailed_feedback_action = cl.Action(
                    name="detailed_feedback",
                    value="collect",
                    label="💬 Share Details",
                    description="Tell us how we can improve"
                )

                await cl.Message(
                    content="Sorry this response wasn't helpful. Would you like to share more details?",
                    actions=[detailed_feedback_action],
                    author="System"
                ).send()
            else:
                # Brief positive acknowledgment
                await cl.Message(
                    content="✅ Thanks for the positive feedback!",
                    author="System"
                ).send()

        else:
            logger.error(f"Failed to record feedback for message {message_id}")

    except Exception as e:
        logger.log_exception("Error processing feedback", e)
        logger.debug(f"Feedback object attributes: {dir(feedback) if feedback else 'None'}")


# Action: Detailed Feedback Collection
@cl.action_callback("detailed_feedback")
async def on_detailed_feedback(action):
    """Handle detailed feedback collection action."""
    await collect_detailed_feedback()





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
