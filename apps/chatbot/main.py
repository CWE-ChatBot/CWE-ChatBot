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

from src.user_context import UserPersona, UserContext
from src.conversation import ConversationManager
from src.input_security import InputSanitizer, SecurityValidator
from src.file_processor import FileProcessor
from src.security.secure_logging import get_secure_logger
# Use the extended config which loads from environment files automatically
from src.app_config_extended import config as app_config
# Import the new UI modules
from src.ui import UIMessaging, UISettings, create_chat_profiles
from src.utils.session import get_user_context


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = get_secure_logger(__name__)

# Global components (initialized on startup)
conversation_manager: Optional[ConversationManager] = None
input_sanitizer: Optional[InputSanitizer] = None
security_validator: Optional[SecurityValidator] = None
file_processor: Optional[FileProcessor] = None
_init_ok: bool = False


def requires_authentication() -> bool:
    """Check if authentication is required based on configuration and available providers."""
    if not app_config.enable_oauth:
        return False

    # Check if OAuth credentials are actually configured
    has_google_oauth = bool(os.getenv("OAUTH_GOOGLE_CLIENT_ID") and os.getenv("OAUTH_GOOGLE_CLIENT_SECRET"))
    has_github_oauth = bool(os.getenv("OAUTH_GITHUB_CLIENT_ID") and os.getenv("OAUTH_GITHUB_CLIENT_SECRET"))

    return has_google_oauth or has_github_oauth


def is_user_authenticated() -> bool:
    """Check if the current user is authenticated (only relevant if OAuth is enabled and configured)."""
    if not requires_authentication():
        return True  # Always authenticated if OAuth is disabled or not configured

    user = cl.user_session.get("user")
    return user is not None


def initialize_components() -> bool:
    """Initialize all Story 2.1 chatbot components with error handling."""
    global conversation_manager, input_sanitizer, security_validator, file_processor, _init_ok

    # Prevent double initialization
    if _init_ok and conversation_manager is not None:
        logger.info("Components already initialized, skipping initialization")
        return True

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

        # Log OAuth configuration status
        if not app_config.enable_oauth:
            logger.info("OAuth mode: disabled (open access)")
        else:
            has_google_oauth = bool(os.getenv("OAUTH_GOOGLE_CLIENT_ID") and os.getenv("OAUTH_GOOGLE_CLIENT_SECRET"))
            has_github_oauth = bool(os.getenv("OAUTH_GITHUB_CLIENT_ID") and os.getenv("OAUTH_GITHUB_CLIENT_SECRET"))
            if has_google_oauth or has_github_oauth:
                providers = []
                if has_google_oauth:
                    providers.append("Google")
                if has_github_oauth:
                    providers.append("GitHub")
                logger.info(f"OAuth mode: enabled with {', '.join(providers)} provider(s)")
            else:
                logger.info("OAuth mode: enabled but no provider credentials found (running in open access mode)")

        _init_ok = True
        return _init_ok
    except Exception as e:
        logger.log_exception("Component initialization failed", e, extra_context={"component": "startup"})
        _init_ok = False
        return _init_ok


@cl.set_chat_profiles
def set_profiles():
    """Expose personas as top-bar chat profiles for quick access."""
    return create_chat_profiles()


def oauth_callback(
    provider_id: str,
    token: str,
    raw_user_data: Dict[str, str],
    default_user: cl.User,
) -> Optional[cl.User]:
    """
    Handle OAuth callback for Google and GitHub providers.

    Args:
        provider_id: OAuth provider ("google" or "github")
        token: OAuth access token
        raw_user_data: Raw user data from OAuth provider
        default_user: Default user object from Chainlit

    Returns:
        cl.User object with provider-specific metadata or None
    """
    try:
        logger.info(f"OAuth callback for provider: {provider_id}")

        # Extract user info based on provider
        if provider_id == "google":
            email = raw_user_data.get("email")
            name = raw_user_data.get("name")
            avatar_url = raw_user_data.get("picture")
        elif provider_id == "github":
            email = raw_user_data.get("email")
            name = raw_user_data.get("name") or raw_user_data.get("login")
            avatar_url = raw_user_data.get("avatar_url")
        else:
            logger.warning(f"Unsupported OAuth provider: {provider_id}")
            return None

        if not email:
            logger.warning(f"No email found in OAuth data for provider: {provider_id}")
            return None

        # Check if the user is in the whitelist
        allowed_users_str = os.getenv("ALLOWED_USERS")
        if allowed_users_str:
            allowed_users = [user.strip() for user in allowed_users_str.split(",")]
            
            is_allowed = False
            for allowed_user in allowed_users:
                if allowed_user.startswith("@"):
                    # Domain-based check
                    if email.endswith(allowed_user):
                        is_allowed = True
                        break
                else:
                    # Email-based check
                    if email == allowed_user:
                        is_allowed = True
                        break
            
            if not is_allowed:
                logger.warning(f"Unauthorized user: {email}")
                return None

        # Create user with provider-specific data
        user = cl.User(
            identifier=f"{provider_id}:{email}",
            metadata={
                "provider": provider_id,
                "email": email,
                "name": name or email.split("@")[0],
                "avatar_url": avatar_url,
                "raw_data": raw_user_data
            }
        )

        logger.info(f"Successfully authenticated user: {email} via {provider_id}")
        return user

    except Exception as e:
        logger.log_exception(f"OAuth callback error for provider {provider_id}", e)
        return None


@cl.on_chat_start
async def start():
    """Initialize the chat session with settings-based persona configuration."""
    global conversation_manager

    if not conversation_manager or not _init_ok:
        await cl.Message(content="Startup error: configuration missing or database unavailable. Please check environment (GEMINI_API_KEY/DB).").send()
        return

    # Authentication enforcement - require OAuth authentication if enabled
    if requires_authentication() and not is_user_authenticated():
        await cl.Message(
            content="🔒 Authentication required. Please authenticate using Google or GitHub to access the CWE ChatBot.",
            author="System"
        ).send()
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

    # Initialize per-user context in Chainlit with centralized helper
    session_id = cl.context.session.id

    # Import and use centralized helper
    from src.utils.session import get_user_context
    user_context = get_user_context()

    # Set the persona from the selected chat profile (only if changed)
    if user_context.persona != persona:
        user_context.persona = persona

    # Integrate OAuth authentication with user context (if OAuth is enabled)
    if requires_authentication():
        user = cl.user_session.get("user")
        if user and hasattr(user, 'metadata') and user.metadata:
            try:
                # User is authenticated via OAuth - integrate with UserContext
                if user_context:
                    user_context.set_oauth_data(
                        provider=user.metadata.get("provider"),
                        email=user.metadata.get("email"),
                        name=user.metadata.get("name"),
                        avatar_url=user.metadata.get("avatar_url")
                    )
                    # Update activity timestamp for session management
                    user_context.update_activity()
                    logger.info(f"OAuth integration completed for user: {user.metadata.get('email')}")

                    # Integrate persona selection with authenticated user context
                    user_context.persona = persona
                    logger.info(f"Persona '{persona}' assigned to authenticated user: {user.metadata.get('email')}")

                # Store session validation data
                cl.user_session.set("auth_timestamp", time.time())
                cl.user_session.set("auth_provider", user.metadata.get("provider"))
                cl.user_session.set("auth_email", user.metadata.get("email"))

            except Exception as e:
                logger.log_exception("OAuth integration error during chat start", e)
                await cl.Message(
                    content="⚠️ Authentication integration error. Some features may not work properly. Please try refreshing the page.",
                    author="System"
                ).send()
    else:
        # OAuth is disabled - just set persona without authentication integration
        if user_context:
            user_context.persona = persona
            logger.info(f"Persona '{persona}' assigned (OAuth disabled mode)")

    # Enhanced onboarding welcome message with progressive introduction
    # Personalize welcome if user is authenticated (OAuth mode only)
    user_greeting = "Welcome to the CWE ChatBot! 🛡️"
    if requires_authentication():
        user = cl.user_session.get("user")
        if user and user.metadata:
            user_name = user.metadata.get("name") or user.metadata.get("email", "").split("@")[0]
            provider = user.metadata.get("provider", "OAuth").title()
            user_greeting = f"Welcome back, {user_name}! 🛡️\n\n*Authenticated via {provider}*\n\n🔐 *Your session is secure and your persona preferences will be saved.*"
    else:
        user_greeting = f"Welcome to the CWE ChatBot! 🛡️\n\n*Running in open access mode (OAuth disabled)*"

    welcome_message = f"""{user_greeting}

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
        display="inline"
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

    # Optional: Debug action rendering if DEBUG_ACTIONS=1 (disabled due to environment ValidationError)
    # To test actions, use the CWE Analyzer flow or thumbs-down feedback instead.

    # Users can upload files via Chainlit's spontaneous file upload feature (config.toml)


@cl.on_message
async def main(message: cl.Message):
    """Handle incoming messages with Story 2.1 NLU and RAG pipeline."""

    # Authentication enforcement - require OAuth authentication if enabled
    if requires_authentication() and not is_user_authenticated():
        await cl.Message(
            content="🔒 Authentication required. Please authenticate using Google or GitHub to send messages.",
            author="System"
        ).send()
        return

    # Session validation and activity tracking
    try:
        user_context = get_user_context()
        if user_context and user_context.is_authenticated:
            user_context.update_activity()
    except Exception as e:
        logger.log_exception("Failed to update user activity", e)

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

        # Manual feedback command as fallback when thumbs UI is unavailable
        if user_query.lower().startswith("/feedback"):
            await cl.Message(content="Opening feedback prompt...").send()
            await collect_detailed_feedback()
            return

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

        # Main Processing Pipeline with Step Visualization
        async with cl.Step(name="Analyze security query", type="tool") as analysis_step:
            analysis_step.input = f"Query: '{user_query[:100]}...' | Persona: {current_persona}"
            analysis_step.output = "Query validated and ready for CWE analysis"

            # Process message using conversation manager with streaming (true streaming)
            result = await conversation_manager.process_user_message_streaming(
                session_id=session_id,
                message_content=user_query,
                message_id=message.id
            )

        # Create source cards as Chainlit Elements if we have retrieved chunks
        elements = []
        if result.get("retrieved_cwes") and result.get("chunk_count", 0) > 0:
            async with cl.Step(name="Prepare source references", type="tool") as sources_step:
                # Get the retrieved chunks to create source elements
                retrieved_chunks = result.get("retrieved_chunks", [])
                elements = UIMessaging.create_source_elements(retrieved_chunks)
                sources_step.output = f"Created {len(elements)} source references"

        # Add uploaded file evidence as a side element (if present)
        file_ctx = cl.user_session.get("uploaded_file_context")
        if file_ctx:
            evidence = UIMessaging.create_file_evidence_element(file_ctx)
            elements.append(evidence)

        # Add metadata for debugging if needed
        if not result.get("is_safe", True):
            logger.warning(f"Security flags detected: {result.get('security_flags', [])}")

        # Apply progressive disclosure based on UI settings and update message with elements
        if result.get("message"):
            # Apply progressive disclosure if configured
            elements = UIMessaging.apply_progressive_disclosure(result["message"], ui_settings, elements)
            # Update message with all elements
            await UIMessaging.update_message_with_elements(result["message"], elements)

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


# Actions removed: follow-ups now driven by slash commands (/ask, /compare, /exit)


@cl.on_settings_update
async def on_settings_update(settings: Dict[str, Any]):
    """Handle settings updates from the native Chainlit settings panel."""
    global conversation_manager

    # Authentication enforcement - require OAuth authentication if enabled
    if requires_authentication() and not is_user_authenticated():
        return

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

            # For negative feedback, collect details directly (no actions)
            if feedback_value == 0:  # thumbs down
                await collect_detailed_feedback()
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


# Actions removed; detailed feedback collected directly on thumbs-down





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


# Conditionally register OAuth callback only if OAuth is enabled AND provider credentials are set
if app_config.enable_oauth:
    # Check if any OAuth provider credentials are actually configured
    has_google_oauth = bool(os.getenv("OAUTH_GOOGLE_CLIENT_ID") and os.getenv("OAUTH_GOOGLE_CLIENT_SECRET"))
    has_github_oauth = bool(os.getenv("OAUTH_GITHUB_CLIENT_ID") and os.getenv("OAUTH_GITHUB_CLIENT_SECRET"))

    if has_google_oauth or has_github_oauth:
        # Register the OAuth callback decorator
        oauth_callback = cl.oauth_callback(oauth_callback)
        providers = []
        if has_google_oauth:
            providers.append("Google")
        if has_github_oauth:
            providers.append("GitHub")
        logger.info(f"OAuth callback registered for: {', '.join(providers)}")
    else:
        logger.warning("OAuth enabled but no provider credentials found (OAUTH_*_CLIENT_ID/SECRET). Running in open access mode.")
else:
    logger.info("OAuth callback not registered (OAuth disabled)")


if __name__ == "__main__":
    # This allows running the app directly with: python main.py
    main_cli()

    # Note: Use 'poetry run chainlit run apps/chatbot/main.py' to start the application
    logger.info("To start the application, run: poetry run chainlit run apps/chatbot/main.py")
