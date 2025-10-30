#!/usr/bin/env python3
"""
CWE ChatBot - Story 2.1 Implementation
Chainlit application with NLU, security sanitization, and RAG response generation.
Integrates with Story 1.5 production infrastructure.
"""

import logging
import os
import sys
import time
from typing import Any, Dict, Optional

import chainlit as cl
from chainlit.data.sql_alchemy import SQLAlchemyDataLayer

# Use the extended config which loads from environment files automatically
from src.app_config import config as app_config

# Configure Chainlit data layer DATABASE_URL for feedback persistence
# Must be set before importing chainlit modules that initialize data layer
database_url = app_config.database_url
os.environ["DATABASE_URL"] = database_url
print(
    f"[STARTUP] DATABASE_URL configured for Chainlit data layer: {database_url[:50]}...",
    flush=True,
)

# Initialize SQLAlchemy data layer for feedback persistence
# Convert postgresql:// to postgresql+asyncpg:// for async support
database_url_async = database_url.replace("postgresql://", "postgresql+asyncpg://")


@cl.data_layer
def get_data_layer():
    """Initialize PostgreSQL data layer for thread/step/feedback persistence."""
    data_layer = SQLAlchemyDataLayer(conninfo=database_url_async)
    print(f"[STARTUP] SQLAlchemyDataLayer created: {type(data_layer)}", flush=True)
    return data_layer


print("[STARTUP] SQLAlchemyDataLayer initialized for feedback persistence", flush=True)

# Verify data layer is registered
from chainlit.data import get_data_layer as get_registered_data_layer  # noqa: E402

dl = get_registered_data_layer()
print(f"[STARTUP] Data layer registered: {type(dl)}", flush=True)
print(f"[STARTUP] Data layer is None: {dl is None}", flush=True)
if dl:
    print(f"[STARTUP] Data layer conninfo: {database_url_async[:60]}...", flush=True)


# Password auth removed - using OAuth (Google/GitHub) for staging and production
# API key auth available via /api/v1/test-login endpoint when AUTH_MODE=hybrid

# Imports after DATABASE_URL setup (required for Chainlit data layer initialization)
from src.conversation import ConversationManager  # noqa: E402
from src.file_processor import FileProcessor  # noqa: E402
from src.input_security import InputSanitizer, SecurityValidator  # noqa: E402

# Story S-12: Import security middleware and CSRF protection
from src.security import (  # noqa: E402
    SecurityHeadersMiddleware,
    require_csrf,
)
from src.security.secure_logging import get_secure_logger  # noqa: E402

# Import the new UI modules
from src.ui import UISettings, create_chat_profiles  # noqa: E402
from src.utils.session import get_user_context  # noqa: E402

# NEW: session bootstrap orchestrator extracted from start()
try:
    from apps.chatbot.session_init import SessionInitializer  # noqa: E402
except ModuleNotFoundError:
    # In Docker container, files are in /app/ (not apps/chatbot/)
    from session_init import SessionInitializer  # noqa: E402

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = get_secure_logger(__name__)

# Story S-12: Add security middleware to Chainlit's Starlette app
# Predeclare asgi_app to satisfy static type checkers when imports fail
asgi_app: Any | None = None
try:
    from chainlit.server import app as asgi_app
    from starlette.middleware.cors import CORSMiddleware
    from starlette.responses import FileResponse, Response

    # Add SecurityHeadersMiddleware for CSP, HSTS, XFO, WebSocket origin validation
    asgi_app.add_middleware(SecurityHeadersMiddleware)
    logger.info("SecurityHeadersMiddleware added to Chainlit app")

    # Add CORS middleware if PUBLIC_ORIGIN is configured
    public_origin = os.getenv("PUBLIC_ORIGIN", "").rstrip("/")
    if public_origin:
        asgi_app.add_middleware(
            CORSMiddleware,
            allow_origins=[public_origin],
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
        )
        logger.info(f"CORS middleware configured for origin: {public_origin}")

    # D4 Issue #2 fix: Add /logo endpoint to eliminate 404 warnings
    from starlette.requests import Request
    from starlette.routing import Route

    async def get_logo(request: Request):
        """
        Serve theme-appropriate logo for Chainlit UI.
        D4 Issue #2: Chainlit 2.8.0 requests /logo?theme=light/dark
        """
        import os.path

        theme = request.query_params.get("theme", "light")
        logo_file = "logo_dark.png" if theme == "dark" else "logo_light.png"
        logo_path = os.path.join(os.path.dirname(__file__), "public", logo_file)

        if os.path.exists(logo_path):
            return FileResponse(
                logo_path,
                media_type="image/png",
                headers={"Cache-Control": "public, max-age=3600"},
            )
        else:
            # Fallback to existing cwe-logo.png if theme logos don't exist
            fallback_path = os.path.join(
                os.path.dirname(__file__), "public", "cwe-logo.png"
            )
            if os.path.exists(fallback_path):
                return FileResponse(
                    fallback_path,
                    media_type="image/png",
                    headers={"Cache-Control": "public, max-age=3600"},
                )
            return Response(status_code=404, content="Logo not found")

    # Add the route explicitly to the Starlette app
    logo_route = Route("/logo", get_logo, methods=["GET"])
    asgi_app.router.routes.insert(
        0, logo_route
    )  # Insert at beginning to override any catchall
    logger.info("Custom /logo endpoint added to eliminate 404 warnings (D4 Issue #2)")

except Exception as e:
    logger.warning(f"Could not add security middleware: {e}")

# Story CWE-82: Add REST API for programmatic query access (testing/integrations)
try:
    from api import router as api_router

    if asgi_app is not None:
        asgi_app.include_router(api_router)
        logger.info("REST API router mounted at /api/v1")
    else:
        logger.warning("ASGI app unavailable; skipping REST API router mount")
except Exception as e:
    logger.warning(f"Could not mount REST API router: {e}")

# Global components (initialized on startup)
conversation_manager: Optional[ConversationManager] = None
input_sanitizer: Optional[InputSanitizer] = None
security_validator: Optional[SecurityValidator] = None
file_processor: Optional[FileProcessor] = None
_init_ok: bool = False

# NEW: we'll lazily create a message handler instance once init succeeds
_message_handler = None


def requires_authentication() -> bool:
    """Check if authentication is required based on configuration and available providers."""
    # Require auth only when OAuth is enabled AND at least one provider is configured.
    return app_config.enable_oauth and app_config.oauth_providers_configured


def is_user_authenticated() -> bool:
    """Check if the current user is authenticated (only relevant if OAuth is enabled and configured)."""
    if not requires_authentication():
        return True  # Always authenticated if OAuth is disabled or not configured

    user = cl.user_session.get("user")
    return user is not None


def initialize_components() -> bool:
    """
    Initialize all Story 2.1 chatbot components with error handling.

    Uses Bootstrapper pattern to reduce cyclomatic complexity.
    """
    global \
        conversation_manager, \
        input_sanitizer, \
        security_validator, \
        file_processor, \
        _init_ok

    # Log initialization attempt
    logger.debug("initialize_components() called")
    logger.debug(
        f"_init_ok={_init_ok}, conversation_manager={'present' if conversation_manager else 'None'}"
    )

    # Prevent double initialization
    if _init_ok and conversation_manager is not None:
        logger.info("Components already initialized, skipping initialization")
        return True

    try:
        logger.debug("Starting component initialization")

        # Use Bootstrapper to handle complex initialization logic
        try:
            from apps.chatbot.bootstrap import Bootstrapper
        except ModuleNotFoundError:
            from bootstrap import Bootstrapper

        bootstrapper = Bootstrapper(db_factory=None, cm_factory=ConversationManager)
        components = bootstrapper.initialize()

        if not components.ok:
            logger.error("Bootstrapper initialization failed")
            _init_ok = False
            return False

        # Assign components to globals
        conversation_manager = components.conversation_manager
        input_sanitizer = components.input_sanitizer
        security_validator = components.security_validator
        file_processor = components.file_processor

        _init_ok = True
        logger.info("Component initialization completed successfully")
        # Create the high-level message handler now that globals exist
        _create_message_handler()
        return _init_ok

    except Exception as e:
        logger.error(f"Initialization FAILED: {type(e).__name__}: {e}")
        import traceback

        if os.getenv("LOG_LEVEL") == "DEBUG":
            traceback.print_exc()
        logger.log_exception(
            "Component initialization failed", e, extra_context={"component": "startup"}
        )
        _init_ok = False
        return _init_ok


# NEW helper: build MessageHandler once we have the components
def _create_message_handler() -> None:
    """
    Instantiate the MessageHandler that powers @cl.on_message.
    Safe to call multiple times; it will no-op after first success.
    """
    global _message_handler
    if _message_handler is not None:
        return
    if not (conversation_manager and file_processor):
        # can't wire yet
        return

    try:
        from apps.chatbot.handlers import MessageHandler  # local import to avoid cycles
    except ModuleNotFoundError:
        from handlers import MessageHandler

    _message_handler = MessageHandler(
        conversation_manager=conversation_manager,
        file_processor=file_processor,
        app_config=app_config,
        requires_authentication_fn=requires_authentication,
        is_user_authenticated_fn=is_user_authenticated,
    )


@cl.set_chat_profiles
async def set_profiles(user: Optional[cl.User] = None):
    """Expose personas as top-bar chat profiles for quick access."""
    return create_chat_profiles()


async def oauth_callback(
    provider_id: str,
    token: str,
    raw_user_data: Dict[str, Any],
    _default_user: cl.User,
    id_token: Optional[str] = None,
) -> Optional[cl.User]:
    """
    Handle OAuth callback for Google and GitHub providers.

    Args:
        provider_id: OAuth provider ("google" or "github")
        token: OAuth access token
        raw_user_data: Raw user data from OAuth provider (can contain nested dicts/lists)
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
            # GitHub email might be in different places depending on privacy settings
            email = raw_user_data.get("email")
            # If email is None or empty, try to get from emails array (for private emails)
            if not email and "emails" in raw_user_data:
                # GitHub returns emails as array, get primary verified email
                for email_obj in raw_user_data.get("emails", []):
                    if email_obj.get("primary") and email_obj.get("verified"):
                        email = email_obj.get("email")
                        break
                # Fallback to first verified email
                if not email:
                    for email_obj in raw_user_data.get("emails", []):
                        if email_obj.get("verified"):
                            email = email_obj.get("email")
                            break
            name = raw_user_data.get("name") or raw_user_data.get("login")
            avatar_url = raw_user_data.get("avatar_url")
        else:
            logger.warning(f"Unsupported OAuth provider: {provider_id}")
            return None

        if not email:
            logger.warning(f"No email found in OAuth data for provider: {provider_id}")
            return None

        # Check if the user is in the whitelist
        if not app_config.is_user_allowed(email):
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
                "raw_data": raw_user_data,
            },
        )

        logger.info(f"Successfully authenticated user: {email} via {provider_id}")
        return user

    except Exception as e:
        logger.log_exception(f"OAuth callback error for provider {provider_id}", e)
        return None


@cl.on_chat_start
async def start():
    """
    Initialize the chat session (Chainlit on_chat_start hook).

    This function is now intentionally very small to keep cyclomatic complexity
    under Ruff C901 thresholds. All of the real work has moved to
    SessionInitializer in session_init.py.
    """
    global conversation_manager, _init_ok

    logger.debug("@cl.on_chat_start triggered - User connected to chat")
    logger.debug(
        "conversation_manager=%s, _init_ok=%s",
        "present" if conversation_manager else "None",
        _init_ok,
    )

    initializer = SessionInitializer(
        app_config=app_config,
        conversation_manager=conversation_manager if _init_ok else None,
        requires_authentication_fn=requires_authentication,
        is_user_authenticated_fn=is_user_authenticated,
    )

    await initializer.run()


@cl.on_message
async def main(message: cl.Message):
    """
    Slim wrapper that delegates to MessageHandler.
    Keeps this function below Ruff C901 threshold.
    """
    global _message_handler

    # If startup failed, surface the same message you already show elsewhere
    if not conversation_manager or not _init_ok:
        await cl.Message(
            content=(
                "Startup error: configuration missing or database unavailable. "
                "Please check environment (GEMINI_API_KEY/DB)."
            )
        ).send()
        return

    # Ensure handler exists (defensive for hot-reload / partial init)
    if _message_handler is None:
        _create_message_handler()
    if _message_handler is None:
        # still not available -> graceful fallback
        await cl.Message(
            content=(
                "Initialization error: message handler not available. "
                "Please retry later."
            ),
            author="System",
        ).send()
        return

    await _message_handler.handle(message)


@cl.action_callback("ask_question")
async def on_ask_action(action: cl.Action):
    """Handle 'Ask Question' action button for CWE Analyzer."""

    # Authentication enforcement - require OAuth authentication if enabled
    if requires_authentication() and not is_user_authenticated():
        await cl.Message(
            content="🔒 Authentication required. Please authenticate to use actions.",
            author="System",
        ).send()
        return

    # Story S-12: CSRF validation for state-changing action
    if not require_csrf(action.payload):
        await cl.Message(
            content="❌ Invalid request token. Please refresh the page and try again.",
            author="System",
        ).send()
        logger.warning("CSRF validation failed for ask_question action")
        return

    try:
        # Get user context using centralized helper
        context = get_user_context()

        # Activate question mode
        context.analyzer_mode = "question"

        # Save the updated context back to the session (critical step)
        from src.utils.session import set_user_context

        set_user_context(context)

        await cl.Message(
            content="**❓ Question mode activated.** Ask a follow-up question about the analysis above.",
            author="System",
        ).send()

        logger.info(
            f"Action 'ask_question' activated analyzer mode: {context.analyzer_mode}"
        )

    except Exception as e:
        logger.log_exception("Error handling ask action", e)
        await cl.Message(
            content="Sorry, there was an error processing that action. Please try again.",
            author="System",
        ).send()


@cl.action_callback("exit_question_mode")
async def on_exit_question_action(action: cl.Action):
    """Handle 'Exit Question Mode' action button for CWE Analyzer."""

    # Authentication enforcement - require OAuth authentication if enabled
    if requires_authentication() and not is_user_authenticated():
        await cl.Message(
            content="🔒 Authentication required. Please authenticate to use actions.",
            author="System",
        ).send()
        return

    # Story S-12: CSRF validation for state-changing action
    if not require_csrf(action.payload):
        await cl.Message(
            content="❌ Invalid request token. Please refresh the page and try again.",
            author="System",
        ).send()
        logger.warning("CSRF validation failed for exit_question_mode action")
        return

    try:
        # Get user context using centralized helper
        context = get_user_context()

        # Exit question mode
        context.analyzer_mode = None

        # Save the updated context back to the session (critical step)
        from src.utils.session import set_user_context

        set_user_context(context)

        await cl.Message(
            content="✅ **Exited question mode.** You can now ask general CWE questions or start a new analysis.",
            author="System",
        ).send()

        logger.info("Action 'exit_question_mode' deactivated analyzer mode")

    except Exception as e:
        logger.log_exception("Error handling exit question mode action", e)
        await cl.Message(
            content="Sorry, there was an error processing that action. Please try again.",
            author="System",
        ).send()


@cl.action_callback("example_cwe79")
async def on_example_cwe79_action(action: cl.Action):
    """Handle 'What is CWE-79' example query button."""
    await handle_example_query_action(action)


@cl.action_callback("example_sql_injection")
async def on_example_sql_injection_action(action: cl.Action):
    """Handle 'SQL injection prevention' example query button."""
    await handle_example_query_action(action)


@cl.action_callback("example_xss_types")
async def on_example_xss_types_action(action: cl.Action):
    """Handle 'Explain XSS types' example query button."""
    await handle_example_query_action(action)


@cl.action_callback("example_nvidia_cve")
async def on_example_nvidia_cve_action(action: cl.Action):
    """Handle NVIDIA CVE analysis example query button (CWE Analyzer persona)."""
    await handle_example_query_action(action)


@cl.action_callback("example_phpgurukul_cve")
async def on_example_phpgurukul_cve_action(action: cl.Action):
    """Handle PHPGurukul SQL injection CVE analysis example query button (CWE Analyzer persona)."""
    await handle_example_query_action(action)


@cl.action_callback("example_wordpress_xss")
async def on_example_wordpress_xss_action(action: cl.Action):
    """Handle WordPress XSS CVE analysis example query button (CWE Analyzer persona)."""
    await handle_example_query_action(action)


@cl.action_callback("example_tomcat_cve")
async def on_example_tomcat_cve_action(action: cl.Action):
    """Handle Apache Tomcat CVE example query button (CVE Creator persona)."""
    await handle_example_query_action(action)


@cl.action_callback("example_rocketmq_rce")
async def on_example_rocketmq_rce_action(action: cl.Action):
    """Handle Apache RocketMQ RCE example query button (CVE Creator persona)."""
    await handle_example_query_action(action)


@cl.action_callback("example_netfilter_overflow")
async def on_example_netfilter_overflow_action(action: cl.Action):
    """Handle Linux netfilter overflow example query button (CVE Creator persona)."""
    await handle_example_query_action(action)


async def handle_example_query_action(action: cl.Action):
    """
    Common handler for example query action buttons.

    Extracts the query from the action payload and processes it as if
    the user typed it in the chat input.
    """
    # Authentication enforcement - require OAuth authentication if enabled
    if requires_authentication() and not is_user_authenticated():
        await cl.Message(
            content="🔒 Authentication required. Please authenticate to use example queries.",
            author="System",
        ).send()
        return

    try:
        # Extract query from action payload
        query = action.payload.get("query", "")
        if not query:
            logger.error("Example query action missing query in payload")
            await cl.Message(
                content="Sorry, there was an error with that example query. Please try typing your question instead.",
                author="System",
            ).send()
            return

        # For CWE Analyzer and CVE Creator buttons, display the full input text first
        # This makes it clear what vulnerability description is being processed
        vulnerability_analysis_buttons = [
            "example_nvidia_cve",
            "example_phpgurukul_cve",
            "example_wordpress_xss",
            "example_tomcat_cve",
            "example_rocketmq_rce",
            "example_netfilter_overflow",
        ]
        if action.name in vulnerability_analysis_buttons:
            # Display the full CVE/vulnerability description as "Input for Analysis"
            await cl.Message(
                content=f"**📝 Input for Analysis:**\n\n{query}",
                author="User",
            ).send()

        # Create a fake message object to reuse the existing message handler
        # We'll process it through the same pipeline as user-typed messages
        fake_message = cl.Message(content=query, author="User")

        # Process the query using the main message handler logic
        await main(fake_message)

        logger.info(f"Processed example query action: {query[:100]}...")

    except Exception as e:
        logger.log_exception("Error handling example query action", e)
        await cl.Message(
            content="Sorry, there was an error processing that example query. Please try typing your question instead.",
            author="System",
        ).send()


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
        _ = cl.context.session.id

        # Normalize settings to our UISettings model and persist.
        # Merge with existing stored settings so missing fields (like persona when using top profiles)
        # are preserved rather than reset to defaults.
        existing = cl.user_session.get("ui_settings") or {}
        merged = {**existing, **(settings or {})}
        model = UISettings(**merged)
        cl.user_session.set("ui_settings", model.dict())

        # Synchronize settings to UserContext so they affect LLM responses
        user_context = get_user_context()
        if user_context:
            user_context.response_detail_level = model.detail_level
            user_context.include_examples = model.include_examples
            user_context.include_mitigations = model.include_mitigations
            logger.info(
                f"Settings synchronized to UserContext: detail={model.detail_level}, examples={model.include_examples}, mitigations={model.include_mitigations}"
            )

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
            # feedback_prompt is a dict with 'output' key containing the user's response
            feedback_content = (
                feedback_prompt.get("output", "")
                if isinstance(feedback_prompt, dict)
                else str(feedback_prompt)
            )
            cl.user_session.set(
                "detailed_feedback",
                {
                    "timestamp": time.time(),
                    "content": feedback_content,
                    "session_id": session_id,
                },
            )

            # Send acknowledgment
            await cl.Message(
                content="🙏 Thank you for your detailed feedback! Your input helps us improve the CWE ChatBot experience.",
                author="System",
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
        message_id = getattr(feedback, "forId", getattr(feedback, "for_id", None))

        if not message_id:
            logger.error("Feedback received but no message ID found")
            return

        # Convert Chainlit feedback to our rating system (1-5 scale)
        feedback_value = getattr(feedback, "value", None)
        if feedback_value is None:
            logger.error("Feedback received but no value found")
            return

        rating = 5 if feedback_value == 1 else 2  # Map thumbs up to 5, thumbs down to 2

        # Record feedback in conversation manager
        success = conversation_manager.record_feedback(session_id, message_id, rating)

        if success:
            logger.info(
                f"Recorded feedback for message {message_id}: rating {rating} (feedback value: {feedback_value})"
            )

            # For negative feedback, collect details directly (no actions)
            if feedback_value == 0:  # thumbs down
                await collect_detailed_feedback()
            else:
                # Brief positive acknowledgment
                await cl.Message(
                    content="✅ Thanks for the positive feedback!", author="System"
                ).send()

        else:
            logger.error(f"Failed to record feedback for message {message_id}")

    except Exception as e:
        logger.log_exception("Error processing feedback", e)
        logger.debug(
            f"Feedback object attributes: {dir(feedback) if feedback else 'None'}"
        )


# Actions removed; detailed feedback collected directly on thumbs-down


def main_cli():
    """CLI entry point for running the Story 2.1 application."""
    # Initialize components on startup
    if not initialize_components():
        logger.error("Failed to initialize Story 2.1 components. Exiting.")
        sys.exit(1)

    logger.info("CWE ChatBot Story 2.1 is ready to serve requests")


# Initialize components when module loads for Chainlit
# Wrap in try/except to allow Chainlit to start even if initialization fails
# This ensures the web server starts and can display error messages to users
try:
    logger.debug("Module-level initialization starting")
    initialize_components()
    logger.debug("Module-level initialization completed")
except Exception as e:
    logger.error(f"Module-level initialization FAILED: {type(e).__name__}: {e}")
    logger.warning("Chainlit will start but components will be unavailable")
    import traceback

    if os.getenv("LOG_LEVEL") == "DEBUG":
        traceback.print_exc()
    # Don't re-raise - let Chainlit start anyway so users get helpful error messages


@cl.on_stop
async def on_stop() -> None:
    """Gracefully close resources when the app stops."""
    try:
        if conversation_manager and getattr(
            conversation_manager, "query_handler", None
        ):
            qh = conversation_manager.query_handler
            close_fn = getattr(qh, "close", None)
            if callable(close_fn):
                close_fn()
                logger.info("Closed retriever/database resources")
        # Dispose global SQLAlchemy engine if present
        try:
            from src.db import close as db_close

            db_close()
            logger.info("Disposed SQLAlchemy engine")
        except Exception as e:
            logger.warning(f"Engine dispose failed: {e}")
    except Exception as e:
        logger.log_exception("Shutdown cleanup failed", e)


# Log OAuth configuration status and register callback if needed
if app_config.enable_oauth:
    has_google_oauth = app_config.google_oauth_configured
    has_github_oauth = app_config.github_oauth_configured

    if has_google_oauth or has_github_oauth:
        # Register OAuth callback decorator
        cl.oauth_callback(oauth_callback)
        providers = []
        if has_google_oauth:
            providers.append("Google")
        if has_github_oauth:
            providers.append("GitHub")
        logger.info(f"OAuth callback registered for: {', '.join(providers)}")
    else:
        logger.warning(
            "OAuth enabled but no provider credentials found (OAUTH_*_CLIENT_ID/SECRET). Running in open access mode."
        )
else:
    logger.info("OAuth callback not registered (OAuth disabled)")


# Keep explicit references so static analyzers (e.g., vulture) recognize action handlers
_ACTION_HANDLER_REFS: tuple[object, ...] = (
    on_ask_action,
    on_exit_question_action,
    on_example_cwe79_action,
    on_example_sql_injection_action,
    on_example_xss_types_action,
)

if __name__ == "__main__":
    # This allows running the app directly with: python main.py
    main_cli()

    # Note: Use 'poetry run chainlit run apps/chatbot/main.py' to start the application
    logger.info(
        "To start the application, run: poetry run chainlit run apps/chatbot/main.py"
    )
