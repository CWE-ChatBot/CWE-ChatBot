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
import time
from typing import Any, Dict, List, Optional, cast

import chainlit as cl
from chainlit.input_widget import InputWidget, Select, Switch

# Use the extended config which loads from environment files automatically
from src.app_config import config as app_config
from src.conversation import ConversationManager
from src.file_processor import FileProcessor
from src.input_security import InputSanitizer, SecurityValidator

# Story S-12: Import security middleware and CSRF protection
from src.security import (
    CSRFManager,
    SecurityHeadersMiddleware,
    require_csrf,
)
from src.security.secure_logging import get_secure_logger

# Import the new UI modules
from src.ui import UIMessaging, UISettings, create_chat_profiles
from src.user_context import UserPersona
from src.utils.session import get_user_context

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
    """Initialize all Story 2.1 chatbot components with error handling."""
    global conversation_manager, input_sanitizer, security_validator, file_processor, _init_ok

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

        # Validate config once; if it fails, we will surface a UI error and disable handlers
        try:
            logger.debug("Validating configuration")
            app_config.validate_config()
            logger.debug("Configuration validation passed")
        except Exception as cfg_err:
            logger.error(f"Configuration validation FAILED: {cfg_err}")
            logger.log_exception(
                "Configuration validation failed",
                cfg_err,
                extra_context={
                    "component": "startup",
                },
            )
            _init_ok = False
            # Still attempt partial initialization to provide a helpful UI message

        # Optional: Validate OAuth configuration if enabled
        try:
            app_config.validate_oauth()
        except Exception as oauth_err:
            logger.log_exception(
                "OAuth configuration error",
                oauth_err,
                extra_context={"component": "startup"},
            )
            # Warning only - don't fail startup, will run in open mode

        # Check for database configuration
        # Option 1: Private IP with password auth (new production setup)
        # Option 2: Cloud SQL Connector with IAM (legacy)
        # Option 3: Traditional database URL (local dev)
        use_private_ip = (
            os.getenv("DB_HOST") and os.getenv("DB_USER") and os.getenv("DB_PASSWORD")
        )
        cloud_sql_instance = os.getenv("INSTANCE_CONN_NAME")
        database_url = os.getenv("DATABASE_URL") or os.getenv("LOCAL_DATABASE_URL")
        gemini_api_key = os.getenv("GEMINI_API_KEY") or app_config.gemini_api_key
        offline_ai = (
            os.getenv("DISABLE_AI") == "1" or os.getenv("GEMINI_OFFLINE") == "1"
        )

        logger.debug(
            f"Environment: DB_HOST={os.getenv('DB_HOST')}, DB_USER={os.getenv('DB_USER')}, "
            f"INSTANCE_CONN_NAME={cloud_sql_instance}, GEMINI_API_KEY={'present' if gemini_api_key else 'missing'}, "
            f"offline_ai={offline_ai}"
        )

        # Initialize database connection
        db_engine = None
        if use_private_ip:
            # Use Private IP direct connection (new production setup)
            logger.info(f"Using Private IP connection to {os.getenv('DB_HOST')}")
            try:
                logger.debug("Importing src.db module")
                from src.db import engine

                logger.debug("Calling engine() to create SQLAlchemy engine")
                db_engine = engine()
                database_url = (
                    "private-ip-connection"  # Placeholder since engine is used
                )
                logger.info("Private IP database engine initialized successfully")
            except Exception as e:
                logger.error(
                    f"Private IP connection initialization FAILED: {type(e).__name__}: {e}"
                )
                if os.getenv("LOG_LEVEL") == "DEBUG":
                    import traceback

                    traceback.print_exc()
                logger.log_exception("Failed to initialize Private IP connection", e)
                raise ValueError(f"Private IP connection initialization failed: {e}")
        elif cloud_sql_instance:
            # Use Cloud SQL Connector for production (legacy)
            logger.info(f"Using Cloud SQL Connector for instance: {cloud_sql_instance}")
            try:
                logger.debug("Importing src.db module")
                from src.db import engine

                logger.debug("Calling engine() to create SQLAlchemy engine")
                db_engine = engine()
                database_url = "cloud-sql-connector"  # Placeholder since engine is used
                logger.info("Cloud SQL Connector engine initialized successfully")
            except Exception as e:
                logger.error(
                    f"Cloud SQL Connector initialization FAILED: {type(e).__name__}: {e}"
                )
                if os.getenv("LOG_LEVEL") == "DEBUG":
                    import traceback

                    traceback.print_exc()
                logger.log_exception("Failed to initialize Cloud SQL Connector", e)
                raise ValueError(f"Cloud SQL Connector initialization failed: {e}")
        else:
            logger.debug(
                "No Private IP or Cloud SQL instance, using traditional database URL"
            )
            # Use traditional database URL for local development
            if not database_url:
                # Derive URL from POSTGRES_* if available
                if app_config.pg_user and app_config.pg_password:
                    # Use postgresql+psycopg:// to use psycopg3 driver (not psycopg2)
                    database_url = f"postgresql+psycopg://{app_config.pg_user}:{app_config.pg_password}@{app_config.pg_host}:{app_config.pg_port}/{app_config.pg_database}"
            if not database_url:
                logger.error("No database configuration found!")
                raise ValueError(
                    "Missing required configuration: database URL, Private IP config, or Cloud SQL instance"
                )

        if not gemini_api_key and not offline_ai:
            logger.error("GEMINI_API_KEY is missing!")
            raise ValueError(
                "Missing required configuration: GEMINI_API_KEY (set DISABLE_AI=1 for offline mode)"
            )

        logger.info(f"Initializing with database: {database_url[:50]}...")

        # Initialize security components
        logger.debug("Initializing security components")
        input_sanitizer = InputSanitizer()
        security_validator = SecurityValidator()
        file_processor = FileProcessor()
        logger.debug("Security components initialized")

        # Initialize conversation manager with all Story 2.1 components
        logger.debug("Initializing ConversationManager")
        conversation_manager = ConversationManager(
            database_url=database_url, gemini_api_key=gemini_api_key, engine=db_engine
        )
        logger.debug("ConversationManager created")

        # Test database connection
        logger.debug("Testing database connection")
        health = conversation_manager.get_system_health()
        logger.debug(f"Health check result: {health}")
        if not health.get("database", False):
            logger.error("Database health check FAILED!")
            raise RuntimeError("Database health check failed")

        logger.info("Database health check passed")
        logger.info("Story 2.1 components initialized successfully")
        logger.info(f"Database health: {health}")

        # Story CWE-82: Set conversation manager for REST API
        try:
            from api import set_conversation_manager

            set_conversation_manager(conversation_manager)
            logger.info("Conversation manager set for REST API")
        except Exception as api_err:
            logger.warning(f"Could not set conversation manager for API: {api_err}")

        # Log OAuth configuration status
        if not app_config.enable_oauth:
            logger.info("OAuth mode: disabled (open access)")
        else:
            has_google_oauth = app_config.google_oauth_configured
            has_github_oauth = app_config.github_oauth_configured
            if has_google_oauth or has_github_oauth:
                providers = []
                if has_google_oauth:
                    providers.append("Google")
                if has_github_oauth:
                    providers.append("GitHub")
                logger.info(
                    f"OAuth mode: enabled with {', '.join(providers)} provider(s)"
                )
            else:
                logger.info(
                    "OAuth mode: enabled but no provider credentials found (running in open access mode)"
                )

        _init_ok = True
        logger.info("Component initialization completed successfully")
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
    """Initialize the chat session with settings-based persona configuration."""
    global conversation_manager

    logger.debug("@cl.on_chat_start triggered - User connected to chat")
    logger.debug(
        f"conversation_manager={'present' if conversation_manager else 'None'}, _init_ok={_init_ok}"
    )

    if not conversation_manager or not _init_ok:
        logger.error(
            f"Initialization check FAILED - conversation_manager: {conversation_manager}, _init_ok: {_init_ok}"
        )
        await cl.Message(
            content="Startup error: configuration missing or database unavailable. Please check environment (GEMINI_API_KEY/DB)."
        ).send()
        return

    # Authentication enforcement - require OAuth authentication if enabled
    if requires_authentication() and not is_user_authenticated():
        await cl.Message(
            content="🔒 Authentication required. Please authenticate using Google or GitHub to access the CWE ChatBot.",
            author="System",
        ).send()
        return

    # Story S-12: Generate CSRF token for this session
    try:
        csrf_manager = CSRFManager()
        csrf_token = csrf_manager.generate_token()
        csrf_manager.set_session_token(csrf_token)
        logger.debug("CSRF token generated for session")
    except Exception as e:
        logger.warning(f"Failed to generate CSRF token: {e}")

    # Initialize default settings and expose a Settings panel
    default_settings = UISettings()
    cl.user_session.set("ui_settings", default_settings.dict())
    selected_profile = cl.user_session.get("chat_profile")
    persona = (
        selected_profile
        if isinstance(selected_profile, str)
        and selected_profile in UserPersona.get_all_personas()
        else UserPersona.DEVELOPER.value
    )

    # Build and display the Chainlit settings panel
    try:
        items = {
            "basic": "basic",
            "standard": "standard",
            "detailed": "detailed",
        }
        widgets: List[InputWidget] = cast(
            List[InputWidget],
            [
                Select(
                    id="detail_level",
                    label="Detail Level",
                    items=items,
                    initial=default_settings.detail_level,
                    description="How much detail to include",
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
            ],
        )
        settings_panel = cl.ChatSettings(widgets)
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
    _ = cl.context.session.id

    # Import and use centralized helper
    from src.utils.session import get_user_context

    user_context = get_user_context()

    # Set the persona from the selected chat profile (only if changed)
    if user_context.persona != persona:
        user_context.persona = persona

    # Integrate OAuth authentication with user context (if OAuth is enabled)
    if requires_authentication():
        user = cl.user_session.get("user")
        if user and hasattr(user, "metadata") and user.metadata:
            try:
                # User is authenticated via OAuth - integrate with UserContext
                if user_context:
                    user_context.set_oauth_data(
                        provider=user.metadata.get("provider"),
                        email=user.metadata.get("email"),
                        name=user.metadata.get("name"),
                        avatar_url=user.metadata.get("avatar_url"),
                    )
                    # Update activity timestamp for session management
                    user_context.update_activity()
                    logger.info(
                        f"OAuth integration completed for user: {user.metadata.get('email')}"
                    )

                    # Integrate persona selection with authenticated user context
                    user_context.persona = persona
                    logger.info(
                        f"Persona '{persona}' assigned to authenticated user: {user.metadata.get('email')}"
                    )

                # Store session validation data
                cl.user_session.set("auth_timestamp", time.time())
                cl.user_session.set("auth_provider", user.metadata.get("provider"))
                cl.user_session.set("auth_email", user.metadata.get("email"))

            except Exception as e:
                logger.log_exception("OAuth integration error during chat start", e)
                await cl.Message(
                    content="⚠️ Authentication integration error. Some features may not work properly. Please try refreshing the page.",
                    author="System",
                ).send()
    else:
        # OAuth is disabled - just set persona without authentication integration
        if user_context:
            user_context.persona = persona
            logger.info(f"Persona '{persona}' assigned (OAuth disabled mode)")

    # Check if welcome message already sent (prevent duplicates on reconnections)
    # Story D2: Fix duplicate welcome messages on WebSocket reconnection (every 150s)
    if cl.user_session.get("welcome_sent"):
        logger.debug(
            "Skipping welcome message - already sent for this session (reconnection)"
        )
        return

    # Enhanced onboarding welcome message with progressive introduction
    # Personalize welcome if user is authenticated (OAuth mode only)
    user_greeting = "Welcome to the CWE ChatBot! 🛡️"
    if requires_authentication():
        user = cl.user_session.get("user")
        if user and user.metadata:
            user_name = (
                user.metadata.get("name")
                or user.metadata.get("email", "").split("@")[0]
            )
            provider = user.metadata.get("provider", "OAuth").title()
            user_greeting = f"Welcome back, {user_name}! 🛡️\n\n*Authenticated via {provider}*\n\n🔐 *Your session is secure and your persona preferences will be saved.*"
    else:
        user_greeting = "Welcome to the CWE ChatBot! 🛡️\n\n*Running in open access mode (OAuth disabled)*"

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
        name="Persona Guide", content=persona_info, display="inline"
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

    # Mark welcome message as sent to prevent duplicates on reconnection
    # Story D2: Prevent duplicate welcome messages on WebSocket reconnection
    cl.user_session.set("welcome_sent", True)
    logger.debug("Welcome message sequence completed and flagged")

    # Optional: Debug action rendering if DEBUG_ACTIONS=1 (disabled due to environment ValidationError)
    # To test actions, use the CWE Analyzer flow or thumbs-down feedback instead.

    # Users can upload files via Chainlit's spontaneous file upload feature (config.toml)


@cl.on_message
async def main(message: cl.Message):
    """Handle incoming messages with Story 2.1 NLU and RAG pipeline."""

    # Debug logging: Log user message content if enabled
    if app_config.debug_log_messages:
        user_email = "anonymous"
        if requires_authentication():
            user = cl.user_session.get("user")
            if user and hasattr(user, "metadata") and user.metadata:
                user_email = user.metadata.get("email", "unknown")
        logger.info(
            f"[DEBUG_MSG] User: {user_email} | Message: {message.content[:200]}{'...' if len(message.content) > 200 else ''}"
        )

    # Authentication enforcement - require OAuth authentication if enabled
    if requires_authentication() and not is_user_authenticated():
        await cl.Message(
            content="🔒 Authentication required. Please authenticate using Google or GitHub to send messages.",
            author="System",
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
        await cl.Message(
            content="Startup error: configuration missing or database unavailable. Please check environment (GEMINI_API_KEY/DB)."
        ).send()
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
    if (
        isinstance(selected_profile, str)
        and selected_profile in UserPersona.get_all_personas()
    ):
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
        if hasattr(message, "elements") and message.elements and file_processor:
            async with cl.Step(
                name="Process file attachments", type="tool"
            ) as file_step:
                current_ctx = conversation_manager.get_session_context(session_id)
                current_persona = (
                    current_ctx.persona if current_ctx else UserPersona.DEVELOPER.value
                )
                file_step.input = (
                    f"Processing {len(message.elements)} file(s) for {current_persona}"
                )
                logger.info(
                    f"Processing {len(message.elements)} file attachments for {current_persona}"
                )

                # Create a keepalive message to prevent WebSocket timeout during PDF processing
                status_msg = await cl.Message(content="Processing files...").send()

                # Keepalive heartbeat to prevent idle disconnects
                heartbeat_running = True

                async def heartbeat():
                    """Send periodic updates to keep WebSocket alive during PDF processing."""
                    count = 0
                    while heartbeat_running:
                        await asyncio.sleep(3)  # Update every 3 seconds
                        if heartbeat_running:  # Check again after sleep
                            count += 1
                            await status_msg.stream_token(".")

                # Start keepalive task
                hb_task = asyncio.create_task(heartbeat())

                try:
                    file_content = await file_processor.process_attachments(message)
                finally:
                    # Stop keepalive
                    heartbeat_running = False
                    try:
                        hb_task.cancel()
                        await hb_task
                    except asyncio.CancelledError:
                        pass
                    # Remove the status message
                    await status_msg.remove()

                if file_content:
                    # SECURITY: do not merge evidence into the prompt; store for isolated use
                    cl.user_session.set("uploaded_file_context", file_content)
                    file_step.output = f"Extracted {len(file_content)} characters from file(s) (stored as isolated evidence)"
                    logger.info(
                        f"File content extracted: {len(file_content)} characters"
                    )
                else:
                    file_step.output = "No content extracted from file(s)"
                    logger.warning("File attachments found but no content extracted")

        # If user uploaded files but didn't provide a query, use a default prompt
        file_ctx = cl.user_session.get("uploaded_file_context")
        if file_ctx and (not user_query or user_query == "..."):
            user_query = (
                "Analyze this document for security vulnerabilities and CWE mappings."
            )
            logger.info("Using default query for file upload without user text")

        current_ctx = conversation_manager.get_session_context(session_id)
        current_persona = (
            current_ctx.persona if current_ctx else UserPersona.DEVELOPER.value
        )
        logger.info(
            f"Processing user query: '{user_query[:100]}...' for persona: {current_persona}"
        )

        # Check if this is a follow-up question (don't show analysis step for follow-ups)
        current_ctx = conversation_manager.get_session_context(session_id)
        is_followup = (
            current_ctx
            and current_ctx.persona == "CWE Analyzer"
            and getattr(current_ctx, "analyzer_mode", None) in ["question", "compare"]
        )

        if is_followup:
            # For follow-up questions, process without showing "Analyze security query" step
            result = await conversation_manager.process_user_message_streaming(
                session_id=session_id, message_content=user_query, message_id=message.id
            )
        else:
            # For new analysis, show the analysis step
            async with cl.Step(
                name="Analyze security query", type="tool"
            ) as analysis_step:
                analysis_step.input = (
                    f"Query: '{user_query[:100]}...' | Persona: {current_persona}"
                )

                # Process message using conversation manager with streaming (true streaming)
                result = await conversation_manager.process_user_message_streaming(
                    session_id=session_id,
                    message_content=user_query,
                    message_id=message.id,
                )

                # Update step output with retrieval statistics
                chunk_count = result.get("chunk_count", 0)
                retrieved_cwes = result.get("retrieved_cwes", [])
                analysis_step.output = f"Query validated and analyzed: Retrieved {chunk_count} chunks from {len(retrieved_cwes)} CWE(s)"

        # Debug logging: Log response content if enabled
        if app_config.debug_log_messages and result.get("message"):
            response_text = (
                result["message"].content
                if hasattr(result["message"], "content")
                else str(result["message"])
            )
            user_email = "anonymous"
            if requires_authentication():
                user = cl.user_session.get("user")
                if user and hasattr(user, "metadata") and user.metadata:
                    user_email = user.metadata.get("email", "unknown")
            logger.info(
                f"[DEBUG_RESP] User: {user_email} | Response length: {len(response_text)} chars | First 200: {response_text[:200]}{'...' if len(response_text) > 200 else ''}"
            )

        # Create source cards as Chainlit Elements if we have retrieved chunks
        elements = []
        if result.get("retrieved_cwes") and result.get("chunk_count", 0) > 0:
            async with cl.Step(
                name="Prepare source references", type="tool"
            ) as sources_step:
                # Get the retrieved chunks to create source elements
                retrieved_chunks = result.get("retrieved_chunks", [])
                retrieved_cwes = result.get("retrieved_cwes", [])
                elements = UIMessaging.create_source_elements(retrieved_chunks)

                # Format CWE list for output
                cwe_list = ", ".join(retrieved_cwes[:5])  # Show first 5 CWEs
                if len(retrieved_cwes) > 5:
                    cwe_list += f" and {len(retrieved_cwes) - 5} more"

                sources_step.output = (
                    f"Created {len(elements)} source references from CWEs: {cwe_list}"
                )

        # Add uploaded file evidence as a side element (if present)
        file_ctx = cl.user_session.get("uploaded_file_context")
        if file_ctx:
            evidence = UIMessaging.create_file_evidence_element(file_ctx)
            elements.append(evidence)

        # Add metadata for debugging if needed
        if not result.get("is_safe", True):
            logger.warning(
                f"Security flags detected: {result.get('security_flags', [])}"
            )

        # Apply progressive disclosure based on UI settings and update message with elements
        if result.get("message"):
            # Apply progressive disclosure if configured
            elements = UIMessaging.apply_progressive_disclosure(
                result["message"], ui_settings, elements
            )
            # Update message with all elements
            await UIMessaging.update_message_with_elements(result["message"], elements)

        # Clear file context after use to avoid unbounded growth (ConversationManager clears its own context copy)
        if file_ctx:
            cl.user_session.set("uploaded_file_context", None)

        # Add Action buttons for CWE Analyzer persona (after response is complete)
        current_ctx = conversation_manager.get_session_context(session_id)
        if current_ctx:
            logger.info(
                f"Debug: persona={current_ctx.persona}, analyzer_mode={getattr(current_ctx, 'analyzer_mode', 'MISSING')}"
            )

            analyzer_mode = getattr(current_ctx, "analyzer_mode", None)
            if current_ctx.persona == "CWE Analyzer":
                if not analyzer_mode:
                    # Initial analysis complete - show "Ask Question" button
                    logger.info("Creating Action buttons for CWE Analyzer (initial)")
                    try:
                        # Story S-12: Include CSRF token in action payload
                        csrf_token = CSRFManager.get_session_token()
                        actions = [
                            cl.Action(
                                name="ask_question",
                                label="❓ Ask a Question",
                                payload={"action": "ask", "csrf_token": csrf_token},
                            )
                        ]
                        logger.info(
                            f"Actions created successfully: {[a.name for a in actions]}"
                        )

                        message = cl.Message(
                            content="**Next steps for this analysis:**",
                            actions=actions,
                            author="System",
                        )
                        logger.info("Message with actions created successfully")

                        await message.send()
                        logger.info("Action buttons sent successfully")
                    except Exception as action_error:
                        logger.error(f"Action button error type: {type(action_error)}")
                        logger.error(
                            f"Action button error message: {str(action_error)}"
                        )
                        logger.error(
                            f"Action button error details: {repr(action_error)}"
                        )
                        if hasattr(action_error, "errors"):
                            logger.error(f"Validation errors: {action_error.errors()}")  # type: ignore[attr-defined]
                        logger.log_exception(
                            "Failed to create/send Action buttons", action_error
                        )
                        # Send message without actions as fallback
                        await cl.Message(
                            content="**Next steps:** Type '/ask' to ask a question about the analysis, or '/compare' to compare CWE IDs.",
                            author="System",
                        ).send()
                elif analyzer_mode == "question":
                    # Question mode active - show "Exit Question Mode" button
                    logger.info("Creating Exit button for CWE Analyzer (question mode)")
                    try:
                        # Story S-12: Include CSRF token in action payload
                        csrf_token = CSRFManager.get_session_token()
                        actions = [
                            cl.Action(
                                name="exit_question_mode",
                                label="🚪 Exit Question Mode",
                                payload={"action": "exit", "csrf_token": csrf_token},
                            )
                        ]
                        logger.info(
                            f"Exit action created successfully: {[a.name for a in actions]}"
                        )
                        message = cl.Message(
                            content="**Question mode active.**",
                            actions=actions,
                            author="System",
                        )
                        await message.send()
                        logger.info("Exit button sent successfully")
                    except Exception as action_error:
                        logger.log_exception(
                            "Failed to create Exit button", action_error
                        )
                        # Fallback to text hint
                        await cl.Message(
                            content="**Question mode active.** Type '/exit' to leave question mode.",
                            author="System",
                        ).send()
                else:
                    logger.info(f"No action buttons for analyzer_mode: {analyzer_mode}")
            else:
                logger.info(
                    f"Not showing Action buttons - persona: {current_ctx.persona}, analyzer_mode: {analyzer_mode}"
                )
        else:
            logger.warning("No current context found - cannot show Action buttons")

        # Log successful interaction
        current_persona = current_ctx.persona if current_ctx else "unknown"
        logger.info(
            f"Successfully processed query for {current_persona}, retrieved {result.get('chunk_count', 0)} chunks"
        )

    except Exception as e:
        # Secure error handling - never expose internal details
        logger.log_exception(
            "Error processing message", e, extra_context={"handler": "on_message"}
        )
        error_response = "I apologize, but I'm experiencing technical difficulties. Please try your question again in a moment."
        await cl.Message(content=error_response).send()


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
)

if __name__ == "__main__":
    # This allows running the app directly with: python main.py
    main_cli()

    # Note: Use 'poetry run chainlit run apps/chatbot/main.py' to start the application
    logger.info(
        "To start the application, run: poetry run chainlit run apps/chatbot/main.py"
    )
