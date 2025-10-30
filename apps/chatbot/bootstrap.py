"""
Component bootstrapping for Chainlit application.

Extracts initialization logic from main.py to reduce cyclomatic complexity.
"""

import os
from dataclasses import dataclass
from typing import Any, Callable, Optional

from src.app_config import config as app_config
from src.security.secure_logging import get_secure_logger

logger = get_secure_logger(__name__)


@dataclass
class Components:
    """Container for initialized application components."""

    conversation_manager: Any
    input_sanitizer: Any
    security_validator: Any
    file_processor: Any
    db_engine: Any
    ok: bool


class Bootstrapper:
    """
    Handles component initialization with dependency injection.

    Reduces complexity by extracting database setup, AI config,
    and component wiring into focused helper methods.
    """

    def __init__(
        self, *, db_factory: Optional[Callable[[], Any]], cm_factory: Callable[..., Any]
    ):
        self._db_factory = db_factory
        self._cm_factory = cm_factory

    def initialize(self) -> Components:
        """
        Initialize all components with error handling.

        Returns Components dataclass with ok=True on success, ok=False on failure.
        """
        ok = False
        db_engine = None

        # Validate configuration
        try:
            logger.debug("Validating configuration")
            app_config.validate_config()
            logger.debug("Configuration validation passed")
        except Exception as cfg_err:
            logger.error(f"Configuration validation FAILED: {cfg_err}")
            logger.log_exception(
                "Configuration validation failed",
                cfg_err,
                extra_context={"component": "startup"},
            )
            # Continue to provide helpful UI message

        # Validate OAuth if enabled
        try:
            app_config.validate_oauth()
        except Exception as oauth_err:
            logger.log_exception(
                "OAuth configuration error",
                oauth_err,
                extra_context={"component": "startup"},
            )
            # Warning only - will run in open mode

        # Initialize database
        db_engine, database_url = self._init_db()
        if not database_url:
            return Components(None, None, None, None, None, False)

        # Check AI configuration
        gemini_api_key, offline_ai = self._read_ai_env()
        if not gemini_api_key and not offline_ai:
            logger.error("GEMINI_API_KEY is missing!")
            return Components(None, None, None, None, None, False)

        logger.info(f"Initializing with database: {database_url[:50]}...")

        # Initialize security components
        from src.file_processor import FileProcessor
        from src.input_security import InputSanitizer, SecurityValidator

        input_sanitizer = InputSanitizer()
        security_validator = SecurityValidator()
        file_processor = FileProcessor()

        # Initialize conversation manager
        cm = self._cm_factory(
            database_url=database_url, gemini_api_key=gemini_api_key, engine=db_engine
        )

        # Test database connection
        health = cm.get_system_health()
        if not health.get("database", False):
            logger.error("Database health check FAILED!")
            return Components(None, None, None, None, None, False)

        logger.info("Database health check passed")
        logger.info("Story 2.1 components initialized successfully")
        logger.info(f"Database health: {health}")

        # Set conversation manager for REST API if available
        self._set_api_conversation_manager(cm)

        # Log OAuth status
        self._log_oauth_status()

        ok = True
        return Components(
            cm, input_sanitizer, security_validator, file_processor, db_engine, ok
        )

    def _init_db(self) -> tuple[Optional[Any], str]:
        """
        Initialize database connection based on environment config.

        Returns (engine, database_url) tuple. Returns (None, "") on failure.
        """
        # Check configuration options
        use_private_ip = (
            os.getenv("DB_HOST") and os.getenv("DB_USER") and os.getenv("DB_PASSWORD")
        )
        cloud_sql_instance = os.getenv("INSTANCE_CONN_NAME")
        database_url = os.getenv("DATABASE_URL") or os.getenv("LOCAL_DATABASE_URL")

        logger.debug(
            f"Environment: DB_HOST={os.getenv('DB_HOST')}, DB_USER={os.getenv('DB_USER')}, "
            f"INSTANCE_CONN_NAME={cloud_sql_instance}, DATABASE_URL={'present' if database_url else 'missing'}"
        )

        # Option 1: Private IP with password auth
        if use_private_ip:
            return self._init_private_ip_db()

        # Option 2: Cloud SQL Connector with IAM
        if cloud_sql_instance:
            return self._init_cloud_sql_connector()

        # Option 3: Traditional database URL
        return self._init_traditional_db(database_url)

    def _init_private_ip_db(self) -> tuple[Optional[Any], str]:
        """Initialize Private IP database connection."""
        logger.info(f"Using Private IP connection to {os.getenv('DB_HOST')}")
        try:
            logger.debug("Importing src.db module")
            from src.db import engine

            logger.debug("Calling engine() to create SQLAlchemy engine")
            db_engine = engine()
            logger.info("Private IP database engine initialized successfully")
            return db_engine, "private-ip-connection"
        except Exception as e:
            logger.error(
                f"Private IP connection initialization FAILED: {type(e).__name__}: {e}"
            )
            if os.getenv("LOG_LEVEL") == "DEBUG":
                import traceback

                traceback.print_exc()
            logger.log_exception("Failed to initialize Private IP connection", e)
            return None, ""

    def _init_cloud_sql_connector(self) -> tuple[Optional[Any], str]:
        """Initialize Cloud SQL Connector."""
        cloud_sql_instance = os.getenv("INSTANCE_CONN_NAME")
        logger.info(f"Using Cloud SQL Connector for instance: {cloud_sql_instance}")
        try:
            logger.debug("Importing src.db module")
            from src.db import engine

            logger.debug("Calling engine() to create SQLAlchemy engine")
            db_engine = engine()
            logger.info("Cloud SQL Connector engine initialized successfully")
            return db_engine, "cloud-sql-connector"
        except Exception as e:
            logger.error(
                f"Cloud SQL Connector initialization FAILED: {type(e).__name__}: {e}"
            )
            if os.getenv("LOG_LEVEL") == "DEBUG":
                import traceback

                traceback.print_exc()
            logger.log_exception("Failed to initialize Cloud SQL Connector", e)
            return None, ""

    def _init_traditional_db(self, database_url: Optional[str]) -> tuple[None, str]:
        """Initialize traditional database URL connection."""
        logger.debug(
            "No Private IP or Cloud SQL instance, using traditional database URL"
        )

        if not database_url:
            # Derive URL from POSTGRES_* if available
            if app_config.pg_user and app_config.pg_password:
                database_url = (
                    f"postgresql+psycopg://{app_config.pg_user}:{app_config.pg_password}"
                    f"@{app_config.pg_host}:{app_config.pg_port}/{app_config.pg_database}"
                )

        if not database_url:
            logger.error("No database configuration found!")
            return None, ""

        return None, database_url

    def _read_ai_env(self) -> tuple[Optional[str], bool]:
        """
        Read AI configuration from environment.

        Returns (gemini_api_key, offline_mode) tuple.
        """
        key = os.getenv("GEMINI_API_KEY") or app_config.gemini_api_key
        offline = os.getenv("DISABLE_AI") == "1" or os.getenv("GEMINI_OFFLINE") == "1"
        return key, offline

    def _set_api_conversation_manager(self, cm: Any) -> None:
        """Set conversation manager for REST API if available."""
        try:
            from api import set_conversation_manager

            set_conversation_manager(cm)
            logger.info("Conversation manager set for REST API")
        except Exception as api_err:
            logger.warning(f"Could not set conversation manager for API: {api_err}")

    def _log_oauth_status(self) -> None:
        """Log OAuth configuration status."""
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
