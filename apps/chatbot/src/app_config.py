"""
Authoritative configuration module for the CWE ChatBot application.

This is the SINGLE SOURCE OF TRUTH for all application configuration.
All configuration values are defined here with their defaults.

Configuration sources (in priority order):
1. Environment variables (from .env file or system environment)
2. Secrets from GCP Secret Manager (production) via secrets.py
3. Default values defined in this file

For local development:
- Copy apps/chatbot/.env.example to .env
- Set only the required values (DB connection, GEMINI_API_KEY)
- All other values have sensible defaults

For production deployment:
- Secrets retrieved automatically from GCP Secret Manager
- Non-sensitive config set via gcloud run deploy --set-env-vars
- See SECRETS.md for Secret Manager architecture
"""
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .config.env_loader import load_environments
from .secrets import (
    get_chainlit_auth_secret,
    get_database_password,
    get_gemini_api_key,
    get_oauth_github_client_id,
    get_oauth_github_client_secret,
    get_oauth_google_client_id,
    get_oauth_google_client_secret,
)

# Load context-specific environment variables from .env files if available.
# This function must be called BEFORE the Config class is defined.
load_environments()

# Get project ID for Secret Manager (from environment or Cloud Run metadata)
_PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")


@dataclass
class Config:
    """Application configuration with environment variable defaults."""

    # PostgreSQL Database Configuration
    # Support both POSTGRES_* and DB_* environment variable naming conventions
    pg_host: str = os.getenv("POSTGRES_HOST") or os.getenv("DB_HOST") or "localhost"
    pg_port: int = int(
        os.getenv("POSTGRES_PORT") or os.getenv("DB_PORT") or "5432"
    )
    pg_database: str = (
        os.getenv("POSTGRES_DATABASE") or os.getenv("DB_NAME") or "cwe_chatbot"
    )
    pg_user: str = os.getenv("POSTGRES_USER") or os.getenv("DB_USER") or "postgres"
    # Password retrieved from Secret Manager (falls back to env var)
    pg_password: str = get_database_password(_PROJECT_ID)

    # Chainlit Data Layer Database Configuration
    # Uses separate 'chainlit' database on same Cloud SQL instance
    chainlit_database: str = os.getenv("CHAINLIT_DATABASE", "chainlit")
    chainlit_user: str = os.getenv("CHAINLIT_USER", "app_user")

    @property
    def database_url(self) -> str:
        """
        Construct DATABASE_URL for Chainlit data layer.

        For Cloud Run (Cloud SQL Unix socket):
            postgresql://USER:PASSWORD@/DATABASE?host=/cloudsql/CONNECTION_NAME
        For local development (TCP):
            postgresql://USER:PASSWORD@HOST:PORT/DATABASE
        """
        # Cloud Run uses Cloud SQL Unix socket (check for Cloud SQL connection name in env)
        cloud_sql_connection = os.getenv("CLOUD_SQL_CONNECTION_NAME")
        if cloud_sql_connection:
            # Production: Cloud SQL Unix socket connection
            return f"postgresql://{self.chainlit_user}:{self.pg_password}@/{self.chainlit_database}?host=/cloudsql/{cloud_sql_connection}"
        else:
            # Local development: TCP connection
            return f"postgresql://{self.chainlit_user}:{self.pg_password}@{self.pg_host}:{self.pg_port}/{self.chainlit_database}"

    # Embedding/LLM Configuration (Gemini standard)
    embedding_model: str = os.getenv("EMBEDDING_MODEL", "models/embedding-001")
    embedding_dimensions: int = int(os.getenv("EMBEDDING_DIMENSIONS", "3072"))
    # API key retrieved from Secret Manager (falls back to env var)
    gemini_api_key: str = get_gemini_api_key(_PROJECT_ID)

    # Retrieval Configuration (RRF hybrid weights)
    w_vec: float = float(os.getenv("RRF_W_VEC", "0.65"))  # Vector similarity
    w_fts: float = float(os.getenv("RRF_W_FTS", "0.25"))  # Full-text search
    w_alias: float = float(os.getenv("RRF_W_ALIAS", "0.10"))  # Alias matching
    max_retrieval_results: int = int(os.getenv("MAX_RETRIEVAL_RESULTS", "5"))
    similarity_threshold: float = float(os.getenv("SIMILARITY_THRESHOLD", "0.1"))
    # RRF (ingestion-aligned) parameters
    rrf_k_vec: int = int(os.getenv("RRF_K_VEC", "200"))
    rrf_fts_k: int = int(os.getenv("RRF_FTS_K", "200"))
    rrf_alias_k: int = int(os.getenv("RRF_ALIAS_K", "200"))
    rrf_k_rrf: int = int(os.getenv("RRF_K_RRF", "60"))

    # Security Configuration
    max_input_length: int = int(os.getenv("MAX_INPUT_LENGTH", "1000"))
    enable_strict_sanitization: bool = (
        os.getenv("ENABLE_STRICT_SANITIZATION", "true").lower() == "true"
    )

    # Content Processing Limits
    max_file_evidence_length: int = int(os.getenv("MAX_FILE_EVIDENCE_LENGTH", "16000"))
    max_attachment_summary_length: int = int(
        os.getenv("MAX_ATTACHMENT_SUMMARY_LENGTH", "1200")
    )
    # Increased from 4096 to 16384 to prevent truncation of long responses
    # 16384 tokens ≈ 12,000 words (addresses truncation at 9182 words)
    max_output_tokens: int = int(os.getenv("MAX_OUTPUT_TOKENS", "16384"))
    max_document_snippet_length: int = int(
        os.getenv("MAX_DOCUMENT_SNIPPET_LENGTH", "1000")
    )
    max_context_length: int = int(os.getenv("MAX_CONTEXT_LENGTH", "16000"))
    max_context_chunks: int = int(os.getenv("MAX_CONTEXT_CHUNKS", "100"))

    # LLM Configuration (Flexible defaults)
    llm_provider: str = os.getenv("LLM_PROVIDER", "google")
    llm_model_name: str = os.getenv("LLM_MODEL_NAME", "gemini-2.5-flash-lite")
    llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.1"))
    llm_top_p: float = float(os.getenv("LLM_TOP_P", "0.9"))
    llm_top_k: int = int(os.getenv("LLM_TOP_K", "40"))
    llm_safety_permissive: bool = (
        os.getenv("LLM_SAFETY_PERMISSIVE", "true").lower() == "true"
    )

    # Application Configuration
    enable_debug_logging: bool = os.getenv("DEBUG", "false").lower() == "true"
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    section_boost_value: float = float(os.getenv("SECTION_BOOST_VALUE", "0.15"))
    # Debug: Log user messages and responses (enable for testing/debugging, disable in production)
    debug_log_messages: bool = (
        os.getenv("DEBUG_LOG_MESSAGES", "false").lower() == "true"
    )

    # Authentication / OAuth / Chainlit
    enable_oauth: bool = os.getenv("ENABLE_OAUTH", "true").lower() == "true"
    # AUTH_MODE: "oauth" (production), "hybrid" (testing - allows test-login endpoint)
    auth_mode: str = os.getenv("AUTH_MODE", "oauth")
    chainlit_url: str = os.getenv("CHAINLIT_URL", "http://localhost:8081")
    # Secrets retrieved from Secret Manager (fall back to env vars)
    chainlit_auth_secret: Optional[str] = get_chainlit_auth_secret(_PROJECT_ID)
    # OAuth Providers - secrets from Secret Manager
    oauth_google_client_id: Optional[str] = get_oauth_google_client_id(_PROJECT_ID)
    oauth_google_client_secret: Optional[str] = get_oauth_google_client_secret(
        _PROJECT_ID
    )
    oauth_github_client_id: Optional[str] = get_oauth_github_client_id(_PROJECT_ID)
    oauth_github_client_secret: Optional[str] = get_oauth_github_client_secret(
        _PROJECT_ID
    )
    # Whitelist (comma-separated emails or @domain suffixes)
    # Prefer environment variable; fallback to a built-in allowlist for production use
    allowed_users_raw: Optional[str] = os.getenv("ALLOWED_USERS") or (
        "crashedmind@gmail.com,@mitre.org"
    )

    def get_pg_config(self) -> Dict[str, Any]:
        """Get PostgreSQL connection configuration."""
        return {
            "host": self.pg_host,
            "port": self.pg_port,
            "database": self.pg_database,
            "user": self.pg_user,
            "password": self.pg_password,
        }

    def get_hybrid_weights(self) -> Dict[str, float]:
        """Get RRF hybrid retrieval weights."""
        return {"w_vec": self.w_vec, "w_fts": self.w_fts, "w_alias": self.w_alias}

    def get_llm_generation_config(self) -> Dict[str, Any]:
        """Get LLM generation configuration with configurable defaults."""
        return {
            "temperature": self.llm_temperature,
            "max_output_tokens": self.max_output_tokens,
            "top_p": self.llm_top_p,
            "top_k": self.llm_top_k,
        }

    def get_llm_safety_settings(self) -> Optional[List[Dict[str, Any]]]:
        """Get LLM safety settings based on configuration."""
        if not self.llm_safety_permissive:
            # Use default safety settings (more restrictive)
            return None

        # Return permissive settings for cybersecurity content
        try:
            from google.generativeai.types import (
                HarmBlockThreshold,
                HarmCategory,
            )

            return [
                {
                    "category": HarmCategory.HARM_CATEGORY_HARASSMENT,
                    "threshold": HarmBlockThreshold.BLOCK_NONE,
                },
                {
                    "category": HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                    "threshold": HarmBlockThreshold.BLOCK_NONE,
                },
                {
                    "category": HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                    "threshold": HarmBlockThreshold.BLOCK_NONE,
                },
                {
                    "category": HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                    "threshold": HarmBlockThreshold.BLOCK_NONE,
                },
            ]
        except ImportError:
            # Fallback using string names
            return [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {
                    "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "threshold": "BLOCK_NONE",
                },
                {
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "threshold": "BLOCK_NONE",
                },
            ]

    def get_llm_provider_config(self) -> Dict[str, Any]:
        """Get complete LLM provider configuration."""
        return {
            "provider": self.llm_provider,
            "model_name": self.llm_model_name,
            "generation_config": self.get_llm_generation_config(),
            "safety_settings": self.get_llm_safety_settings(),
        }

    # ------- OAuth helpers (centralize logic used by the app) -------
    @property
    def google_oauth_configured(self) -> bool:
        return bool(self.oauth_google_client_id and self.oauth_google_client_secret)

    @property
    def github_oauth_configured(self) -> bool:
        return bool(self.oauth_github_client_id and self.oauth_github_client_secret)

    @property
    def oauth_providers_configured(self) -> bool:
        return self.google_oauth_configured or self.github_oauth_configured

    @property
    def oauth_ready(self) -> bool:
        """True if OAuth is enabled, at least one provider is configured, and Chainlit can sign tokens."""
        return (
            self.enable_oauth
            and self.oauth_providers_configured
            and bool(self.chainlit_auth_secret)
        )

    def get_allowed_users(self) -> list[str]:
        if not self.allowed_users_raw:
            return []
        return [
            u.strip().lower() for u in self.allowed_users_raw.split(",") if u.strip()
        ]

    def is_user_allowed(self, email: str) -> bool:
        """Email allowlist check supporting full address or @domain suffix."""
        allow = self.get_allowed_users()
        if not allow:
            return True  # no list => allow all authenticated users
        email_l = (email or "").lower()
        for rule in allow:
            if rule.startswith("@"):
                if email_l.endswith(rule):
                    return True
            elif email_l == rule:
                return True
        return False

    def validate_oauth(self) -> None:
        """Optional stricter checks to call at startup when you want to enforce OAuth correctness."""
        if not self.enable_oauth:
            return
        if not self.oauth_providers_configured:
            # Not fatal if you want "open mode when no providers", but usually this is a misconfig.
            raise ValueError(
                "ENABLE_OAUTH=true but no OAuth provider is configured (set Google or GitHub client id/secret)."
            )
        if not self.chainlit_auth_secret:
            raise ValueError(
                "CHAINLIT_AUTH_SECRET must be set when OAuth is enabled (Chainlit needs it to sign tokens)."
            )

    def validate_config(self, *, offline_ai: bool = False) -> None:
        """Validate configuration and raise errors for missing required values."""
        errors = []

        # Check database configuration - skip password check if using IAM authentication
        using_iam_auth = bool(os.getenv("DB_IAM_USER")) or bool(
            os.getenv("INSTANCE_CONN_NAME")
        )
        if not self.pg_password and not using_iam_auth:
            errors.append(
                "POSTGRES_PASSWORD environment variable is required (or use IAM authentication)"
            )

        # Check Gemini API key
        if not self.gemini_api_key and not offline_ai:
            errors.append("GEMINI_API_KEY environment variable is required")

        # Validate RRF weights sum to 1.0
        total_weight = self.w_vec + self.w_fts + self.w_alias
        if not abs(total_weight - 1.0) < 1e-6:
            errors.append(
                f"RRF weights (w_vec + w_fts + w_alias) must sum to 1.0, got {total_weight}"
            )

        if errors:
            raise ValueError(f"Configuration errors: {'; '.join(errors)}")


# Global configuration instance
config = Config()
