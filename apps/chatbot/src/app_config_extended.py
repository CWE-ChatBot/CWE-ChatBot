"""
Configuration management for CWE ChatBot application.
Handles environment variables and application settings.
"""

import os
from dataclasses import dataclass
from typing import Optional, Dict, Any
from .config.env_loader import load_env_auto

# Auto-load environment on import
load_env_auto()


@dataclass
class Config:
    """Application configuration with environment variable defaults."""
    
    # PostgreSQL Database Configuration
    pg_host: str = os.getenv("POSTGRES_HOST", "localhost")
    pg_port: int = int(os.getenv("POSTGRES_PORT", "5432"))
    pg_database: str = os.getenv("POSTGRES_DATABASE", "cwe_chatbot")
    pg_user: str = os.getenv("POSTGRES_USER", "postgres")
    pg_password: str = os.getenv("POSTGRES_PASSWORD", "")
    
    # Embedding/LLM Configuration (Gemini standard)
    embedding_model: str = os.getenv("EMBEDDING_MODEL", "models/embedding-001")
    embedding_dimensions: int = int(os.getenv("EMBEDDING_DIMENSIONS", "3072"))
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    
    # Retrieval Configuration (RRF hybrid weights)
    w_vec: float = float(os.getenv("RRF_W_VEC", "0.65"))    # Vector similarity
    w_fts: float = float(os.getenv("RRF_W_FTS", "0.25"))    # Full-text search
    w_alias: float = float(os.getenv("RRF_W_ALIAS", "0.10")) # Alias matching
    max_retrieval_results: int = int(os.getenv("MAX_RETRIEVAL_RESULTS", "5"))
    similarity_threshold: float = float(os.getenv("SIMILARITY_THRESHOLD", "0.1"))
    # RRF (ingestion-aligned) parameters
    rrf_k_vec: int = int(os.getenv("RRF_K_VEC", "200"))
    rrf_fts_k: int = int(os.getenv("RRF_FTS_K", "200"))
    rrf_alias_k: int = int(os.getenv("RRF_ALIAS_K", "200"))
    rrf_k_rrf: int = int(os.getenv("RRF_K_RRF", "60"))
    
    # Security Configuration
    max_input_length: int = int(os.getenv("MAX_INPUT_LENGTH", "1000"))
    enable_strict_sanitization: bool = os.getenv("ENABLE_STRICT_SANITIZATION", "true").lower() == "true"

    # Content Processing Limits
    max_file_evidence_length: int = int(os.getenv("MAX_FILE_EVIDENCE_LENGTH", "16000"))
    max_attachment_summary_length: int = int(os.getenv("MAX_ATTACHMENT_SUMMARY_LENGTH", "1200"))
    max_output_tokens: int = int(os.getenv("MAX_OUTPUT_TOKENS", "2048"))
    max_document_snippet_length: int = int(os.getenv("MAX_DOCUMENT_SNIPPET_LENGTH", "1000"))
    max_context_length: int = int(os.getenv("MAX_CONTEXT_LENGTH", "16000"))
    
    # Application Configuration
    enable_debug_logging: bool = os.getenv("DEBUG", "false").lower() == "true"
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    section_boost_value: float = float(os.getenv("SECTION_BOOST_VALUE", "0.15"))
    
    def get_pg_config(self) -> Dict[str, Any]:
        """Get PostgreSQL connection configuration."""
        return {
            "host": self.pg_host,
            "port": self.pg_port,
            "database": self.pg_database,
            "user": self.pg_user,
            "password": self.pg_password
        }
    
    def get_hybrid_weights(self) -> Dict[str, float]:
        """Get RRF hybrid retrieval weights."""
        return {
            "w_vec": self.w_vec,
            "w_fts": self.w_fts,
            "w_alias": self.w_alias
        }
    
    def validate_config(self, *, offline_ai: bool = False) -> None:
        """Validate configuration and raise errors for missing required values."""
        errors = []
        
        # Check required database configuration
        if not self.pg_password:
            errors.append("POSTGRES_PASSWORD environment variable is required")
        
        # Check Gemini API key
        if not self.gemini_api_key and not offline_ai:
            errors.append("GEMINI_API_KEY environment variable is required")
        
        # Validate RRF weights sum to 1.0
        total_weight = self.w_vec + self.w_fts + self.w_alias
        if not abs(total_weight - 1.0) < 1e-6:
            errors.append(f"RRF weights (w_vec + w_fts + w_alias) must sum to 1.0, got {total_weight}")
        
        if errors:
            raise ValueError(f"Configuration errors: {'; '.join(errors)}")


# Global configuration instance
config = Config()
