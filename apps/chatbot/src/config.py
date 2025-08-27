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
    
    # Embedding Model Configuration (following ADR)
    embedding_model: str = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")
    embedding_dimensions: int = int(os.getenv("EMBEDDING_DIMENSIONS", "1536"))
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    
    # Retrieval Configuration
    hybrid_dense_weight: float = float(os.getenv("HYBRID_DENSE_WEIGHT", "0.6"))
    hybrid_sparse_weight: float = float(os.getenv("HYBRID_SPARSE_WEIGHT", "0.4"))
    max_retrieval_results: int = int(os.getenv("MAX_RETRIEVAL_RESULTS", "5"))
    similarity_threshold: float = float(os.getenv("SIMILARITY_THRESHOLD", "0.1"))
    
    # Security Configuration
    max_input_length: int = int(os.getenv("MAX_INPUT_LENGTH", "1000"))
    enable_strict_sanitization: bool = os.getenv("ENABLE_STRICT_SANITIZATION", "true").lower() == "true"
    
    # Application Configuration
    enable_debug_logging: bool = os.getenv("DEBUG", "false").lower() == "true"
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    
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
        """Get hybrid retrieval weights."""
        return {
            "dense": self.hybrid_dense_weight,
            "sparse": self.hybrid_sparse_weight
        }
    
    def validate_config(self) -> None:
        """Validate configuration and raise errors for missing required values."""
        errors = []
        
        # Check required database configuration
        if not self.pg_password:
            errors.append("POSTGRES_PASSWORD environment variable is required")
        
        # Check OpenAI API key
        if not self.openai_api_key:
            errors.append("OPENAI_API_KEY environment variable is required")
        
        # Validate weights sum to 1.0
        total_weight = self.hybrid_dense_weight + self.hybrid_sparse_weight
        if not abs(total_weight - 1.0) < 0.001:
            errors.append(f"Hybrid weights must sum to 1.0, got {total_weight}")
        
        if errors:
            raise ValueError(f"Configuration errors: {'; '.join(errors)}")


# Global configuration instance
config = Config()