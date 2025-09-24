#!/usr/bin/env python3
"""
CWE Query Handler - Story 2.1 Integration with Story 1.5 Production Infrastructure
Integrates with existing production hybrid retrieval system from Story 1.5.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from src.security.secure_logging import get_secure_logger

# Prefer a clean package import; fall back to legacy path if package is unavailable
try:  # minimal path when cwe_ingestion is installed
    from cwe_ingestion.pg_chunk_store import PostgresChunkStore  # type: ignore
    from cwe_ingestion.embedder import GeminiEmbedder  # type: ignore
except Exception:  # fallback to legacy repo layout/env var
    import os, sys
    ingestion_path = os.getenv("CWE_INGESTION_PATH")
    if ingestion_path and os.path.isdir(ingestion_path):
        sys.path.insert(0, ingestion_path)
        from pg_chunk_store import PostgresChunkStore  # type: ignore
        from embedder import GeminiEmbedder  # type: ignore
    else:  # pragma: no cover
        raise

logger = get_secure_logger(__name__)


class CWEQueryHandler:
    """
    Handles CWE queries using existing production hybrid retrieval system from Story 1.5.

    Integrates with:
    - PostgresChunkStore: Production hybrid retrieval (Vector + FTS + Alias matching)
    - GeminiEmbedder: Production Gemini embeddings (3072D)
    """

    def __init__(self, database_url: str, gemini_api_key: str, hybrid_weights: Optional[Dict[str, float]] = None) -> None:
        """
        Initialize handler with Story 1.5 production components.

        Args:
            database_url: PostgreSQL connection string for production database
            gemini_api_key: Gemini API key for embeddings
            hybrid_weights: RRF weights dict with w_vec, w_fts, w_alias keys (defaults to validated config values)
        """
        try:
            # Use existing production components from Story 1.5
            self.store = PostgresChunkStore(dims=3072, database_url=database_url)
            self.embedder = GeminiEmbedder(api_key=gemini_api_key)

            # Store hybrid weights (use provided weights or fall back to config defaults)
            if hybrid_weights is None:
                # Import config here to avoid circular imports
                from .app_config import config
                self.hybrid_weights = config.get_hybrid_weights()
            else:
                self.hybrid_weights = hybrid_weights

            logger.info("CWEQueryHandler initialized with Story 1.5 production infrastructure")
            logger.info(f"RRF weights: {self.hybrid_weights}")

            # Verify database connection
            stats = self.store.get_collection_stats()
            logger.info(f"Connected to production database: {stats['count']} chunks available")

            if stats['count'] == 0:
                logger.warning("Production database appears empty. Verify Story 1.5 ingestion completed.")

        except Exception as e:
            logger.log_exception("Failed to initialize CWEQueryHandler", e)
            raise

    async def process_query(self, query: str, user_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process query using existing hybrid retrieval with user context.

        Args:
            query: User query string
            user_context: User persona and context information

        Returns:
            List of retrieved chunks with metadata and scores
        """
        try:
            logger.info(f"Processing query: '{query[:50]}...' for persona: {user_context.get('persona', 'unknown')}")

            # Generate embedding using existing Gemini embedder from Story 1.5 (non-blocking)
            query_embedding = await asyncio.to_thread(self.embedder.embed_text, query)
            logger.debug(f"Generated {len(query_embedding)}D embedding")

            # Use centralized hybrid weights from Config (Story 1.5 validated weights)
            weights = self.hybrid_weights

            # Apply persona-specific section boost if configured
            section_boost = user_context.get("section_boost")
            query_params = {
                "query_text": query,
                "query_embedding": query_embedding,
                "limit_chunks": 10,
                **weights
            }

            if section_boost:
                # Pull boost value from centralized config
                try:
                    from .app_config import config
                    boost_value = getattr(config, "section_boost_value", 0.15)
                except Exception:
                    boost_value = 0.15
                query_params["section_intent_boost"] = section_boost
                query_params["section_boost_value"] = boost_value
                logger.debug(f"Applied section boost: {section_boost}")

            # Execute hybrid search using Story 1.5 production system
            results = await asyncio.to_thread(self.store.query_hybrid, **query_params)

            logger.info(f"Retrieved {len(results)} chunks")

            # Log top results for debugging
            if results:
                top_cwes = [r["metadata"]["cwe_id"] for r in results[:3]]
                logger.debug(f"Top CWEs: {top_cwes}")

            return results

        except Exception as e:
            logger.log_exception("Query processing failed", e)
            # Return empty results on error to ensure graceful degradation
            return []

    def get_database_stats(self) -> Dict[str, Any]:
        """Get production database statistics."""
        try:
            stats: Dict[str, Any] = self.store.get_collection_stats()
            return stats
        except Exception as e:
            logger.log_exception("Failed to get database stats", e)
            return {"count": 0, "error": str(e)}

    def health_check(self) -> Dict[str, bool]:
        """Perform health check on all components."""
        health = {}

        try:
            # Check database connection
            stats = self.store.get_collection_stats()
            health["database"] = stats["count"] > 0
        except Exception:
            health["database"] = False

        try:
            # Check embedder
            test_embedding = self.embedder.embed_text("test")
            health["embedder"] = len(test_embedding) == 3072
        except Exception:
            health["embedder"] = False

        return health

    def close(self) -> None:
        """Close underlying resources."""
        try:
            if getattr(self, "store", None) is not None:
                conn = getattr(self.store, "conn", None)
                if conn:
                    conn.close()
        except Exception as e:
            logger.log_exception("Error closing QueryHandler resources", e)
