#!/usr/bin/env python3
"""
CWE Query Handler - Story 2.1 Integration with Story 1.5 Production Infrastructure
Integrates with existing production hybrid retrieval system from Story 1.5.
"""

import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

# Add cwe_ingestion to path for imports from Story 1.5
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "cwe_ingestion"))

try:
    from pg_chunk_store import PostgresChunkStore
    from embedder import GeminiEmbedder
except ImportError as e:
    logging.error(f"Failed to import Story 1.5 components: {e}")
    raise ImportError(
        "Story 1.5 components required. Ensure pg_chunk_store.py and embedder.py are available in cwe_ingestion."
    ) from e

logger = logging.getLogger(__name__)


class CWEQueryHandler:
    """
    Handles CWE queries using existing production hybrid retrieval system from Story 1.5.

    Integrates with:
    - PostgresChunkStore: Production hybrid retrieval (Vector + FTS + Alias matching)
    - GeminiEmbedder: Production Gemini embeddings (3072D)
    """

    def __init__(self, database_url: str, gemini_api_key: str):
        """
        Initialize handler with Story 1.5 production components.

        Args:
            database_url: PostgreSQL connection string for production database
            gemini_api_key: Gemini API key for embeddings
        """
        try:
            # Use existing production components from Story 1.5
            self.store = PostgresChunkStore(dims=3072, database_url=database_url)
            self.embedder = GeminiEmbedder(api_key=gemini_api_key)

            logger.info("CWEQueryHandler initialized with Story 1.5 production infrastructure")

            # Verify database connection
            stats = self.store.get_collection_stats()
            logger.info(f"Connected to production database: {stats['count']} chunks available")

            if stats['count'] == 0:
                logger.warning("Production database appears empty. Verify Story 1.5 ingestion completed.")

        except Exception as e:
            logger.error(f"Failed to initialize CWEQueryHandler: {e}")
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

            # Generate embedding using existing Gemini embedder from Story 1.5
            query_embedding = self.embedder.embed_text(query)
            logger.debug(f"Generated {len(query_embedding)}D embedding")

            # Use existing hybrid query with optimized weights from Story 1.5 persona testing
            # These weights achieved 60% success rate in Story 1.5 validation
            weights = {
                "w_vec": 0.65,   # Vector similarity
                "w_fts": 0.25,   # Full-text search
                "w_alias": 0.10  # Alias matching
            }

            # Apply persona-specific section boost if configured
            section_boost = user_context.get("section_boost")
            query_params = {
                "query_text": query,
                "query_embedding": query_embedding,
                "limit_chunks": 10,
                **weights
            }

            if section_boost:
                query_params["section_intent_boost"] = section_boost
                query_params["section_boost_value"] = 0.15
                logger.debug(f"Applied section boost: {section_boost}")

            # Execute hybrid search using Story 1.5 production system
            results = self.store.query_hybrid(**query_params)

            logger.info(f"Retrieved {len(results)} chunks")

            # Log top results for debugging
            if results:
                top_cwes = [r["metadata"]["cwe_id"] for r in results[:3]]
                logger.debug(f"Top CWEs: {top_cwes}")

            return results

        except Exception as e:
            logger.error(f"Query processing failed: {e}")
            # Return empty results on error to ensure graceful degradation
            return []

    def get_database_stats(self) -> Dict[str, Any]:
        """Get production database statistics."""
        try:
            return self.store.get_collection_stats()
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
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