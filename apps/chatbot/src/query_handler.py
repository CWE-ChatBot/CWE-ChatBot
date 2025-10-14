#!/usr/bin/env python3
"""
CWE Query Handler - Story 2.1 Integration with Story 1.5 Production Infrastructure
Integrates with existing production hybrid retrieval system from Story 1.5.
"""

import asyncio
import errno
import os
from typing import Any, Dict, List, Literal, Optional, TypedDict

from tenacity import (
    AsyncRetrying,
    retry_if_exception,
    stop_after_attempt,
    wait_random_exponential,
)

from src.processing.query_processor import QueryProcessor
from src.security.secure_logging import get_secure_logger

# Processing components moved to ProcessingPipeline
# from src.processing.confidence_calculator import ConfidenceCalculator, create_aggregated_cwe
# from src.processing.cwe_filter import CWEFilter, create_default_filter
# from src.processing.explanation_builder import ExplanationBuilder
# from src.processing.query_suggester import QuerySuggester

# Prefer a clean package import; fall back to legacy path if package is unavailable
try:  # minimal path when cwe_ingestion is installed
    from cwe_ingestion.embedder import GeminiEmbedder
    from cwe_ingestion.pg_chunk_store import PostgresChunkStore
except Exception:  # fallback to legacy repo layout/env var
    import os
    import sys

    ingestion_path = os.getenv("CWE_INGESTION_PATH")
    if ingestion_path and os.path.isdir(ingestion_path):
        sys.path.insert(0, ingestion_path)
        from embedder import GeminiEmbedder
        from pg_chunk_store import PostgresChunkStore
    else:  # pragma: no cover
        raise

logger = get_secure_logger(__name__)


def _is_transient_db_error(e: BaseException) -> bool:
    msg = str(e).lower()
    try:
        import psycopg

        if isinstance(e, (psycopg.OperationalError, psycopg.InterfaceError)):
            return True
    except Exception:
        pass
    # SQLAlchemy wrapper case
    try:
        from sqlalchemy.exc import DBAPIError, OperationalError

        if isinstance(e, (OperationalError, DBAPIError)):
            return True
    except Exception:
        pass
    # Generic network-y signals
    if isinstance(e, OSError) and getattr(e, "errno", None) in {
        errno.ECONNRESET,
        errno.ETIMEDOUT,
        errno.EHOSTUNREACH,
        errno.ECONNABORTED,
    }:
        return True
    return any(
        s in msg
        for s in (
            "could not connect",
            "connection refused",
            "connection reset",
            "server closed the connection",
            "timeout",
            "deadlock detected",
            "terminating connection",
            "too many connections",
        )
    )


class Recommendation(TypedDict):
    """Unified recommendation format for CWE suggestions."""

    cwe_id: str
    name: str
    confidence: float
    level: Literal["High", "Medium", "Low", "Very Low"]
    explanation: Dict[str, Any]  # {"snippets":[...], "bullets":[...]}
    top_chunks: List[Dict[str, Any]]  # server-side only
    relationships: Optional[Dict[str, Any]]


class QueryResult(TypedDict):
    """Complete query processing result."""

    recommendations: List[Recommendation]
    low_confidence: bool
    improvement_guidance: Optional[Dict[str, Any]]


class CWEQueryHandler:
    """
    Handles CWE queries using existing production hybrid retrieval system from Story 1.5.

    Integrates with:
    - PostgresChunkStore: Production hybrid retrieval (Vector + FTS + Alias matching)
    - GeminiEmbedder: Production Gemini embeddings (3072D)
    """

    def __init__(
        self,
        database_url: str,
        gemini_api_key: str,
        hybrid_weights: Optional[Dict[str, float]] = None,
        engine: Any = None,
    ) -> None:
        """
        Initialize handler with Story 1.5 production components.

        Args:
            database_url: PostgreSQL connection string for production database
            gemini_api_key: Gemini API key for embeddings
            hybrid_weights: RRF weights dict with w_vec, w_fts, w_alias keys (defaults to validated config values)
            engine: Optional SQLAlchemy engine for Cloud SQL Connector (Cloud Run mode)
        """
        try:
            # Use existing production components from Story 1.5
            # Use dependency injection: prefer engine (Cloud SQL) over database_url (local/proxy)
            # Skip schema initialization in Cloud Run - schema already exists from ingestion pipeline
            skip_schema = (
                engine is not None
            )  # Skip when using Cloud SQL (production Cloud Run)

            if engine is not None:
                logger.info(
                    "Using SQLAlchemy engine for Cloud SQL Connector (skipping schema init)"
                )
                self.store = PostgresChunkStore(
                    dims=3072, engine=engine, skip_schema_init=skip_schema
                )
            else:
                logger.info("Using psycopg with database URL")
                self.store = PostgresChunkStore(
                    dims=3072, database_url=database_url, skip_schema_init=skip_schema
                )

            self.embedder = GeminiEmbedder(api_key=gemini_api_key)

            # Initialize query processor for proper CWE extraction and query analysis
            self.query_processor = QueryProcessor()

            # Processing modules moved to ProcessingPipeline for better separation of concerns

            # Store hybrid weights (use provided weights or fall back to config defaults)
            if hybrid_weights is None:
                from src.app_config import config

                self.hybrid_weights = config.get_hybrid_weights()
            else:
                self.hybrid_weights = hybrid_weights

            logger.info(
                "CWEQueryHandler initialized with Story 1.5 production infrastructure"
            )
            logger.info(f"RRF weights: {self.hybrid_weights}")

            # Verify database connection (skip if SKIP_DB_STATS=true for quick deployment)
            if os.getenv("SKIP_DB_STATS", "").lower() != "true":
                stats = self.store.get_collection_stats()
                logger.info(
                    f"Connected to production database: {stats['count']} chunks available"
                )

                if stats["count"] == 0:
                    logger.warning(
                        "Production database appears empty. Verify Story 1.5 ingestion completed."
                    )
            else:
                logger.warning("Skipping database stats check (SKIP_DB_STATS=true)")

        except Exception as e:
            logger.log_exception("Failed to initialize CWEQueryHandler", e)
            raise

    async def process_query(
        self,
        query: str,
        user_context: Dict[str, Any],
        *,
        hybrid_weights_override: Optional[Dict[str, float]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute hybrid search and return raw chunks - NO business logic applied.

        This method is now a pure Data Access Layer that only retrieves data.
        Business logic (force-injection, boosting) is handled by ProcessingPipeline.

        Args:
            query: User query string
            user_context: User persona and context information
            hybrid_weights_override: Optional custom hybrid weights

        Returns:
            List of raw retrieved chunks with metadata and scores
        """
        try:
            import time

            query_start = time.time()

            logger.info(
                f"Processing query: '{query[:50]}...' for persona: {user_context.get('persona', 'unknown')}"
            )

            # Use QueryProcessor to properly extract CWE IDs and analyze query
            query_analysis = self.query_processor.preprocess_query(query)
            extracted_cwe_ids = query_analysis.get("cwe_ids", set())
            logger.debug(f"Extracted CWE IDs: {extracted_cwe_ids}")

            # Generate embedding using existing Gemini embedder from Story 1.5 (non-blocking)
            embed_start = time.time()
            query_embedding = await asyncio.to_thread(self.embedder.embed_text, query)
            embed_time = (time.time() - embed_start) * 1000
            logger.info(
                f"✓ Embedding generated: {len(query_embedding)}D in {embed_time:.1f}ms"
            )

            # Use centralized hybrid weights from Config (Story 1.5 validated weights)
            weights = hybrid_weights_override or self.hybrid_weights

            # Apply persona-specific section boost if configured
            section_boost = user_context.get("section_boost")
            query_params = {
                "query_text": query,
                "query_embedding": query_embedding,
                "limit_chunks": 10,
                "k_vec": 50,  # vector candidate pool size
                **weights,
            }

            if section_boost:
                # Pull boost value from centralized config
                try:
                    from src.app_config import config

                    boost_value = getattr(config, "section_boost_value", 0.15)
                except Exception:
                    boost_value = 0.15
                query_params["section_intent_boost"] = section_boost
                query_params["section_boost_value"] = boost_value
                logger.debug(f"Applied section boost: {section_boost}")

            # Execute hybrid search using Story 1.5 production system
            db_start = time.time()
            # Light retries for transient DB hiccups; keep total worst-case small
            attempts = int(os.getenv("DB_RETRY_ATTEMPTS", "3"))
            timeout_s = float(os.getenv("DB_QUERY_TIMEOUT_SEC", "20"))

            # Get correlation ID for request tracing
            from src.observability import get_correlation_id

            correlation_id = get_correlation_id()

            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(attempts),
                wait=wait_random_exponential(
                    multiplier=0.3, max=float(os.getenv("DB_RETRY_MAX_WAIT", "2.0"))
                ),
                retry=retry_if_exception(_is_transient_db_error),
                reraise=True,
            ):
                with attempt:
                    attempt_num = attempt.retry_state.attempt_number
                    logger.info(
                        "DB hybrid search attempt %d/%d",
                        attempt_num,
                        attempts,
                        extra={
                            "correlation_id": correlation_id,
                            "attempt_number": attempt_num,
                            "max_attempts": attempts,
                        },
                    )
                    try:
                        # Run the blocking call on a worker thread, but bound by an async timeout
                        results = await asyncio.wait_for(
                            asyncio.to_thread(self.store.query_hybrid, **query_params),
                            timeout=timeout_s,
                        )
                    except Exception as e:
                        will_retry = attempt_num < attempts
                        logger.warning(
                            "DB hybrid search failed on attempt %d/%d: %s",
                            attempt_num,
                            attempts,
                            type(e).__name__,
                            extra={
                                "correlation_id": correlation_id,
                                "attempt_number": attempt_num,
                                "error_type": type(e).__name__,
                                "will_retry": will_retry,
                            },
                        )
                        raise
            db_time = (time.time() - db_start) * 1000

            total_time = (time.time() - query_start) * 1000

            logger.info(
                f"✓ Retrieved {len(results)} chunks in {db_time:.1f}ms (total: {total_time:.1f}ms)"
            )

            # Log top results for debugging
            if results:
                top_cwes = [r["metadata"]["cwe_id"] for r in results[:3]]
                top_scores = [r["scores"]["hybrid"] for r in results[:3]]
                logger.info(
                    f"Top results: {list(zip(top_cwes, [f'{s:.2f}' for s in top_scores]))}"
                )

            return list(results)

        except Exception as e:
            logger.log_exception("Query processing failed", e)
            # Return empty results on error to ensure graceful degradation
            return []

    def fetch_canonical_sections_for_cwes(
        self, cwe_ids: List[str], limit_per_cwe: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Fetch canonical sections for specific CWE IDs. Used by ProcessingPipeline for business logic.

        Args:
            cwe_ids: List of CWE IDs to fetch sections for
            limit_per_cwe: Maximum number of sections per CWE

        Returns:
            List of chunks in query_hybrid format
        """
        sections = []
        for cwe_id in cwe_ids:
            try:
                cwe_sections = self._fetch_cwe_sections(cwe_id, limit=limit_per_cwe)
                sections.extend(cwe_sections)
            except Exception as e:
                logger.warning(f"Failed to fetch sections for {cwe_id}: {e}")
                continue
        return sections

    # Business logic methods removed - moved to ProcessingPipeline for better separation of concerns
    # process_query_with_recommendations() -> ProcessingPipeline.generate_recommendations()
    # _aggregate_chunks_by_cwe() -> ProcessingPipeline._aggregate_chunks_by_cwe()

    def get_database_stats(self) -> Dict[str, Any]:
        """Get production database statistics."""
        try:
            stats: Dict[str, Any] = self.store.get_collection_stats()
            return stats
        except Exception as e:
            logger.log_exception("Failed to get database stats", e)
            return {"count": 0, "error": str(e)}

    def get_canonical_cwe_metadata(
        self, cwe_ids: List[str]
    ) -> Dict[str, Dict[str, str]]:
        """
        Fetch canonical CWE metadata (name, abstraction, status) from the embeddings table.

        Args:
            cwe_ids: List of CWE IDs like ["CWE-79", "CWE-89"]

        Returns:
            Dict mapping CWE ID to {name, abstraction, status}
        """
        meta: Dict[str, Dict[str, str]] = {}
        if not cwe_ids:
            return meta
        try:
            with self.store._get_connection() as conn:
                # Normalize IDs to uppercase
                ids = [str(cid).upper() for cid in cwe_ids]
                # Safe: placeholders are programmatically generated (%s), not user input
                placeholders = ",".join(["%s"] * len(ids))  # nosec B608
                # Prefer cwe_catalog if present; fallback to cwe_embeddings
                with self.store._cursor(conn) as cur:
                    try:
                        cur.execute(
                            f"SELECT cwe_id, name, abstraction, status FROM cwe_catalog WHERE UPPER(cwe_id) IN ({placeholders})",  # nosec B608
                            ids,
                        )
                        rows = cur.fetchall()
                        if rows:
                            for cwe_id, name, abstraction, status in rows:
                                meta[str(cwe_id).upper()] = {
                                    "name": name or "",
                                    "abstraction": abstraction or "",
                                    "status": status or "",
                                }
                    except Exception:
                        # Fall back to embeddings if catalog is missing
                        cur.execute(
                            f"SELECT cwe_id, name, abstraction, status FROM cwe_embeddings WHERE UPPER(cwe_id) IN ({placeholders})",  # nosec B608
                            ids,
                        )
                        rows = cur.fetchall()
                        for cwe_id, name, abstraction, status in rows:
                            meta[str(cwe_id).upper()] = {
                                "name": name or "",
                                "abstraction": abstraction or "",
                                "status": status or "",
                            }
        except Exception as e:
            # Downgrade noise when tables are not present
            msg = str(e)
            if "UndefinedTable" in msg or "undefined table" in msg.lower():
                logger.info("Canonical CWE metadata table(s) not available; skipping")
            else:
                logger.log_exception("Failed to fetch canonical CWE metadata", e)
        return meta

    def get_cwe_policy_labels(self, cwe_ids: List[str]) -> Dict[str, Dict[str, str]]:
        """
        Fetch CWE policy labels (e.g., vulnerability mapping policy: Allowed / Allowed-with-Review / Discouraged)
        from a dedicated table if present. This table is separate from embeddings and may be managed independently.

        Expected schema (if present):
        CREATE TABLE cwe_policy_labels (
          cwe_id TEXT PRIMARY KEY,
          mapping_label TEXT,  -- e.g., 'Allowed', 'Allowed-with-Review', 'Discouraged'
          notes TEXT
        );
        """
        labels: Dict[str, Dict[str, str]] = {}
        if not cwe_ids:
            return labels
        try:
            with self.store._get_connection() as conn:
                ids = [str(cid).upper() for cid in cwe_ids]
                # Safe: placeholders are programmatically generated (%s), not user input
                placeholders = ",".join(["%s"] * len(ids))  # nosec B608
                sql = f"""
                    SELECT cwe_id, mapping_label, COALESCE(notes, '')
                      FROM cwe_policy_labels
                     WHERE UPPER(cwe_id) IN ({placeholders})
                """  # nosec B608
                with self.store._cursor(conn) as cur:
                    try:
                        cur.execute(sql, ids)
                        for cwe_id, mapping_label, notes in cur.fetchall():
                            labels[str(cwe_id).upper()] = {
                                "mapping_label": mapping_label or "",
                                "notes": notes or "",
                            }
                    except Exception as e:
                        # Table may not exist; log at info to avoid noise
                        logger.info(
                            f"Policy labels table not available or fetch failed: {e}"
                        )
        except Exception:
            pass
        return labels

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

    def _fetch_cwe_sections(
        self, cwe_id: str, *, limit: int = 3
    ) -> List[Dict[str, Any]]:
        """Fetch top sections for a given CWE ID directly from the store.
        Returns chunks shaped like query_hybrid outputs.
        """
        rows: List[Dict[str, Any]] = []
        try:
            with self.store._get_connection() as conn:
                with self.store._cursor(conn) as cur:
                    cur.execute(
                        """
                        SELECT id, cwe_id, section, section_rank, name, full_text
                        FROM cwe_chunks
                        WHERE UPPER(cwe_id) = %s
                        ORDER BY section_rank ASC
                        LIMIT %s
                        """,
                        (cwe_id.upper(), int(limit)),
                    )
                    for (
                        chunk_id,
                        cid,
                        section,
                        section_rank,
                        name,
                        full_text,
                    ) in cur.fetchall():
                        rows.append(
                            {
                                "chunk_id": str(chunk_id),
                                "metadata": {
                                    "cwe_id": cid,
                                    "section": section,
                                    "section_rank": section_rank,
                                    "name": name,
                                },
                                "document": full_text,
                                "scores": {
                                    "vec": 0.0,
                                    "fts": 0.0,
                                    "alias": 0.0,
                                    "hybrid": 0.0,
                                },
                            }
                        )
        except Exception as e:
            logger.log_exception("Forced CWE section fetch failed", e)
        return rows
