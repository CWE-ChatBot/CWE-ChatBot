# apps/cwe_ingestion/pg_chunk_store.py
import os
import logging
import contextlib
from typing import Any, Dict, List, Optional, Sequence, Tuple
import numpy as np

try:
    import psycopg
    HAS_PSYCOPG = True
except ImportError:
    # Allow import of this module even without psycopg for type definitions
    psycopg = None
    HAS_PSYCOPG = False

try:
    import sqlalchemy as sa
    from sqlalchemy.engine import Engine
    HAS_SQLALCHEMY = True
except ImportError:
    sa = None
    Engine = None
    HAS_SQLALCHEMY = False

logger = logging.getLogger(__name__)

DDL_CHUNKED = """
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- for gen_random_uuid on PG < 13 (on some installs)

-- Table with multiple rows per CWE (one per semantic section)
CREATE TABLE IF NOT EXISTS cwe_chunks (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cwe_id              TEXT NOT NULL,             -- 'CWE-79'
  section             TEXT NOT NULL,             -- 'Title','Abstract','Extended','Mitigations','Examples','Related','Aliases'
  section_rank        INT  NOT NULL,             -- 0..N order for aggregation
  name                TEXT NOT NULL,             -- CWE Name (duplicated per chunk for convenience)
  alternate_terms_text TEXT DEFAULT '',
  full_text           TEXT NOT NULL,
  tsv                 tsvector GENERATED ALWAYS AS (
    setweight(to_tsvector('english', COALESCE(alternate_terms_text,'')), 'A') ||
    setweight(to_tsvector('english', COALESCE(name,'')), 'B') ||
    setweight(to_tsvector('english', COALESCE(full_text,'')), 'C')
  ) STORED,
  embedding           vector(%(dims)s) NOT NULL,
  created_at          TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cwe_chunks_cwe_id_idx   ON cwe_chunks(cwe_id);
CREATE INDEX IF NOT EXISTS cwe_chunks_section_idx  ON cwe_chunks(section);
CREATE INDEX IF NOT EXISTS cwe_chunks_name_idx     ON cwe_chunks(name);
CREATE INDEX IF NOT EXISTS cwe_chunks_tsv_idx      ON cwe_chunks USING gin(tsv);
CREATE INDEX IF NOT EXISTS cwe_chunks_emb_idx      ON cwe_chunks USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);
"""

DDL_HALFVEC = """
-- Add halfvec column if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'cwe_chunks' AND column_name = 'embedding_halfvec') THEN
        ALTER TABLE cwe_chunks ADD COLUMN embedding_halfvec halfvec(%(dims)s);
    END IF;
END
$$;

-- Create halfvec index if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'cwe_chunks_halfvec_idx') THEN
        CREATE INDEX cwe_chunks_halfvec_idx ON cwe_chunks USING hnsw (embedding_halfvec halfvec_cosine_ops) WITH (m = 16, ef_construction = 64);
    END IF;
END
$$;
"""


class PostgresChunkStore:
    """
    Postgres + pgvector store with HYBRID retrieval over chunked sections.
    Table: cwe_chunks

    Clean dependency injection approach:
    - If SQLAlchemy Engine provided, use engine.raw_connection() (Cloud SQL + pg8000)
    - Otherwise, fall back to psycopg.connect(database_url) (local/proxy)
    """

    @contextlib.contextmanager
    def _cursor(self, conn):
        """Safe cursor context manager that works with both psycopg and pg8000."""
        cur = conn.cursor()
        try:
            yield cur
        finally:
            try:
                cur.close()
            except Exception:
                pass
    def __init__(self,
                 dims: int = 3072,
                 database_url: Optional[str] = None,
                 engine: Optional["Engine"] = None,
                 skip_schema_init: bool = False):
        self.dims = int(dims)
        self.database_url = database_url or os.environ.get("DATABASE_URL")
        self._engine = engine

        if not self.database_url and self._engine is None:
            raise ValueError("Either database_url or engine must be provided")

        if self._engine is None and not HAS_PSYCOPG:
            raise ImportError(
                "psycopg (v3) is required for PostgresChunkStore. Install with: pip install psycopg[binary]"
            )

        # Initialize schema (skip if flag set - used in Cloud Run where schema already exists)
        if not skip_schema_init:
            self._ensure_schema()
        else:
            logger.info("Skipping schema initialization (schema already exists from ingestion pipeline)")

    @property
    def _using_pg8000(self) -> bool:
        """Check if we're using pg8000 driver (Cloud SQL)."""
        return self._engine is not None

    @staticmethod
    def _to_vector_literal(embedding: List[float]) -> str:
        """Convert embedding to pgvector literal format."""
        return "[" + ",".join(map(str, embedding)) + "]"

    @contextlib.contextmanager
    def _get_connection(self):
        """
        Connection factory:
          - If an SQLAlchemy Engine was provided, use engine.raw_connection()
            (DBAPI connection via Cloud SQL Connector + pg8000 in Cloud Run).
          - Otherwise, fall back to psycopg.connect(self.database_url) for local/proxy.
        """
        if self._engine is not None:
            logger.debug("Using SQLAlchemy engine for database connection")
            conn = self._engine.raw_connection()
            try:
                yield conn
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        else:
            logger.debug("Using psycopg for database connection")
            conn = psycopg.connect(self.database_url)
            try:
                yield conn
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def _ensure_schema(self):
        logger.info("Ensuring Postgres chunked schema exists...")
        with self._get_connection() as conn, self._cursor(conn) as cur:
            # Create extensions
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
            cur.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")
            cur.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
            try:
                cur.execute("CREATE EXTENSION IF NOT EXISTS unaccent;")
            except Exception:
                logger.warning("unaccent extension not available, continuing without it")

            # Create table and indexes
            cur.execute(DDL_CHUNKED % {"dims": self.dims})

            # Add halfvec optimization if available
            try:
                cur.execute(DDL_HALFVEC % {"dims": self.dims})
                logger.info("halfvec optimization enabled")
            except Exception as e:
                logger.warning(f"halfvec optimization not available: {e}")

            conn.commit()

    def store_chunks(self, chunks: Sequence[Dict[str, Any]]) -> int:
        """Store multiple chunks in batch."""
        if not chunks:
            return 0

        logger.info(f"Storing {len(chunks)} chunks...")

        with self._get_connection() as conn, self._cursor(conn) as cur:
            # Clear existing data
            cur.execute("DELETE FROM cwe_chunks;")

            # Prepare data for batch insert
            values = []
            for chunk in chunks:
                emb = chunk["embedding"]
                # normalize to list[float]
                if isinstance(emb, np.ndarray):
                    emb = emb.astype(float).tolist()
                elif not isinstance(emb, list):
                    emb = list(emb)

                if self._using_pg8000:
                    emb = self._to_vector_literal(emb)

                values.append((
                    chunk["cwe_id"],
                    chunk["section"],
                    chunk["section_rank"],
                    chunk["name"],
                    chunk.get("alternate_terms_text", ""),
                    chunk["full_text"],
                    emb
                ))

            # Batch insert with appropriate casting for pg8000
            if self._using_pg8000:
                insert_sql = """
                    INSERT INTO cwe_chunks
                        (cwe_id, section, section_rank, name, alternate_terms_text, full_text, embedding)
                    VALUES (%s, %s, %s, %s, %s, %s, %s::vector)
                """
            else:
                insert_sql = """
                    INSERT INTO cwe_chunks
                        (cwe_id, section, section_rank, name, alternate_terms_text, full_text, embedding)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """

            cur.executemany(insert_sql, values)

            # Update halfvec if available
            try:
                cur.execute("UPDATE cwe_chunks SET embedding_halfvec = embedding::halfvec;")
                logger.info("Updated halfvec embeddings")
            except Exception:
                pass

            conn.commit()

        logger.info(f"Successfully stored {len(chunks)} chunks")
        return len(chunks)

    def hybrid_search(
        self,
        query_embedding: List[float],
        query_text: str = "",
        limit: int = 5,
        similarity_threshold: float = 0.1
    ) -> List[Dict[str, Any]]:
        """Perform hybrid search combining vector similarity and text search."""
        with self._get_connection() as conn, self._cursor(conn) as cur:
            # normalize embedding
            qe = query_embedding
            if isinstance(qe, np.ndarray):
                qe = qe.astype(float).tolist()
            elif not isinstance(qe, list):
                qe = list(qe)

            if self._using_pg8000:
                vec_param = self._to_vector_literal(qe)
                halfvec_left = "%s::halfvec"
                vector_left  = "%s::vector"
            else:
                vec_param = qe
                # psycopg is fine with no cast, but explicit cast is also safe:
                halfvec_left = "%s::halfvec"
                vector_left  = "%s::vector"

            # Prefer halfvec; if that errors, fall back to vector
            try:
                search_sql = f"""
                WITH vector_search AS (
                    SELECT *, (embedding_halfvec <=> {halfvec_left}) AS vec_distance
                    FROM cwe_chunks
                    WHERE (embedding_halfvec <=> {halfvec_left}) <= %s
                    ORDER BY embedding_halfvec <=> {halfvec_left}
                    LIMIT %s
                ),
                text_search AS (
                    SELECT *, ts_rank(tsv, plainto_tsquery('english', %s)) AS text_rank
                    FROM cwe_chunks
                    WHERE tsv @@ plainto_tsquery('english', %s)
                    ORDER BY ts_rank(tsv, plainto_tsquery('english', %s)) DESC
                    LIMIT %s
                )
                SELECT DISTINCT ON (id) *
                FROM (
                    SELECT *, vec_distance, 0 as text_rank FROM vector_search
                    UNION ALL
                    SELECT *, 999 as vec_distance, text_rank FROM text_search
                ) combined
                ORDER BY id, LEAST(vec_distance, 1.0 - text_rank)
                LIMIT %s;
                """
                params = [
                    vec_param, vec_param, (1.0 - similarity_threshold), vec_param, (limit * 2),
                    query_text, query_text, query_text, (limit * 2),
                    limit
                ]
                cur.execute(search_sql, params)
            except Exception:
                # Fallback to regular vector column
                search_sql = f"""
                WITH vector_search AS (
                    SELECT *, (embedding <=> {vector_left}) AS vec_distance
                    FROM cwe_chunks
                    WHERE (embedding <=> {vector_left}) <= %s
                    ORDER BY embedding <=> {vector_left}
                    LIMIT %s
                ),
                text_search AS (
                    SELECT *, ts_rank(tsv, plainto_tsquery('english', %s)) AS text_rank
                    FROM cwe_chunks
                    WHERE tsv @@ plainto_tsquery('english', %s)
                    ORDER BY ts_rank(tsv, plainto_tsquery('english', %s)) DESC
                    LIMIT %s
                )
                SELECT DISTINCT ON (id) *
                FROM (
                    SELECT *, vec_distance, 0 as text_rank FROM vector_search
                    UNION ALL
                    SELECT *, 999 as vec_distance, text_rank FROM text_search
                ) combined
                ORDER BY id, LEAST(vec_distance, 1.0 - text_rank)
                LIMIT %s;
                """
                params = [
                    vec_param, vec_param, (1.0 - similarity_threshold), vec_param, (limit * 2),
                    query_text, query_text, query_text, (limit * 2),
                    limit
                ]
                cur.execute(search_sql, params)

            rows = cur.fetchall()
            columns = [d[0] for d in cur.description]
            return [dict(zip(columns, r)) for r in rows]

    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the stored chunks."""
        with self._get_connection() as conn, self._cursor(conn) as cur:
            cur.execute("SELECT COUNT(*) FROM cwe_chunks;")
            count = cur.fetchone()[0]

            cur.execute("SELECT COUNT(DISTINCT cwe_id) FROM cwe_chunks;")
            unique_cwes = cur.fetchone()[0]

            cur.execute("SELECT COUNT(DISTINCT section) FROM cwe_chunks;")
            unique_sections = cur.fetchone()[0]

            # Check if halfvec is available
            try:
                cur.execute("SELECT COUNT(*) FROM cwe_chunks WHERE embedding_halfvec IS NOT NULL;")
                halfvec_count = cur.fetchone()[0]
                has_halfvec = halfvec_count > 0
            except Exception:
                has_halfvec = False

            return {
                "count": count,
                "unique_cwes": unique_cwes,
                "unique_sections": unique_sections,
                "has_halfvec_optimization": has_halfvec,
                "dimensions": self.dims
            }

    def query_hybrid(
        self,
        query_text: str,
        query_embedding: List[float],
        limit_chunks: int = 10,
        w_vec: float = 0.65,
        w_fts: float = 0.25,
        w_alias: float = 0.10,
        section_intent_boost: Optional[str] = None,
        section_boost_value: float = 0.15,
    ) -> List[Dict[str, Any]]:
        """
        Hybrid retrieval with RRF-style weighted ranking for chunked CWE data.
        Combines vector similarity, full-text search, and alias matching.
        Supports optional section-specific boosting for persona-based queries.

        Args:
            query_text: User query string
            query_embedding: Query embedding vector
            limit_chunks: Maximum number of chunks to return
            w_vec: Weight for vector similarity
            w_fts: Weight for full-text search
            w_alias: Weight for alias matching
            section_intent_boost: Optional section name to boost (e.g., "Mitigations")
            section_boost_value: Boost multiplier for matching sections

        Returns:
            List of chunks with metadata and scores
        """
        with self._get_connection() as conn, self._cursor(conn) as cur:
            # Normalize embedding
            qe = query_embedding
            if isinstance(qe, np.ndarray):
                qe = qe.astype(float).tolist()
            elif not isinstance(qe, list):
                qe = list(qe)

            if self._using_pg8000:
                vec_param = self._to_vector_literal(qe)
                halfvec_cast = "%s::halfvec"
            else:
                vec_param = qe
                halfvec_cast = "%s::halfvec"

            # Build hybrid query with RRF-style weighted ranking
            # Prefer halfvec for performance
            try:
                sql = f"""
                WITH vec AS (
                    SELECT id, cwe_id, section, section_rank, name, full_text, alternate_terms_text,
                           (embedding_halfvec <=> {halfvec_cast}) AS cos_dist
                      FROM cwe_chunks
                  ORDER BY embedding_halfvec <=> {halfvec_cast}
                     LIMIT 50
                ),
                fts AS (
                    SELECT id, ts_rank(tsv, websearch_to_tsquery('english', %s)) AS fts_rank
                      FROM cwe_chunks
                     WHERE tsv @@ websearch_to_tsquery('english', %s)
                ),
                joined AS (
                    SELECT v.*, COALESCE(f.fts_rank, 0) AS fts_rank,
                           GREATEST(
                               similarity(lower(v.alternate_terms_text), lower(%s)),
                               similarity(lower(regexp_replace(v.alternate_terms_text, '[^a-z0-9 ]', ' ', 'gi')), lower(%s))
                           ) AS alias_sim
                      FROM vec v
                 LEFT JOIN fts f USING (id)
                ),
                agg AS (
                    SELECT *,
                           COALESCE(1 - (cos_dist / NULLIF((SELECT MAX(cos_dist) FROM joined), 0)), 0) AS vec_sim_norm,
                           COALESCE(fts_rank / NULLIF(GREATEST((SELECT MAX(fts_rank) FROM joined), 1e-9), 0), 0) AS fts_norm,
                           COALESCE(alias_sim / NULLIF((SELECT MAX(alias_sim) FROM joined), 0), 0) AS alias_norm
                      FROM joined
                )
                SELECT id, cwe_id, section, section_rank, name, full_text,
                       vec_sim_norm, fts_norm, alias_norm,
                       (%s * COALESCE(vec_sim_norm,0)) +
                       (%s * COALESCE(fts_norm,0)) +
                       (%s * COALESCE(alias_norm,0)) AS hybrid_score
                  FROM agg
              ORDER BY hybrid_score DESC NULLS LAST
                 LIMIT %s;
                """
                params = (
                    vec_param, vec_param,  # vector search
                    query_text, query_text,  # FTS
                    query_text, query_text,  # alias matching
                    w_vec, w_fts, w_alias, limit_chunks
                )
                cur.execute(sql, params)
            except Exception:
                # Fallback to regular vector column if halfvec fails
                sql = f"""
                WITH vec AS (
                    SELECT id, cwe_id, section, section_rank, name, full_text, alternate_terms_text,
                           (embedding <=> %s::vector) AS cos_dist
                      FROM cwe_chunks
                  ORDER BY embedding <=> %s::vector
                     LIMIT 50
                ),
                fts AS (
                    SELECT id, ts_rank(tsv, websearch_to_tsquery('english', %s)) AS fts_rank
                      FROM cwe_chunks
                     WHERE tsv @@ websearch_to_tsquery('english', %s)
                ),
                joined AS (
                    SELECT v.*, COALESCE(f.fts_rank, 0) AS fts_rank,
                           GREATEST(
                               similarity(lower(v.alternate_terms_text), lower(%s)),
                               similarity(lower(regexp_replace(v.alternate_terms_text, '[^a-z0-9 ]', ' ', 'gi')), lower(%s))
                           ) AS alias_sim
                      FROM vec v
                 LEFT JOIN fts f USING (id)
                ),
                agg AS (
                    SELECT *,
                           COALESCE(1 - (cos_dist / NULLIF((SELECT MAX(cos_dist) FROM joined), 0)), 0) AS vec_sim_norm,
                           COALESCE(fts_rank / NULLIF(GREATEST((SELECT MAX(fts_rank) FROM joined), 1e-9), 0), 0) AS fts_norm,
                           COALESCE(alias_sim / NULLIF((SELECT MAX(alias_sim) FROM joined), 0), 0) AS alias_norm
                      FROM joined
                )
                SELECT id, cwe_id, section, section_rank, name, full_text,
                       vec_sim_norm, fts_norm, alias_norm,
                       (%s * COALESCE(vec_sim_norm,0)) +
                       (%s * COALESCE(fts_norm,0)) +
                       (%s * COALESCE(alias_norm,0)) AS hybrid_score
                  FROM agg
              ORDER BY hybrid_score DESC NULLS LAST
                 LIMIT %s;
                """
                params = (
                    vec_param, vec_param,  # vector search
                    query_text, query_text,  # FTS
                    query_text, query_text,  # alias matching
                    w_vec, w_fts, w_alias, limit_chunks
                )
                cur.execute(sql, params)

            rows = cur.fetchall()

        # Format results
        results: List[Dict[str, Any]] = []
        for r in rows:
            chunk = {
                "chunk_id": str(r[0]),
                "metadata": {
                    "cwe_id": r[1],
                    "section": r[2],
                    "section_rank": r[3],
                    "name": r[4],
                },
                "document": r[5],
                "scores": {
                    "vec": float(r[6]) if r[6] is not None else 0.0,
                    "fts": float(r[7]) if r[7] is not None else 0.0,
                    "alias": float(r[8]) if r[8] is not None else 0.0,
                    "hybrid": float(r[9]),
                }
            }

            # Apply section boost if specified
            if section_intent_boost and r[2] == section_intent_boost:
                chunk["scores"]["hybrid"] *= (1.0 + section_boost_value)

            results.append(chunk)

        # Re-sort if section boost was applied
        if section_intent_boost:
            results.sort(key=lambda x: x["scores"]["hybrid"], reverse=True)

        return results

    def test_connection(self) -> bool:
        """Test database connectivity."""
        try:
            with self._get_connection() as conn, self._cursor(conn) as cur:
                cur.execute("SELECT 1;")
                return cur.fetchone()[0] == 1
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False