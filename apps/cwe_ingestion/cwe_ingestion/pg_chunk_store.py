# apps/cwe_ingestion/pg_chunk_store.py
import contextlib
import logging
import os
import re
from typing import Any, Dict, Generator, List, Optional, Sequence

import numpy as np

psycopg: Any
try:
    import psycopg as _psycopg

    psycopg = _psycopg
    HAS_PSYCOPG = True
except ImportError:
    # Allow import of this module even without psycopg for type definitions
    psycopg = None
    HAS_PSYCOPG = False

sa: Any
Engine: Any
try:
    import sqlalchemy as _sa
    from sqlalchemy.engine import Engine as _Engine

    sa = _sa
    Engine = _Engine
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
    def _cursor(self, conn: Any) -> Generator[Any, None, None]:
        """Safe cursor context manager that works with both psycopg and pg8000."""
        cur = conn.cursor()
        try:
            yield cur
        finally:
            try:
                cur.close()
            except Exception:
                pass

    def __init__(
        self,
        dims: int = 3072,
        database_url: Optional[str] = None,
        engine: Optional["Engine"] = None,
        skip_schema_init: bool = False,
    ):
        """
        Always reuse connections:
          - Prefer a pooled SQLAlchemy Engine (created here if not provided).
          - If SQLAlchemy isn't available, fall back to a single persistent psycopg connection.
        """
        self.dims = int(dims)
        self.database_url = database_url or os.environ.get("DATABASE_URL")
        self._engine: Optional["Engine"] = engine
        # psycopg connection kept open if engine is unavailable
        self._persistent_conn: Optional[Any] = None

        if not self.database_url and self._engine is None:
            raise ValueError("Either database_url or engine must be provided")

        # Ensure we have a pooled engine if SQLAlchemy is available and no engine was passed.
        if self._engine is None and HAS_SQLALCHEMY and self.database_url:
            # Reasonable defaults; adjust via central factory if desired.
            self._engine = sa.create_engine(
                self.database_url,
                pool_size=5,
                max_overflow=10,
                pool_pre_ping=True,
                pool_recycle=1800,
                future=True,
            )
            logger.info("Created pooled SQLAlchemy engine for PostgresChunkStore")

        # If we still have no engine, keep a single persistent psycopg connection.
        if self._engine is None:
            if not HAS_PSYCOPG:
                raise ImportError(
                    "psycopg (v3) or SQLAlchemy is required. Install one of: "
                    "pip install psycopg[binary]  OR  pip install sqlalchemy"
                )
            # Lazy-open on first use inside _get_connection()
            logger.info(
                "Using single persistent psycopg connection (no SQLAlchemy engine detected)"
            )

        # Initialize schema (skip if flag set - used in Cloud Run where schema already exists)
        if not skip_schema_init:
            self._ensure_schema()
        else:
            logger.info(
                "Skipping schema initialization (schema already exists from ingestion pipeline)"
            )

    @property
    def _using_pg8000(self) -> bool:
        """True iff the SQLAlchemy engine is present and uses pg8000 driver."""
        try:
            return (
                self._engine is not None
                and getattr(self._engine.dialect, "driver", "") == "pg8000"
            )
        except Exception:
            return False

    @staticmethod
    def _to_vector_literal(embedding: List[float]) -> str:
        """Convert embedding to pgvector literal format."""
        return "[" + ",".join(map(str, embedding)) + "]"

    @contextlib.contextmanager
    def _get_connection(self) -> Generator[Any, None, None]:
        """
        Connection factory (no per-query handshakes):
          - With Engine: checkout a pooled connection from SQLAlchemy; close() returns to pool.
          - Without Engine: reuse one persistent psycopg connection for the process.
        """
        if self._engine is not None:
            logger.debug("Using SQLAlchemy pooled connection")
            # Use raw_connection() for transaction control
            conn = self._engine.raw_connection()
            try:
                yield conn
            finally:
                conn.close()  # return to pool
        else:
            # Lazy init persistent psycopg connection
            if self._persistent_conn is None:
                logger.debug("Opening persistent psycopg connection")
                assert self.database_url is not None
                self._persistent_conn = psycopg.connect(self.database_url)
            yield self._persistent_conn

    def _ensure_schema(self) -> None:
        logger.info("Ensuring Postgres chunked schema exists...")
        with self._get_connection() as conn, self._cursor(conn) as cur:
            # Set PostgreSQL tuning parameters for better performance
            try:
                cur.execute("SET statement_timeout = '300s';")  # 5 minute timeout
                cur.execute("SET hnsw.ef_search = 100;")  # HNSW search quality
                logger.debug("Applied PostgreSQL performance tuning")
            except Exception as e:
                logger.warning(f"Could not apply some GUCs: {e}")

            # Create extensions
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
            cur.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")
            cur.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
            try:
                cur.execute("CREATE EXTENSION IF NOT EXISTS unaccent;")
            except Exception:
                logger.warning(
                    "unaccent extension not available, continuing without it"
                )

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
            # Clear existing data (TRUNCATE is faster and keeps stats healthy)
            cur.execute("TRUNCATE TABLE cwe_chunks RESTART IDENTITY;")

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

                values.append(
                    (
                        chunk["cwe_id"],
                        chunk["section"],
                        chunk["section_rank"],
                        chunk["name"],
                        chunk.get("alternate_terms_text", ""),
                        chunk["full_text"],
                        emb,
                    )
                )

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
                cur.execute(
                    "UPDATE cwe_chunks SET embedding_halfvec = embedding::halfvec;"
                )
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
        similarity_threshold: float = 0.1,
    ) -> List[Dict[str, Any]]:
        """Perform hybrid search combining vector similarity and text search."""
        with self._get_connection() as conn, self._cursor(conn) as cur:
            # normalize embedding
            qe = query_embedding
            if isinstance(qe, np.ndarray):
                qe = qe.astype(float).tolist()
            elif not isinstance(qe, list):
                qe = list(qe)

            vec_param: Any
            if self._using_pg8000:
                vec_param = self._to_vector_literal(qe)
                halfvec_left = "%s::halfvec"
                vector_left = "%s::vector"
            else:
                vec_param = qe
                # psycopg is fine with no cast, but explicit cast is also safe:
                halfvec_left = "%s::halfvec"
                vector_left = "%s::vector"

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
                    vec_param,
                    vec_param,
                    (1.0 - similarity_threshold),
                    vec_param,
                    (limit * 2),
                    query_text,
                    query_text,
                    query_text,
                    (limit * 2),
                    limit,
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
                    vec_param,
                    vec_param,
                    (1.0 - similarity_threshold),
                    vec_param,
                    (limit * 2),
                    query_text,
                    query_text,
                    query_text,
                    (limit * 2),
                    limit,
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
                cur.execute(
                    "SELECT COUNT(*) FROM cwe_chunks WHERE embedding_halfvec IS NOT NULL;"
                )
                halfvec_count = cur.fetchone()[0]
                has_halfvec = halfvec_count > 0
            except Exception:
                has_halfvec = False

            return {
                "count": count,
                "unique_cwes": unique_cwes,
                "unique_sections": unique_sections,
                "has_halfvec_optimization": has_halfvec,
                "dimensions": self.dims,
            }

    def query_hybrid(
        self,
        query_text: str,
        query_embedding: List[float],
        limit_chunks: int = 10,
        k_vec: int = 50,  # vector candidate pool size
        w_vec: float = 0.65,
        w_fts: float = 0.25,
        w_alias: float = 0.10,
        section_intent_boost: Optional[str] = None,
        section_boost_value: float = 0.15,
    ) -> List[Dict[str, Any]]:
        """
        Hybrid retrieval with candidate pooling and trigram alias similarity.
        Combines vector KNN, FTS, and alias trigram sim; supports optional section boost.
        """
        # Normalize embedding
        qe = query_embedding
        if isinstance(qe, np.ndarray):
            qe = qe.astype(float).tolist()
        elif not isinstance(qe, list):
            qe = list(qe)

        # Clean the raw text once for FTS + alias (keep it simple and guard empties)
        q_raw = (query_text or "").strip()
        q_clean = re.sub(r"[^A-Za-z0-9\s]+", " ", q_raw).strip()
        alias_pattern = f"%{q_clean}%"

        # Driver-specific vector literal + casts
        vec_param: Any
        if self._using_pg8000:
            vec_param = self._to_vector_literal(qe)
            halfvec_cast = "%s::halfvec"
            vector_cast = "%s::vector"
        else:
            vec_param = qe
            halfvec_cast = "%s::halfvec"
            vector_cast = "%s::vector"

        def _begin_with_knn_hints(cur, ef_search: int = 32):
            """Apply transaction-scoped planner hints for HNSW KNN queries."""
            cur.execute("BEGIN;")
            cur.execute("SET LOCAL enable_seqscan = off;")
            cur.execute("SET LOCAL jit = off;")
            cur.execute(
                f"SET LOCAL hnsw.ef_search = {ef_search};"
            )  # Direct value, not parameter
            cur.execute("SET LOCAL random_page_cost = 1.1;")

        # --- Try halfvec fast path; fallback to main vector column ---
        try:
            with self._get_connection() as conn, self._cursor(conn) as cur:
                # Apply transaction-scoped hints for HNSW optimization
                _begin_with_knn_hints(cur, ef_search=32)

                sql = f"""
WITH
vec AS (
  SELECT id, (embedding_halfvec <=> {halfvec_cast}) AS dist
  FROM cwe_chunks
  ORDER BY dist
  LIMIT %s
),
fts AS (
  SELECT id, ts_rank(tsv, websearch_to_tsquery('english', %s)) AS rank
  FROM cwe_chunks
  WHERE %s <> '' AND tsv @@ websearch_to_tsquery('english', %s)
  ORDER BY rank DESC
  LIMIT %s
),
alias_hits AS (
  SELECT id
  FROM cwe_chunks
  WHERE (%s <> '' AND (alternate_terms_text ILIKE %s OR name ILIKE %s))
),
cand AS (
  SELECT id FROM vec
  UNION
  SELECT id FROM fts
  UNION
  SELECT id FROM alias_hits
),
scored AS (
  SELECT
    ch.id, ch.cwe_id, ch.section, ch.section_rank, ch.name, ch.full_text,
    (ch.embedding_halfvec <=> {halfvec_cast}) AS cos_dist,
    COALESCE(ts_rank(ch.tsv, websearch_to_tsquery('english', %s)), 0) AS fts_rank,
    GREATEST(
      similarity(lower(ch.alternate_terms_text), lower(%s)),
      similarity(lower(regexp_replace(ch.alternate_terms_text, '[^a-z0-9 ]', ' ', 'gi')), lower(%s)),
      similarity(lower(ch.name), lower(%s))
    ) AS alias_sim
  FROM cand c
  JOIN cwe_chunks ch USING (id)
),
maxes AS (
  SELECT
    GREATEST(MAX(cos_dist), 1e-9) AS max_dist,
    GREATEST(MAX(fts_rank), 1e-9) AS max_fts,
    GREATEST(MAX(alias_sim), 1e-9) AS max_alias
  FROM scored
)
SELECT id, cwe_id, section, section_rank, name, full_text,
       (1 - (cos_dist / max_dist)) AS vec_sim_norm,
       (fts_rank / max_fts)        AS fts_norm,
       (alias_sim / max_alias)     AS alias_norm,
       (%s * (1 - (cos_dist / max_dist))) +
       (%s * (fts_rank / max_fts)) +
       (%s * (alias_sim / max_alias)) AS hybrid_score
FROM scored, maxes
ORDER BY hybrid_score DESC NULLS LAST
LIMIT %s;
"""
            params = [
                # vec
                vec_param,
                k_vec,
                # fts (guard + ts_rank + where + limit)
                q_clean,
                q_clean,
                q_clean,
                k_vec,
                # alias_hits (guard + two patterns)
                q_clean,
                alias_pattern,
                alias_pattern,
                # scored: vector distance again + fts tsquery + alias sim (3 variants)
                vec_param,
                q_clean,
                q_clean,
                q_clean,
                q_clean,
                # weights + limit
                w_vec,
                w_fts,
                w_alias,
                limit_chunks,
            ]
            cur.execute(sql, params)
            rows = cur.fetchall()

            # Log candidate pooling stats within same transaction
            try:
                stats_sql = f"""
WITH
vec AS (SELECT id FROM cwe_chunks ORDER BY embedding_halfvec <=> {halfvec_cast} LIMIT %s),
fts AS (SELECT id FROM cwe_chunks WHERE %s <> '' AND tsv @@ websearch_to_tsquery('english', %s) LIMIT %s),
alias_hits AS (SELECT id FROM cwe_chunks WHERE %s <> '' AND (alternate_terms_text ILIKE %s OR name ILIKE %s))
SELECT
    (SELECT COUNT(*) FROM vec) as vec_count,
    (SELECT COUNT(*) FROM fts) as fts_count,
    (SELECT COUNT(*) FROM alias_hits) as alias_count,
    (SELECT COUNT(DISTINCT id) FROM (
        SELECT id FROM vec UNION SELECT id FROM fts UNION SELECT id FROM alias_hits
    ) cand) as total_candidates;
                """
                stats_params = [
                    vec_param,
                    k_vec,
                    q_clean,
                    q_clean,
                    k_vec,
                    q_clean,
                    alias_pattern,
                    alias_pattern,
                ]
                cur.execute(stats_sql, stats_params)
                stats_rows = cur.fetchall()
                if stats_rows:
                    vec_cnt, fts_cnt, alias_cnt, total_cnt = stats_rows[0]
                    logger.info(
                        f"Candidate pooling: vec={vec_cnt}, fts={fts_cnt}, alias={alias_cnt}, total={total_cnt}"
                    )
            except Exception as e:
                logger.debug(f"Could not log candidate stats: {e}")

            # Commit transaction
            conn.commit()

        except Exception as e:
            # Halfvec transaction automatically rolled back by context manager exit
            logger.warning(f"halfvec query failed, falling back to vector column: {e}")

            # Fallback to main vector column with transaction-scoped hints
            with self._get_connection() as conn, self._cursor(conn) as cur:
                _begin_with_knn_hints(cur, ef_search=32)

                sql = f"""
WITH
vec AS (
  SELECT id, (embedding <=> {vector_cast}) AS dist
  FROM cwe_chunks
  ORDER BY dist
  LIMIT %s
),
fts AS (
  SELECT id, ts_rank(tsv, websearch_to_tsquery('english', %s)) AS rank
  FROM cwe_chunks
  WHERE %s <> '' AND tsv @@ websearch_to_tsquery('english', %s)
  ORDER BY rank DESC
  LIMIT %s
),
alias_hits AS (
  SELECT id
  FROM cwe_chunks
  WHERE (%s <> '' AND (alternate_terms_text ILIKE %s OR name ILIKE %s))
),
cand AS (
  SELECT id FROM vec
  UNION
  SELECT id FROM fts
  UNION
  SELECT id FROM alias_hits
),
scored AS (
  SELECT
    ch.id, ch.cwe_id, ch.section, ch.section_rank, ch.name, ch.full_text,
    (ch.embedding <=> {vector_cast}) AS cos_dist,
    COALESCE(ts_rank(ch.tsv, websearch_to_tsquery('english', %s)), 0) AS fts_rank,
    GREATEST(
      similarity(lower(ch.alternate_terms_text), lower(%s)),
      similarity(lower(regexp_replace(ch.alternate_terms_text, '[^a-z0-9 ]', ' ', 'gi')), lower(%s)),
      similarity(lower(ch.name), lower(%s))
    ) AS alias_sim
  FROM cand c
  JOIN cwe_chunks ch USING (id)
),
maxes AS (
  SELECT
    GREATEST(MAX(cos_dist), 1e-9) AS max_dist,
    GREATEST(MAX(fts_rank), 1e-9) AS max_fts,
    GREATEST(MAX(alias_sim), 1e-9) AS max_alias
  FROM scored
)
SELECT id, cwe_id, section, section_rank, name, full_text,
       (1 - (cos_dist / max_dist)) AS vec_sim_norm,
       (fts_rank / max_fts)        AS fts_norm,
       (alias_sim / max_alias)     AS alias_norm,
       (%s * (1 - (cos_dist / max_dist))) +
       (%s * (fts_rank / max_fts)) +
       (%s * (alias_sim / max_alias)) AS hybrid_score
FROM scored, maxes
ORDER BY hybrid_score DESC NULLS LAST
LIMIT %s;
"""
                params = [
                    vec_param,
                    k_vec,
                    q_clean,
                    q_clean,
                    q_clean,
                    k_vec,
                    q_clean,
                    alias_pattern,
                    alias_pattern,
                    vec_param,
                    q_clean,
                    q_clean,
                    q_clean,
                    q_clean,
                    w_vec,
                    w_fts,
                    w_alias,
                    limit_chunks,
                ]
                cur.execute(sql, params)
                rows = cur.fetchall()

                # Commit transaction
                conn.commit()

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
                },
            }
            if section_intent_boost and r[2] == section_intent_boost:
                chunk["scores"]["hybrid"] *= 1.0 + section_boost_value
            results.append(chunk)

        if section_intent_boost:
            results.sort(key=lambda x: x["scores"]["hybrid"], reverse=True)

        return results

    def test_connection(self) -> bool:
        """Test database connectivity."""
        try:
            with self._get_connection() as conn, self._cursor(conn) as cur:
                cur.execute("SELECT 1;")
                row = cur.fetchone()
                return bool(row and int(row[0]) == 1)
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
