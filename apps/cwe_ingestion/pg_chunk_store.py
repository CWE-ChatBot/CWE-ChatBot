# apps/cwe_ingestion/pg_chunk_store.py
import os
import logging
from typing import Any, Dict, List, Optional, Sequence
import numpy as np

try:
    import psycopg
except ImportError as e:
    raise ImportError(
        "psycopg (v3) is required for Postgres chunked store. Install with: pip install psycopg[binary]"
    ) from e

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
CREATE INDEX IF NOT EXISTS cwe_chunks_section_idx  ON cwe_chunks(section, section_rank);
CREATE INDEX IF NOT EXISTS cwe_chunks_tsv_gin      ON cwe_chunks USING GIN (tsv);

-- Natural unique key for preventing duplicates on re-ingest
CREATE UNIQUE INDEX IF NOT EXISTS cwe_chunks_unique ON cwe_chunks (cwe_id, section, section_rank);

DO $$
BEGIN
  -- Try HNSW first; if unavailable, fall back to IVFFlat
  BEGIN
    EXECUTE 'CREATE INDEX cwe_chunks_hnsw_cos ON cwe_chunks USING hnsw (embedding vector_cosine_ops)';
  EXCEPTION WHEN others THEN
    PERFORM 1;
  END;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'cwe_chunks_hnsw_cos') THEN
    BEGIN
      EXECUTE 'CREATE INDEX IF NOT EXISTS cwe_chunks_ivf_cos ON cwe_chunks USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)';
    EXCEPTION WHEN others THEN
      PERFORM 1;
    END;
  END IF;
END $$;
"""

class PostgresChunkStore:
    """
    Postgres + pgvector store with HYBRID retrieval over chunked sections.
    Table: cwe_chunks
    """

    def __init__(self, dims: int = 3072, database_url: Optional[str] = None):
        self.dims = int(dims)
        self.database_url = database_url or os.environ.get("DATABASE_URL")
        if not self.database_url:
            raise ValueError("DATABASE_URL is required for PostgresChunkStore")

        # Configure connection for Google Cloud SQL IAM if needed
        conn_params = self._prepare_connection_params(self.database_url)
        self.conn = psycopg.connect(**conn_params)
        self.conn.execute("SET statement_timeout = '30s';")
        self.conn.execute("SET ivfflat.probes = 10;")  # Improve IVFFlat recall (harmless if HNSW is used)
        self.conn.execute("SET hnsw.ef_search = 80;")  # Improve HNSW recall (harmless if IVFFlat is used)
        self._ensure_schema()

    def _prepare_connection_params(self, database_url: str) -> Dict[str, Any]:
        """
        Prepare connection parameters, adding Google Cloud SQL IAM support if needed.
        """
        import urllib.parse

        parsed = urllib.parse.urlparse(database_url)

        # Check if this looks like Google Cloud SQL IAM format
        # Format: postgresql://username@project:region:instance/dbname
        # The netloc will be "username@project:region:instance"
        netloc = (parsed.netloc or "")
        has_at_symbol = "@" in netloc
        has_colon_after_at = "@" in netloc and ":" in netloc.split("@", 1)[-1]

        is_gcp_iam = (
            has_at_symbol and
            has_colon_after_at and
            parsed.password is None
        )

        if is_gcp_iam:
            logger.info("Detected Google Cloud SQL IAM authentication format.")
            # For Google Cloud SQL with IAM, add specific connection parameters
            # Check if sslmode is explicitly set in URL parameters
            query_params = urllib.parse.parse_qs(parsed.query)
            sslmode = query_params.get('sslmode', ['require'])[0]  # Default to require, but allow override

            return {
                "conninfo": database_url,
                "sslmode": sslmode,  # Respect URL parameter for sslmode
                "connect_timeout": 10,
                # IAM authentication is handled by the psycopg driver
                # when no password is provided and IAM credentials are available
            }
        else:
            # Standard PostgreSQL connection
            return {"conninfo": database_url}

    def _ensure_schema(self):
        logger.info("Ensuring Postgres chunked schema exists...")

        # Create schema step by step to avoid transaction issues
        with self.conn.cursor() as cur:
            # Create extensions
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
            cur.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")
            cur.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
            try:
                cur.execute("CREATE EXTENSION IF NOT EXISTS unaccent;")
            except Exception:
                logger.warning("unaccent extension not available, continuing without it")

            # Create table
            from psycopg import sql
            table_ddl = sql.SQL("""
                CREATE TABLE IF NOT EXISTS cwe_chunks (
                    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    cwe_id              TEXT NOT NULL,
                    section             TEXT NOT NULL,
                    section_rank        INT  NOT NULL,
                    name                TEXT NOT NULL,
                    alternate_terms_text TEXT DEFAULT '',
                    full_text           TEXT NOT NULL,
                    tsv                 tsvector GENERATED ALWAYS AS (
                        setweight(to_tsvector('english', COALESCE(alternate_terms_text,'')), 'A') ||
                        setweight(to_tsvector('english', COALESCE(name,'')), 'B') ||
                        setweight(to_tsvector('english', COALESCE(full_text,'')), 'C')
                    ) STORED,
                    embedding           vector({}) NOT NULL,
                    created_at          TIMESTAMPTZ DEFAULT now()
                );
            """).format(sql.Literal(self.dims))
            cur.execute(table_ddl)

            # Create indexes
            cur.execute("CREATE INDEX IF NOT EXISTS cwe_chunks_cwe_id_idx ON cwe_chunks(cwe_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS cwe_chunks_section_idx ON cwe_chunks(section, section_rank);")
            cur.execute("CREATE INDEX IF NOT EXISTS cwe_chunks_tsv_gin ON cwe_chunks USING GIN (tsv);")
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS cwe_chunks_unique ON cwe_chunks (cwe_id, section, section_rank);")
            # Trigram index for alias similarity matching
            try:
                cur.execute("CREATE INDEX IF NOT EXISTS cwe_chunks_alias_trgm ON cwe_chunks USING GIN (lower(alternate_terms_text) gin_trgm_ops);")
            except Exception:
                logger.warning("Could not create trigram index for alternate_terms_text; continuing")

            # Create vector index - try HNSW first, fall back to IVFFlat
            try:
                cur.execute("SELECT 1 FROM pg_indexes WHERE indexname = 'cwe_chunks_hnsw_cos' AND tablename = 'cwe_chunks';")
                if not cur.fetchone():
                    try:
                        cur.execute("CREATE INDEX cwe_chunks_hnsw_cos ON cwe_chunks USING hnsw (embedding vector_cosine_ops) WITH (m = 24, ef_construction = 200);")
                        logger.info("Created HNSW vector index on cwe_chunks")
                    except Exception:
                        logger.info("HNSW not available, falling back to IVFFlat for cwe_chunks")
                        ivf_lists = self._recommended_ivf_lists('cwe_chunks')
                        ivf_sql = sql.SQL("CREATE INDEX IF NOT EXISTS cwe_chunks_ivf_cos ON cwe_chunks USING ivfflat (embedding vector_cosine_ops) WITH (lists = {});").format(sql.Literal(ivf_lists))
                        cur.execute(ivf_sql)
            except Exception as e:
                logger.warning(f"Vector index creation skipped: {e}")

        self.conn.commit()
        logger.info("Schema setup completed for chunked table: cwe_chunks")

    def _recommended_ivf_lists(self, table_name: str) -> int:
        """Calculate IVF lists from current table count (sqrt(N), clamped)."""
        from psycopg import sql
        try:
            with self.conn.cursor() as cur:
                cur.execute(sql.SQL("SELECT GREATEST(1, COUNT(*)) FROM {}").format(sql.Identifier(table_name)))
                result = cur.fetchone()
                (n,) = result if result else (1,)
        except psycopg.errors.UndefinedTable:
            # Table doesn't exist yet, use default
            n = 1
        import math
        return max(64, min(8192, int(math.sqrt(n))))


    # ---------- Writes ----------
    def store_batch(self, chunks: List[Dict[str, Any]]) -> int:
        """
        chunks: list of dicts with keys:
          cwe_id, section, section_rank, name, full_text, alternate_terms_text, embedding
        """
        if not chunks:
            return 0
        rows: Sequence[tuple] = []
        for ch in chunks:
            emb = ch["embedding"]
            if isinstance(emb, np.ndarray):
                emb = emb.tolist()
            rows.append((
                ch["cwe_id"],
                ch["section"],
                int(ch["section_rank"]),
                ch["name"],
                ch.get("alternate_terms_text", "") or "",
                ch["full_text"],
                emb
            ))
        sql = """
        INSERT INTO cwe_chunks
          (cwe_id, section, section_rank, name, alternate_terms_text, full_text, embedding)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (cwe_id, section, section_rank) DO UPDATE SET
          name = EXCLUDED.name,
          alternate_terms_text = EXCLUDED.alternate_terms_text,
          full_text = EXCLUDED.full_text,
          embedding = EXCLUDED.embedding,
          created_at = LEAST(cwe_chunks.created_at, now());
        """
        with self.conn.transaction():
            with self.conn.cursor() as cur:
                cur.executemany(sql, rows)

        # Refresh statistics after significant batch inserts for optimal query planning
        if len(rows) >= 10:  # Only for meaningful batch sizes
            with self.conn.cursor() as cur:
                cur.execute("ANALYZE cwe_chunks;")
            self.conn.commit()
            logger.debug(f"Refreshed table statistics after inserting {len(rows)} chunks")

        return len(rows)

    # ---------- Vector-only (compat) ----------
    def query_similar(self, query_embedding: np.ndarray, n_results: int = 5) -> List[Dict]:
        if isinstance(query_embedding, np.ndarray):
            query_embedding = query_embedding.tolist()
        sql = """
        SELECT cwe_id, section, section_rank, name, full_text,
               embedding <=> %s::vector AS cos_dist
          FROM cwe_chunks
      ORDER BY embedding <=> %s::vector
         LIMIT %s;
        """
        with self.conn.cursor() as cur:
            cur.execute(sql, (query_embedding, query_embedding, n_results))
            rows = cur.fetchall()
        out: List[Dict] = []
        for r in rows:
            out.append({
                "metadata": {
                    "cwe_id": r[0],
                    "section": r[1],
                    "section_rank": r[2],
                    "name": r[3],
                },
                "document": r[4],
                "distance": float(r[5]),
            })
        return out

    # ---------- Optimized halfvec queries for <200ms p95 ----------
    def query_similar_fast(self, query_embedding: np.ndarray, n_results: int = 5) -> List[Dict]:
        """
        Fast vector similarity search using halfvec(3072) + HNSW index.
        Target: <20ms query time for optimal p95 performance.
        """
        if isinstance(query_embedding, np.ndarray):
            # Normalize to unit length for cosine similarity
            query_embedding = query_embedding / np.linalg.norm(query_embedding)
            query_embedding = query_embedding.tolist()

        # Optimize HNSW settings for speed
        with self.conn.cursor() as cur:
            cur.execute("SET LOCAL hnsw.ef_search = 80;")
            cur.execute("SET LOCAL jit = off;")
            cur.execute("SET LOCAL work_mem = '64MB';")

            sql = """
            SELECT cwe_id, section, section_rank, name, full_text,
                   embedding_h <=> %s::halfvec AS cos_dist
              FROM cwe_chunks
          ORDER BY embedding_h <=> %s::halfvec
             LIMIT %s;
            """
            cur.execute(sql, (query_embedding, query_embedding, n_results))
            rows = cur.fetchall()

        out: List[Dict] = []
        for r in rows:
            out.append({
                "metadata": {
                    "cwe_id": r[0],
                    "section": r[1],
                    "section_rank": r[2],
                    "name": r[3],
                },
                "document": r[4],
                "distance": float(r[5]),
            })
        return out

    def query_hybrid_fast(
        self,
        query_text: str,
        query_embedding: np.ndarray,
        limit_chunks: int = 20,
        fts_limit: int = 200,
        section_intent_boost: Optional[str] = None,
    ) -> List[Dict]:
        """
        Fast hybrid search: FTS shortlist → halfvec rerank for optimal performance.
        Recommended pattern for <200ms p95 end-to-end.
        """
        if isinstance(query_embedding, np.ndarray):
            # Normalize to unit length for cosine similarity
            query_embedding = query_embedding / np.linalg.norm(query_embedding)
            query_embedding = query_embedding.tolist()

        # Optimize PostgreSQL settings
        with self.conn.cursor() as cur:
            cur.execute("SET LOCAL hnsw.ef_search = 64;")  # Lower for hybrid (speed over pure accuracy)
            cur.execute("SET LOCAL jit = off;")
            cur.execute("SET LOCAL work_mem = '64MB';")

            # Hybrid query: FTS shortlist → halfvec rerank
            sql = """
            WITH txt AS (
              SELECT id
              FROM   cwe_chunks
              WHERE  tsv @@ websearch_to_tsquery('english', %s)
              ORDER  BY ts_rank(tsv, websearch_to_tsquery('english', %s)) DESC
              LIMIT %s
            )
            SELECT c.cwe_id, c.section, c.section_rank, c.name, c.full_text,
                   c.embedding_h <=> %s::halfvec AS distance
            FROM   cwe_chunks c
            JOIN   txt USING (id)
            ORDER  BY distance
            LIMIT %s;
            """

            cur.execute(sql, (
                query_text, query_text, fts_limit,
                query_embedding, limit_chunks
            ))
            rows = cur.fetchall()

        results: List[Dict] = []
        for r in rows:
            results.append({
                "cwe_id": r[0],
                "section": r[1],
                "section_rank": r[2],
                "name": r[3],
                "full_text": r[4],
                "distance": float(r[5]),
                "score": 1.0 - float(r[5]),  # Convert distance to similarity score
            })

        return results

    # ---------- Hybrid query over chunks ----------
    def query_hybrid(
        self,
        query_text: str,
        query_embedding: np.ndarray,
        k_vec: int = 100,
        limit_chunks: int = 20,
        w_vec: float = 0.6,  # unused in RRF fusion (kept for API compat)
        w_fts: float = 0.25,  # unused in RRF fusion (kept for API compat)
        w_alias: float = 0.10,  # unused in RRF fusion (kept for API compat)
        section_intent_boost: Optional[str] = None,  # e.g., 'Mitigations'
        section_boost_value: float = 0.15,
        fts_k: Optional[int] = None,
        k_rrf: int = 60,
        alias_k: Optional[int] = None,
    ) -> List[Dict]:
        """
        Returns top chunk rows scored by hybrid. Caller can group by cwe_id to present.
        section_intent_boost: if provided, applies a bonus to that section.
        """
        if isinstance(query_embedding, np.ndarray):
            query_embedding = query_embedding.tolist()

        section = (section_intent_boost or "").strip()
        vec_k = int(k_vec)
        fts_k_eff = int(fts_k if fts_k is not None else vec_k)

        # Reciprocal Rank Fusion (RRF) over vector KNN and FTS candidate pools.
        # Keeps both pools via UNION ALL and aggregates per chunk id.
        sql = """
        WITH
          vec_search AS MATERIALIZED (
            SELECT id,
                   embedding_h <=> l2_normalize(%s::vector)::halfvec AS dist,
                   ROW_NUMBER() OVER (ORDER BY embedding_h <=> l2_normalize(%s::vector)::halfvec) AS rnk_v
            FROM   cwe_chunks
            ORDER  BY dist
            LIMIT  %s
          ),
          fts_search AS MATERIALIZED (
            SELECT id,
                   ROW_NUMBER() OVER (
                     ORDER BY ts_rank(tsv, websearch_to_tsquery('english', %s)) DESC
                   ) AS rnk_f
            FROM   cwe_chunks
            WHERE  tsv @@ websearch_to_tsquery('english', %s)
            LIMIT  %s
          ),
          alias_search AS MATERIALIZED (
            SELECT id,
                   ROW_NUMBER() OVER (
                     ORDER BY GREATEST(
                       similarity(lower(alternate_terms_text), lower(%s)),
                       similarity(lower(regexp_replace(alternate_terms_text, '[^a-z0-9 ]', ' ', 'gi')), lower(%s))
                     ) DESC
                   ) AS rnk_a
            FROM   cwe_chunks
            WHERE  alternate_terms_text <> ''
            ORDER  BY GREATEST(
                       similarity(lower(alternate_terms_text), lower(%s)),
                       similarity(lower(regexp_replace(alternate_terms_text, '[^a-z0-9 ]', ' ', 'gi')), lower(%s))
                     ) DESC
            LIMIT  %s
          ),
        unioned AS (
          SELECT id, rnk_v AS rnk FROM vec_search
          UNION ALL
          SELECT id, rnk_f AS rnk FROM fts_search
          UNION ALL
          SELECT id, rnk_a AS rnk FROM alias_search
        ),
        rrf AS (
          SELECT id,
                 SUM(1.0 / (%s + rnk)) AS rrf_score
          FROM   unioned
          GROUP  BY id
        )
        SELECT c.id,
               c.cwe_id,
               c.section,
               c.section_rank,
               c.name,
               c.full_text,
               (rrf.rrf_score +
                CASE WHEN %s <> '' AND c.section = %s THEN %s ELSE 0 END
               ) AS score,
               v.rnk_v,
               f.rnk_f,
               a.rnk_a
        FROM   rrf
        JOIN   cwe_chunks c USING (id)
        LEFT JOIN vec_search v USING (id)
        LEFT JOIN fts_search f USING (id)
        LEFT JOIN alias_search a USING (id)
        ORDER  BY score DESC NULLS LAST, c.section_rank ASC
        LIMIT  %s;
        """
        alias_k_eff = int(alias_k if alias_k is not None else vec_k)
        params = (
            query_embedding,
            query_embedding,
            vec_k,
            query_text,
            query_text,
            fts_k_eff,
            query_text,
            query_text,
            query_text,
            query_text,
            alias_k_eff,
            k_rrf,
            section,
            section,
            section_boost_value,
            limit_chunks,
        )
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

        results: List[Dict] = []
        for r in rows:
            chunk_id, cwe_id, section_name, section_rank, name, full_text, score, rnk_v, rnk_f, rnk_a = r
            # Approximate per-source contributions using RRF components
            vec_contrib = (1.0 / (k_rrf + rnk_v)) if rnk_v is not None else 0.0
            fts_contrib = (1.0 / (k_rrf + rnk_f)) if rnk_f is not None else 0.0
            alias_contrib = (1.0 / (k_rrf + rnk_a)) if rnk_a is not None else 0.0

            results.append({
                "chunk_id": str(chunk_id),
                "metadata": {
                    "cwe_id": cwe_id,
                    "section": section_name,
                    "section_rank": section_rank,
                    "name": name,
                },
                "document": full_text,
                "scores": {
                    "vec": float(vec_contrib),
                    "fts": float(fts_contrib),
                    "alias": float(alias_contrib),
                    "hybrid": float(score),
                },
            })
        return results

    def get_collection_stats(self) -> Dict[str, Any]:
        with self.conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM cwe_chunks;")  # type: ignore[arg-type]
            result = cur.fetchone()
            (cnt,) = result if result else (0,)
        return {"collection_name": "cwe_chunks", "count": cnt}
