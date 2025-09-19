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
            return {
                "conninfo": database_url,
                "sslmode": "require",  # Google Cloud SQL requires SSL
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
            cur.execute(f"""
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
                    embedding           vector({self.dims}) NOT NULL,
                    created_at          TIMESTAMPTZ DEFAULT now()
                );
            """)

            # Create indexes
            cur.execute("CREATE INDEX IF NOT EXISTS cwe_chunks_cwe_id_idx ON cwe_chunks(cwe_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS cwe_chunks_section_idx ON cwe_chunks(section, section_rank);")
            cur.execute("CREATE INDEX IF NOT EXISTS cwe_chunks_tsv_gin ON cwe_chunks USING GIN (tsv);")
            cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS cwe_chunks_unique ON cwe_chunks (cwe_id, section, section_rank);")

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
                        cur.execute(f"CREATE INDEX IF NOT EXISTS cwe_chunks_ivf_cos ON cwe_chunks USING ivfflat (embedding vector_cosine_ops) WITH (lists = {ivf_lists});")
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

    # ---------- Hybrid query over chunks ----------
    def query_hybrid(
        self,
        query_text: str,
        query_embedding: np.ndarray,
        k_vec: int = 100,
        limit_chunks: int = 20,
        w_vec: float = 0.6,
        w_fts: float = 0.25,
        w_alias: float = 0.10,
        section_intent_boost: Optional[str] = None,  # e.g., 'Mitigations'
        section_boost_value: float = 0.15,
    ) -> List[Dict]:
        """
        Returns top chunk rows scored by hybrid. Caller can group by cwe_id to present.
        section_intent_boost: if provided, applies a bonus to that section.
        """
        if isinstance(query_embedding, np.ndarray):
            query_embedding = query_embedding.tolist()

        section = (section_intent_boost or "").strip()
        sql = f"""
        WITH vec AS (
          SELECT id, cwe_id, section, section_rank, name, full_text, alternate_terms_text,
                 embedding <=> %s::vector AS cos_dist
            FROM cwe_chunks
        ORDER BY embedding <=> %s::vector
           LIMIT %s
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
        scored AS (
          SELECT *,
                 COALESCE(1 - (cos_dist / NULLIF((SELECT MAX(cos_dist) FROM joined), 0)), 0) AS vec_sim_norm,
                 COALESCE(fts_rank / NULLIF((SELECT MAX(fts_rank) FROM joined), 0), 0) AS fts_norm,
                 COALESCE(alias_sim / NULLIF((SELECT MAX(alias_sim) FROM joined), 0), 0) AS alias_norm,
                 CASE
                   WHEN %s <> '' AND section = %s THEN %s
                   ELSE 0
                 END AS section_boost
            FROM joined
        )
        SELECT id, cwe_id, section, section_rank, name, full_text,
               vec_sim_norm, fts_norm, alias_norm, section_boost,
               (%s * COALESCE(vec_sim_norm,0)) +
               (%s * COALESCE(fts_norm,0)) +
               (%s * COALESCE(alias_norm,0)) +
               section_boost
               AS hybrid_score
          FROM scored
      ORDER BY hybrid_score DESC NULLS LAST, section_rank ASC
         LIMIT %s;
        """
        params = (
            query_embedding, query_embedding, k_vec,
            query_text, query_text,
            query_text, query_text,
            section, section, section_boost_value,
            w_vec, w_fts, w_alias,
            limit_chunks
        )
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

        results: List[Dict] = []
        for r in rows:
            results.append({
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
                    "section_boost": float(r[9]) if r[9] is not None else 0.0,
                    "hybrid": float(r[10]),
                }
            })
        return results

    def get_collection_stats(self) -> Dict[str, Any]:
        with self.conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM cwe_chunks;")  # type: ignore[arg-type]
            result = cur.fetchone()
            (cnt,) = result if result else (0,)
        return {"collection_name": "cwe_chunks", "count": cnt}
