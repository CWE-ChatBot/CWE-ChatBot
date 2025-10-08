# apps/cwe_ingestion/pg_vector_store.py
import logging
import os
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

try:
    import psycopg
except ImportError as e:
    raise ImportError(
        "psycopg (v3) is required for Postgres vector store. Install with: pip install psycopg[binary]"
    ) from e

logger = logging.getLogger(__name__)


DDL_SINGLE = """
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS cwe_embeddings (
  id                  TEXT PRIMARY KEY,           -- 'CWE-79'
  cwe_id              TEXT NOT NULL,              -- duplicate of id for clarity
  name                TEXT NOT NULL,
  abstraction         TEXT,
  status              TEXT,
  full_text           TEXT NOT NULL,
  alternate_terms_text TEXT DEFAULT '',
  tsv                 tsvector GENERATED ALWAYS AS (
    setweight(to_tsvector('english', COALESCE(alternate_terms_text,'')), 'A') ||
    setweight(to_tsvector('english', COALESCE(name,'')), 'B') ||
    setweight(to_tsvector('english', COALESCE(full_text,'')), 'C')
  ) STORED,
  embedding           vector(%(dims)s) NOT NULL,
  created_at          TIMESTAMPTZ DEFAULT now(),
  updated_at          TIMESTAMPTZ DEFAULT now()
);

-- Indexes
CREATE INDEX IF NOT EXISTS cwe_fulltext_gin ON cwe_embeddings USING GIN (tsv);
-- Choose ONE ANN index type your pgvector supports:
DO $$
BEGIN
  -- Try HNSW (pgvector >= 0.7.0, PG16+). If not available, fall back to IVFFlat.
  BEGIN
    EXECUTE 'CREATE INDEX cwe_embed_hnsw_cos ON cwe_embeddings USING hnsw (embedding vector_cosine_ops)';
  EXCEPTION WHEN others THEN
    PERFORM 1;
  END;
  IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'cwe_embed_hnsw_cos') THEN
    BEGIN
      EXECUTE 'CREATE INDEX IF NOT EXISTS cwe_embed_ivf_cos ON cwe_embeddings USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)';
    EXCEPTION WHEN others THEN
      PERFORM 1;
    END;
  END IF;
END $$;
"""


class PostgresVectorStore:
    """
    Postgres + pgvector store with hybrid retrieval (vector + FTS + alias boost).
    Table: cwe_embeddings (single row per CWE).
    """

    def __init__(
        self,
        table: str = "cwe_embeddings",
        dims: int = 3072,
        database_url: Optional[str] = None,
    ):
        self.table = table
        self.dims = int(dims)
        self.database_url = database_url or os.environ.get("DATABASE_URL")
        if not self.database_url:
            raise ValueError("DATABASE_URL is required for PostgresVectorStore")

        # Configure connection for Google Cloud SQL IAM if needed
        conn_params = self._prepare_connection_params(self.database_url)
        self.conn = psycopg.connect(**conn_params)
        self.conn.execute("SET statement_timeout = '30s';")
        self.conn.execute(
            "SET ivfflat.probes = 10;"
        )  # Improve IVFFlat recall (harmless if HNSW is used)
        self.conn.execute(
            "SET hnsw.ef_search = 80;"
        )  # Improve HNSW recall (harmless if IVFFlat is used)
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
        netloc = parsed.netloc or ""
        has_at_symbol = "@" in netloc
        has_colon_after_at = "@" in netloc and ":" in netloc.split("@", 1)[-1]

        is_gcp_iam = has_at_symbol and has_colon_after_at and parsed.password is None

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
        logger.info("Ensuring Postgres schema exists for hybrid retrieval...")

        # Atomic DDL block for robust schema management
        ivf_lists = self._recommended_ivf_lists(self.table)
        atomic_ddl = f"""
        DO $$
        BEGIN
            CREATE EXTENSION IF NOT EXISTS vector;
            CREATE EXTENSION IF NOT EXISTS pg_trgm;
            -- Optional: unaccent for more robust full-text search (removes diacritics)
            CREATE EXTENSION IF NOT EXISTS unaccent;

            CREATE TABLE IF NOT EXISTS {self.table} (
                id TEXT PRIMARY KEY,
                cwe_id TEXT NOT NULL,
                name TEXT NOT NULL,
                abstraction TEXT,
                status TEXT,
                full_text TEXT NOT NULL,
                alternate_terms_text TEXT DEFAULT '',
                tsv tsvector GENERATED ALWAYS AS (
                    setweight(to_tsvector('english', COALESCE(alternate_terms_text,'')), 'A') ||
                    setweight(to_tsvector('english', COALESCE(name,'')), 'B') ||
                    setweight(to_tsvector('english', COALESCE(full_text,'')), 'C')
                ) STORED,
                embedding vector({self.dims}) NOT NULL,
                created_at TIMESTAMPTZ DEFAULT now(),
                updated_at TIMESTAMPTZ DEFAULT now()
            );

            CREATE INDEX IF NOT EXISTS cwe_fulltext_gin ON {self.table} USING GIN (tsv);
            CREATE INDEX IF NOT EXISTS cwe_embeddings_cwe_id_idx ON {self.table}(cwe_id);

            -- Try HNSW first; if unavailable, fall back to IVFFlat with calculated lists
            IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'cwe_embed_hnsw_cos' AND tablename = '{self.table}') THEN
                BEGIN
                    EXECUTE 'CREATE INDEX cwe_embed_hnsw_cos ON {self.table} USING hnsw (embedding vector_cosine_ops) WITH (m = 24, ef_construction = 200)';
                    RAISE NOTICE 'Created HNSW vector index on {self.table}';
                EXCEPTION WHEN OTHERS THEN
                    RAISE NOTICE 'HNSW not available, falling back to IVFFlat for {self.table}';
                    EXECUTE 'CREATE INDEX IF NOT EXISTS cwe_embed_ivf_cos ON {self.table} USING ivfflat (embedding vector_cosine_ops) WITH (lists = {ivf_lists})';
                END;
            END IF;

            -- Refresh statistics after schema setup
            PERFORM pg_catalog.pg_stat_reset();
            EXECUTE 'ANALYZE {self.table}';
        END $$;
        """

        with self.conn.cursor() as cur:
            cur.execute(atomic_ddl)  # type: ignore[arg-type]
        self.conn.commit()
        logger.info(f"Schema setup completed for table: {self.table}")

    def _recommended_ivf_lists(self, table: str) -> int:
        """Calculate IVF lists from current table count (sqrt(N), clamped)."""
        from psycopg import sql

        with self.conn.cursor() as cur:
            cur.execute(
                sql.SQL("SELECT GREATEST(1, COUNT(*)) FROM {}").format(
                    sql.Identifier(table)
                )
            )
            result = cur.fetchone()
            (n,) = result if result else (1,)
        import math

        return max(64, min(8192, int(math.sqrt(n))))

    # ---- Write ----
    def store_batch(self, docs: List[Dict[str, Any]]) -> int:
        """
        Docs must include: id ('CWE-79'), name, abstraction, status,
        full_text, alternate_terms_text, embedding (np.ndarray or list)
        """
        if not docs:
            return 0
        rows: Sequence[tuple] = []
        for d in docs:
            emb = d["embedding"]
            if isinstance(emb, np.ndarray):
                emb = emb.tolist()
            rows.append(
                (
                    d["id"],
                    d.get("cwe_id", d["id"]),
                    d["name"],
                    d.get("abstraction", ""),
                    d.get("status", ""),
                    d["full_text"],
                    d.get("alternate_terms_text", "") or "",
                    emb,
                )
            )
        sql = f"""
        INSERT INTO {self.table}
            (id, cwe_id, name, abstraction, status, full_text, alternate_terms_text, embedding)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (id) DO UPDATE SET
            name = EXCLUDED.name,
            abstraction = EXCLUDED.abstraction,
            status = EXCLUDED.status,
            full_text = EXCLUDED.full_text,
            alternate_terms_text = EXCLUDED.alternate_terms_text,
            embedding = EXCLUDED.embedding,
            updated_at = now();
        """
        with self.conn.transaction():
            with self.conn.cursor() as cur:
                cur.executemany(sql, rows)  # type: ignore[arg-type]

        # Refresh statistics after significant batch inserts for optimal query planning
        if len(rows) >= 10:  # Only for meaningful batch sizes
            from psycopg import sql

            with self.conn.cursor() as cur:
                cur.execute(sql.SQL("ANALYZE {}").format(sql.Identifier(self.table)))
            self.conn.commit()
            logger.debug(
                f"Refreshed table statistics after inserting {len(rows)} embeddings"
            )

        return len(rows)

    # ---- Read: vector-only (compat) ----
    def query_similar(
        self, query_embedding: np.ndarray, n_results: int = 5
    ) -> List[Dict]:
        if isinstance(query_embedding, np.ndarray):
            query_embedding = query_embedding.tolist()
        sql = f"""
        SELECT id, cwe_id, name, abstraction, status, full_text,
               embedding <=> %s::vector AS cos_dist
          FROM {self.table}
      ORDER BY embedding <=> %s::vector
         LIMIT %s;
        """
        with self.conn.cursor() as cur:
            cur.execute(sql, (query_embedding, query_embedding, n_results))  # type: ignore[arg-type]
            rows = cur.fetchall()
        out: List[Dict] = []
        for r in rows:
            out.append(
                {
                    "metadata": {
                        "cwe_id": r[1],
                        "name": r[2],
                        "abstraction": r[3],
                        "status": r[4],
                    },
                    "document": r[5],
                    "distance": float(r[6]),
                }
            )
        return out

    # ---- Read: hybrid retrieval ----
    def query_hybrid(
        self,
        query_text: str,
        query_embedding: np.ndarray,
        k_vec: int = 50,
        limit: int = 10,
        w_vec: float = 0.65,
        w_fts: float = 0.25,
        w_alias: float = 0.10,
    ) -> List[Dict]:
        if isinstance(query_embedding, np.ndarray):
            query_embedding = query_embedding.tolist()

        # Hybrid CTE: vector KNN + FTS + trigram alias boost (normalized)
        sql = f"""
        WITH vec AS (
          SELECT id, cwe_id, name, abstraction, status, full_text, alternate_terms_text,
                 embedding <=> %s::vector AS cos_dist
            FROM {self.table}
        ORDER BY embedding <=> %s::vector
           LIMIT %s
        ),
        fts AS (
          SELECT id, ts_rank(tsv, websearch_to_tsquery('english', %s)) AS fts_rank
            FROM {self.table}
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
                 -- Normalize distances/ranks to [0,1] with robust max scaling
                 COALESCE(1 - (cos_dist / NULLIF((SELECT MAX(cos_dist) FROM joined), 0)), 0) AS vec_sim_norm,
                 COALESCE(fts_rank / NULLIF(GREATEST((SELECT MAX(fts_rank) FROM joined), 1e-9), 0), 0) AS fts_norm,
                 COALESCE(alias_sim / NULLIF((SELECT MAX(alias_sim) FROM joined), 0), 0) AS alias_norm
            FROM joined
        )
        SELECT id, cwe_id, name, abstraction, status, full_text,
               vec_sim_norm, fts_norm, alias_norm,
               (%s * COALESCE(vec_sim_norm,0)) +
               (%s * COALESCE(fts_norm,0)) +
               (%s * COALESCE(alias_norm,0)) AS hybrid_score
          FROM agg
      ORDER BY hybrid_score DESC NULLS LAST
         LIMIT %s;
        """
        params = (
            query_embedding,
            query_embedding,
            k_vec,
            query_text,
            query_text,
            query_text,
            query_text,
            w_vec,
            w_fts,
            w_alias,
            limit,
        )
        with self.conn.cursor() as cur:
            cur.execute(sql, params)  # type: ignore[arg-type]
            rows = cur.fetchall()

        results: List[Dict] = []
        for r in rows:
            results.append(
                {
                    "metadata": {
                        "cwe_id": r[1],
                        "name": r[2],
                        "abstraction": r[3],
                        "status": r[4],
                    },
                    "document": r[5],
                    "scores": {
                        "vec": float(r[6]) if r[6] is not None else 0.0,
                        "fts": float(r[7]) if r[7] is not None else 0.0,
                        "alias": float(r[8]) if r[8] is not None else 0.0,
                        "hybrid": float(r[9]),
                    },
                }
            )
        return results

    def get_collection_stats(self) -> Dict[str, Any]:
        from psycopg import sql

        with self.conn.cursor() as cur:
            cur.execute(
                sql.SQL("SELECT COUNT(*) FROM {}").format(sql.Identifier(self.table))
            )
            result = cur.fetchone()
            (cnt,) = result if result else (0,)
        return {"collection_name": self.table, "count": cnt}
