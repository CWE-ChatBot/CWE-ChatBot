Awesome — here’s a **PostgreSQL-only** README you can drop in as `README.md`. It removes Chroma completely and documents the Postgres single-row + chunked stores, hybrid retrieval, alias boosts, docker quickstart, and worked examples.

---

# CWE Data Ingestion Pipeline (PostgreSQL + pgvector)

A secure, high-performance pipeline for ingesting MITRE CWE data into **PostgreSQL + pgvector** with **hybrid retrieval** (vector + full-text + alias boost). Supports **single-row** and **chunked** storage (recommended).

## Overview

This pipeline downloads the CWE XML from MITRE, parses and normalizes entries, generates embeddings (Gemini or local), and stores them in Postgres for **hybrid** search:

* **Vector** similarity via pgvector
* **Full-Text Search (FTS)** via `tsvector` + `websearch_to_tsquery`
* **Alias boost** for `Alternate_Terms` via FTS weighting + trigram similarity

## Features

### 🔒 Security-First

* **XXE protection** with `defusedxml`
* Masked API keys in logs/errors
* Strict error handling, validation & SSL verification

### 🚀 Embeddings

* **Gemini (`gemini-embedding-001`)** – 3072-D (recommended)
* **Local (Sentence Transformers)** – default 384-D (no external API)
* Batch embedding with deterministic fallback

### 🧠 Retrieval (Hybrid)

* **Vector ANN** (HNSW or IVFFlat)
* **FTS weights**: `Alternate_Terms` (A, highest) > `name` (B) > `full_text` (C)
* **Alias boost**: `pg_trgm` similarity on aliases string
* Optional **section intent** boost in chunked mode (e.g., “Mitigations”)

### 🧱 Storage Modes

* **Single-row** (`cwe_embeddings`): one row per CWE
* **Chunked** (`cwe_chunks`) (recommended): per-section rows (Title, Abstract, Extended, Mitigations, Examples, Related, Aliases)

---

## Architecture

```
┌───────────────┐   ┌───────────────┐   ┌─────────────────────┐
│ MITRE CWE XML │──▶│ XML Parser    │──▶│ Embedder            │
│ (download)    │   │ (defusedxml)  │   │ (Gemini / Local)    │
└───────────────┘   └───────────────┘   └───────────────┬─────┘
                                                        │
                                      ┌─────────────────▼─────────────────┐
                                      │ PostgreSQL + pgvector (Hybrid)    │
                                      │ • Vector ANN (HNSW / IVFFlat)     │
                                      │ • FTS (tsvector) + alias weights  │
                                      │ • Optional chunked sections       │
                                      └────────────────────────────────────┘
```

---

## Data Model

### Single-row table (simpler)

* One row per CWE entry.
* `alternate_terms_text` is kept separate and heavily weighted in FTS.

```sql
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS cwe_embeddings (
  id                   TEXT PRIMARY KEY,           -- 'CWE-79'
  cwe_id               TEXT NOT NULL,              -- same as id
  name                 TEXT NOT NULL,
  abstraction          TEXT,
  status               TEXT,
  full_text            TEXT NOT NULL,
  alternate_terms_text TEXT DEFAULT '',
  tsv                  tsvector GENERATED ALWAYS AS (
    setweight(to_tsvector('english', COALESCE(alternate_terms_text,'')), 'A') ||
    setweight(to_tsvector('english', COALESCE(name,'')), 'B') ||
    setweight(to_tsvector('english', COALESCE(full_text,'')), 'C')
  ) STORED,
  embedding            vector(3072) NOT NULL,      -- 384 if local embeddings
  created_at           timestamptz DEFAULT now(),
  updated_at           timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cwe_fulltext_gin ON cwe_embeddings USING GIN (tsv);
-- Prefer HNSW if available; otherwise IVFFlat:
-- CREATE INDEX cwe_embed_hnsw_cos ON cwe_embeddings USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS cwe_embed_ivf_cos ON cwe_embeddings
  USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
```

### Chunked table (recommended)

* Multiple rows per CWE (Title, Abstract, Extended, Mitigations, Examples, Related, Aliases).
* Better recall and snippet relevance; supports **section intent** boost.

```sql
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- for gen_random_uuid on some installs

CREATE TABLE IF NOT EXISTS cwe_chunks (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cwe_id               TEXT NOT NULL,             -- 'CWE-79'
  section              TEXT NOT NULL,             -- 'Title','Abstract','Extended','Mitigations','Examples','Related','Aliases'
  section_rank         INT  NOT NULL,             -- order for grouping
  name                 TEXT NOT NULL,
  alternate_terms_text TEXT DEFAULT '',
  full_text            TEXT NOT NULL,
  tsv                  tsvector GENERATED ALWAYS AS (
    setweight(to_tsvector('english', COALESCE(alternate_terms_text,'')), 'A') ||
    setweight(to_tsvector('english', COALESCE(name,'')), 'B') ||
    setweight(to_tsvector('english', COALESCE(full_text,'')), 'C')
  ) STORED,
  embedding            vector(3072) NOT NULL,     -- 384 if local embeddings
  created_at           timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cwe_chunks_cwe_id_idx  ON cwe_chunks(cwe_id);
CREATE INDEX IF NOT EXISTS cwe_chunks_section_idx ON cwe_chunks(section, section_rank);
CREATE INDEX IF NOT EXISTS cwe_chunks_tsv_gin     ON cwe_chunks USING GIN (tsv);
-- Prefer HNSW if available; otherwise IVFFlat:
-- CREATE INDEX cwe_chunks_hnsw_cos ON cwe_chunks USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS cwe_chunks_ivf_cos ON cwe_chunks
  USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
```

---

## Installation

```bash
# Install all dependencies via Poetry
poetry install

# Verify installation
poetry run python --version
poetry run python -c "import psycopg; print('✅ psycopg installed')"
```

**Dependencies Included**

### Required Dependencies
* `psycopg[binary]` - PostgreSQL database adapter with binary extensions
* `defusedxml` - Secure XML parsing (XXE protection)
* `pydantic` - Data validation and parsing models
* `click` - Command-line interface framework
* `numpy` - Numerical computing for embeddings
* `requests` - HTTP client for CWE XML downloads

### Optional Dependencies (Auto-installed)
* `sentence-transformers` - Local embedding models (no external API required)
* `google-generativeai` - Gemini API integration for production embeddings

### Development & Testing
* `pytest` - Testing framework (if in dev dependencies)
* All dependencies are managed via Poetry for consistent environments

**Note**: All dependencies are automatically installed with `poetry install`. No manual dependency installation required.

---

## Quickstart (Local Postgres via Docker)

### 🚀 Quick Setup

**1. Create docker-compose.yml** (provided in repo):

```yaml
version: "3.9"
services:
  pg:
    image: pgvector/pgvector:pg16
    environment:
      POSTGRES_PASSWORD: postgres
      POSTGRES_USER: postgres
      POSTGRES_DB: cwe
    ports: ["5432:5432"]
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
```

**2. Start Database & Set Environment**

```bash
# Start PostgreSQL with pgvector
docker compose up -d

# Set database connection
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"

# (Optional) Gemini embeddings
export GEMINI_API_KEY="your_google_ai_api_key"
```

**3. Test Database Connection**

```bash
# Verify PostgreSQL and pgvector are working
poetry run python test_db_connection.py
```

This test script validates:
- ✅ PostgreSQL connection
- ✅ pgvector extension functionality
- ✅ Vector similarity search
- ✅ Hybrid retrieval capabilities

**3b. Test Multi-Database Setup (Optional)**

For cost-optimized multi-database ingestion:

```bash
# Set up both database URLs
export LOCAL_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"
export PROD_DATABASE_URL="postgresql://username@project:region:instance/dbname"  # Google Cloud SQL IAM

# Ensure Google Cloud authentication for production database
gcloud auth application-default login

# Test multi-database configuration
poetry run python test_multi_db.py
```

This validates:
- ✅ Environment variable configuration
- ✅ Multiple database connections
- ✅ Embedding cost optimization setup
- ✅ CLI multi-database integration

**4. Ready to Ingest!**

```bash
# Ingest CWE data (chunked + local embeddings)
poetry run python cli.py ingest --chunked

# Test queries
poetry run python cli.py query -q "cross site scripting" --hybrid --chunked
```

### Alternative: Native PostgreSQL

If you prefer not to use Docker:

```bash
# Install PostgreSQL 16 + pgvector (Ubuntu/Debian)
sudo apt update
sudo apt install postgresql-16 postgresql-16-pgvector

# Create database
sudo -u postgres psql
CREATE DATABASE cwe;
CREATE USER postgres WITH PASSWORD 'postgres';
GRANT ALL PRIVILEGES ON DATABASE cwe TO postgres;
CREATE EXTENSION vector;
\q

# Set environment
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"
```

---

## Usage (CLI)

### 💰 Multi-Database Ingestion (Cost-Optimized)

**Generate embeddings once and distribute to multiple databases** - ideal for Gemini embeddings:

```bash
# Set up database URLs
export LOCAL_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"
export PROD_DATABASE_URL="postgresql://username@project:region:instance/dbname"  # Google Cloud SQL IAM

# Ensure Google Cloud authentication for production database
gcloud auth application-default login

# Ingest to both databases with embeddings generated once (Gemini)
poetry run python cli.py ingest-multi --embedder-type gemini

# Ingest to both databases with local embeddings
poetry run python cli.py ingest-multi --embedder-type local

# Target specific CWEs and control storage modes
poetry run python cli.py ingest-multi \
  --embedder-type gemini \
  -c CWE-79 -c CWE-89 \
  --local-chunked --prod-chunked

# Mix storage modes (local chunked, production single-row)
poetry run python cli.py ingest-multi \
  --embedder-type gemini \
  --local-chunked --prod-single
```

**Benefits:**
- 🔥 **50% cost reduction** for Gemini embeddings (generate once, store twice)
- ⚡ **Faster ingestion** - no duplicate embedding generation
- 🎯 **Flexible storage** - different modes per database
- 🔒 **Consistent data** - same embeddings across environments

### 📊 Single Database Ingestion

```bash
# Local embeddings (384-D), CHUNKED (recommended)
poetry run python cli.py ingest --chunked

# Gemini embeddings (3072-D), CHUNKED
poetry run python cli.py ingest --chunked --embedder-type gemini

# Single-row mode (not chunked)
poetry run python cli.py ingest --single --embedder-type gemini

# Target only specific CWEs
poetry run python cli.py ingest --chunked -c CWE-79 -c CWE-89 -c CWE-20
```

### Query (Hybrid Retrieval)

```bash
# Chunked hybrid (recommended)
poetry run python cli.py query -q "xss filter bypass" --hybrid --chunked

# With weights & mitigation boost
poetry run python cli.py query -q "how to prevent sql injection" \
  --hybrid --chunked --boost-section Mitigations \
  --w-vec 0.55 --w-fts 0.30 --w-alias 0.15

# Single-row hybrid
poetry run python cli.py query -q "path traversal" --hybrid --single
```

**Weights (defaults)**

* `w_vec = 0.60–0.65`
* `w_fts = 0.25–0.30`
* `w_alias = 0.10–0.15`

**Alias boost** activates when queries contain acronyms/aliases (e.g., “xss”, “sqli”).

---

## Hybrid Retrieval Details

We combine three signals (normalized 0–1):

```
hybrid = w_vec * vec_sim_norm
       + w_fts * fts_norm
       + w_alias * alias_norm
       + optional section_boost (chunked)
```

* **Vector**: cosine similarity candidate set (KNN) using pgvector.
* **FTS**: `tsv @@ websearch_to_tsquery('english', :q)` with weighted `tsvector`:

  * **A**: `alternate_terms_text` (aliases) → **most important**
  * **B**: `name`
  * **C**: `full_text`
* **Alias boost**: `pg_trgm` similarity against `alternate_terms_text` (helps fuzzy “xss/sqli/dir traversal” queries).
* **Section boost** (chunked): optional small bonus (e.g., **Mitigations** when query implies “prevent”, “mitigate”, “fix”).

---

## Worked Examples

> Assume chunked store + hybrid retrieval (`--chunked --hybrid`) with weights `w_vec=0.6`, `w_fts=0.25`, `w_alias=0.15`.

### 1) Alias-driven search

**Query:** `xss`

```bash
poetry run python cli.py query -q "xss" --hybrid --chunked --w-vec 0.55 --w-fts 0.30 --w-alias 0.15
```

**Why it works:**

* Alias appears in `alternate_terms_text` (**A** weight) → high FTS.
* `pg_trgm` similarity on aliases adds extra lift.
* Vector also matches to CWE-79.

**Abridged output:**

```
1. CWE-79: Cross-site Scripting (score=0.94)
   ▸ [Aliases] hybrid=0.94 vec=0.71 fts=0.82 alias=1.00
     XSS; Cross Site Scripting...
   ▸ [Abstract] hybrid=0.88 vec=0.80 fts=0.40 alias=0.50
     The software does not neutralize user input...
```

### 2) Mitigation intent

**Query:** `how to prevent sql injection`

```bash
poetry run python cli.py query -q "how to prevent sql injection" --hybrid --chunked --boost-section Mitigations
```

**Why it works:**

* Vector pulls CWE-89.
* FTS hits “sql injection”.
* **Mitigations** chunks get a +0.15 bonus → remediation rises to the top.

**Abridged output:**

```
1. CWE-89: SQL Injection (score=0.92)
   ▸ [Mitigations] hybrid=0.92 vec=0.76 fts=0.62 alias=0.20
     - Architecture/Design: Use prepared statements...
```

### 3) Exact ID

**Query:** `CWE-22`

```bash
poetry run python cli.py query -q "CWE-22" --hybrid --chunked
```

**Why it works:**

* Title chunk carries exact token → high FTS + good vector match.

**Abridged output:**

```
1. CWE-22: Path Traversal (score=0.97)
   ▸ [Title] hybrid=0.97 vec=0.84 fts=0.95 alias=0.10
```

### 4) Fuzzy jargon

**Query:** `os command exec vuln`

```bash
poetry run python cli.py query -q "os command exec vuln" --hybrid --chunked
```

**Why it works:**

* Vector → CWE-78
* FTS → “command”, “exec”
* Aliases (“command injection”, “shell injection”) boost score

**Abridged output:**

```
1. CWE-78: OS Command Injection (score=0.90)
   ▸ [Abstract] hybrid=0.90 vec=0.82 fts=0.46 alias=0.35
   ▸ [Aliases] hybrid=0.87 vec=0.60 fts=0.40 alias=1.00
```

---

## Programmatic Usage

### Single Database Pipeline

```python
from pipeline import CWEIngestionPipeline

# Single database + chunked storage
pipe = CWEIngestionPipeline(embedder_type="gemini", use_chunked=True)

# Ingest to single database
ok = pipe.run()

# Hybrid query (chunked)
query = "sanitize untrusted input xss"
qemb = pipe.embedder.embed_text(query)
results = pipe.vector_store.query_hybrid(
    query_text=query,
    query_embedding=qemb,
    k_vec=100,                 # vector candidate pool
    limit_chunks=20,           # top chunks to return
    w_vec=0.6, w_fts=0.25, w_alias=0.15,
    section_intent_boost="Mitigations",  # optional
    section_boost_value=0.15
)
# Group by cwe_id and select best 1–2 chunks per CWE for output/snippets.
```

### Multi-Database Pipeline (Cost-Optimized)

```python
from multi_db_pipeline import MultiDatabaseCWEPipeline, DatabaseTarget, create_database_targets_from_env

# Option 1: Use environment variables
targets = create_database_targets_from_env()

# Option 2: Manual configuration
targets = [
    DatabaseTarget(
        name="local",
        database_url="postgresql://postgres:postgres@localhost:5432/cwe",
        use_chunked=True,
        description="Local development database"
    ),
    DatabaseTarget(
        name="production",
        database_url="postgresql://username@project:region:instance/dbname",  # Google Cloud SQL IAM
        use_chunked=True,
        description="Production database (Google Cloud SQL + IAM)"
    )
]

# Create multi-database pipeline
pipeline = MultiDatabaseCWEPipeline(
    database_targets=targets,
    embedder_type="gemini",      # Cost-optimized: embeddings generated once
    target_cwes=["79", "89"]     # Optional: specific CWEs only
)

# Run ingestion (generates embeddings once, stores in all targets)
success = pipeline.run()

if success:
    print("✅ Embeddings generated once and distributed to all databases!")
    print("💰 Cost savings: ~50% reduction for Gemini embeddings")
```

### Google Cloud SQL IAM Helpers

```python
from multi_db_pipeline import create_google_cloud_sql_url

# Generate Google Cloud SQL IAM connection URL
url = create_google_cloud_sql_url(
    project_id="myproject",
    region="us-central1",
    instance_name="cwe-instance",
    database_name="cwe",
    username="cwe-service"
)
print(f"Connection URL: {url}")
# Output: postgresql://cwe-service@myproject:us-central1:cwe-instance/cwe
```

---

## Environment

### Single Database Setup

```bash
# Local development (Docker)
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"

# Optional: Gemini embeddings
export GEMINI_API_KEY="AIza..."
```

### Multi-Database Setup (Cost-Optimized)

```bash
# Local database (Docker)
export LOCAL_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"

# Production database (Google Cloud SQL with IAM - recommended)
export PROD_DATABASE_URL="postgresql://username@project:region:instance/dbname"

# Ensure Google Cloud authentication for production
gcloud auth application-default login
# OR set service account credentials
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"

# Optional: Traditional production database with password
export PROD_DATABASE_URL="postgresql://user:pass@prod-host:5432/cwe_prod"

# Optional: Gemini embeddings (recommended for production)
export GEMINI_API_KEY="AIza..."
```

### Google Cloud SQL IAM Setup

Use the helper script to generate correct connection URLs:

```bash
# Generate Google Cloud SQL IAM connection URL
poetry run python gcp_db_helper.py create-url \
  --project-id myproject \
  --region us-central1 \
  --instance cwe-instance \
  --username cwe-service \
  --database cwe

# Test IAM authentication
poetry run python gcp_db_helper.py test-iam-auth

# Check authentication status
poetry run python gcp_db_helper.py check-auth
```

---

## Testing

### 🧪 Database Connection Test

**Before running ingestion or queries**, verify your setup:

```bash
# 1. Start PostgreSQL (if not already running)
docker compose up -d

# 2. Set environment variable
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"

# 3. Run connection test (provided script)
poetry run python test_db_connection.py
```

**Expected output:**
```
🧪 PostgreSQL + pgvector Database Test
==================================================
🔍 Testing PostgreSQL connection...
✅ PostgreSQL connection successful!
📊 Database stats: {'collection_name': 'cwe_embeddings', 'count': 0}

🔍 Testing pgvector extension...
✅ pgvector test successful! Stored 1 test documents.
✅ Vector similarity search working!

🔍 Testing hybrid retrieval...
✅ Hybrid retrieval successful! Found 1 results.

🎉 All database tests passed! Ready for CWE ingestion.
```

### 🔬 Unit Tests

```bash
# Run all tests (requires DATABASE_URL)
poetry run pytest

# Run specific test suite
poetry run pytest tests/unit/
poetry run pytest tests/integration/
```

**Example unit test** (chunk store roundtrip):

```python
# tests/unit/test_pg_chunk_store.py
import os, numpy as np, pytest
@pytest.mark.skipif("DATABASE_URL" not in os.environ, reason="Postgres required")
def test_postgres_chunk_store_roundtrip():
    from apps.cwe_ingestion.pg_chunk_store import PostgresChunkStore
    store = PostgresChunkStore(dims=384)
    emb = np.random.rand(384).astype(np.float32)
    n = store.store_batch([{
        "cwe_id":"CWE-79","section":"Title","section_rank":0,"name":"Cross-site Scripting",
        "alternate_terms_text":"XSS; Cross Site Scripting","full_text":"CWE-79: Cross-site Scripting","embedding":emb
    }])
    assert n == 1
    res = store.query_similar(emb, 1)
    assert res and res[0]["metadata"]["cwe_id"] == "CWE-79"
```

---

## Troubleshooting

### 🔧 Database Setup Issues

* **`DATABASE_URL` missing** → set it (local Docker example above)
* **Connection test fails** → check:
  ```bash
  # Verify PostgreSQL is running
  docker compose ps
  docker compose logs pg

  # Test direct connection
  docker compose exec pg psql -U postgres -d cwe -c "SELECT version();"

  # Check pgvector extension
  docker compose exec pg psql -U postgres -d cwe -c "SELECT * FROM pg_extension WHERE extname='vector';"
  ```

* **`psycopg` import errors** → ensure dependency installed:
  ```bash
  poetry add psycopg[binary]
  ```

* **Docker not available** → use native PostgreSQL installation (see Alternative setup above)

### 🔐 Google Cloud SQL IAM Authentication Issues

* **Test IAM authentication**:
  ```bash
  # Test specific database URL
  poetry run python gcp_db_helper.py test-iam-auth

  # Check authentication status
  poetry run python gcp_db_helper.py check-auth
  ```

* **Common IAM Issues**:

  1. **Authentication not configured**:
     ```bash
     gcloud auth application-default login
     ```

  2. **Service account missing permissions**:
     - Ensure service account has `Cloud SQL Client` role
     - Grant `cloudsql.instances.connect` permission

  3. **Wrong URL format**:
     ```bash
     # ✅ Correct: No password for IAM
     postgresql://username@project:region:instance/dbname

     # ❌ Incorrect: Has password
     postgresql://username:password@project:region:instance/dbname
     ```

  4. **Cloud SQL instance not configured for IAM**:
     - Enable IAM authentication in Cloud SQL console
     - Create IAM database user (not traditional user)

* **Multi-database configuration issues**:
  ```bash
  # Test multi-database setup
  poetry run python test_multi_db.py

  # Create Google Cloud SQL URL
  poetry run python gcp_db_helper.py create-url \
    -p myproject -r us-central1 -i cwe-instance -u cwe-service
  ```

### 🚀 Performance & Query Issues

* **`gemini-embedding-001` errors** → check `GEMINI_API_KEY` and network egress; fall back to local model with `--embedder-type local`
* **Slow queries**:
  * Ensure ANN index exists (HNSW preferred; else IVFFlat with appropriate `lists`)
  * Use reasonable vector K (e.g., `k_vec=50–150`) and `limit_chunks` (10–30)
  * `VACUUM ANALYZE` after big ingests
* **FTS no hits**:
  * Confirm `tsv` generated column and GIN index exist
  * Use `websearch_to_tsquery` for natural-language style queries

### 🛠️ Development Issues

* **Import errors when running files directly** → use `poetry run python -m module_name` or run from parent directory
* **Test database pollution** → reset with:
  ```bash
  docker compose down -v  # Remove volumes
  docker compose up -d    # Fresh start
  ```

---

## 📁 File Structure

This codebase contains the following key files:

### 🔄 Core Pipeline Components
- **`pipeline.py`** - Single database CWE ingestion pipeline
- **`multi_db_pipeline.py`** - Multi-database pipeline with cost-optimized embedding generation
- **`cli.py`** - Command-line interface with `ingest`, `ingest-multi`, and `query` commands

### 🗄️ Database Integration
- **`pg_vector_store.py`** - PostgreSQL + pgvector single-row storage with hybrid retrieval
- **`pg_chunk_store.py`** - PostgreSQL + pgvector chunked storage with hybrid retrieval
- Both stores support Google Cloud SQL IAM authentication

### 🔧 Data Processing
- **`downloader.py`** - MITRE CWE XML download and extraction
- **`parser.py`** - Secure XML parsing with Pydantic models
- **`embedder.py`** - Local (Sentence Transformers) and Gemini embedding generation
- **`models.py`** - Pydantic models with embedding optimization techniques

### 🧪 Testing & Utilities
- **`test_db_connection.py`** - Single database connection and functionality testing
- **`test_multi_db.py`** - Multi-database configuration and connection testing
- **`gcp_db_helper.py`** - Google Cloud SQL IAM utilities (URL generation, auth testing)

### 📚 Documentation
- **`README.md`** - This comprehensive documentation
- **`MULTI_DATABASE_SETUP.md`** - Detailed multi-database setup guide
- **`docker-compose.yml`** - Local PostgreSQL + pgvector setup

### 🎯 Key Features Implemented
- ✅ **Cost-optimized multi-database ingestion** (50% embedding cost reduction)
- ✅ **Google Cloud SQL IAM authentication** (passwordless, secure connections)
- ✅ **Hybrid retrieval** (vector + full-text search + alias boost)
- ✅ **Chunked and single-row storage modes** (flexible deployment options)
- ✅ **Comprehensive testing** (connection validation, IAM authentication)
- ✅ **Security-first design** (XXE protection, masked logging, SSL enforcement)

---

## Security Notes

* `defusedxml` prevents XXE.
* Never log raw API keys; masked logging is already enforced.
* Use a secrets manager for prod (`DATABASE_URL`, Gemini keys).
* Consider Cloud SQL Auth Proxy for managed Postgres.

---

## Contributing

1. TDD (write tests first).
2. Keep security-first principles.
3. Maintain backward compatibility across embedder choices (Gemini/local).
4. Update README when changing retrieval/ranking.
5. Test chunked and single-row paths.

---

## License

This project is part of the CWE ChatBot BMad implementation, for **defensive security** use only.

---

## 💡 Best Practices & Tips

### 🎯 Deployment Strategy

**For Development:**
```bash
# Start with local testing
docker compose up -d
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"
poetry run python test_db_connection.py
poetry run python cli.py ingest --chunked --embedder-type local
```

**For Production:**
```bash
# Use multi-database with Google Cloud SQL IAM
export LOCAL_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"
export PROD_DATABASE_URL="postgresql://username@project:region:instance/dbname"
gcloud auth application-default login
poetry run python cli.py ingest-multi --embedder-type gemini  # 50% cost savings!
```

### ⚙️ Query Tuning

Start with **chunked + hybrid** and tune based on query type:

* **General queries**: `w_vec=0.65, w_fts=0.25, w_alias=0.10`
* **Short alias queries** ("xss", "sqli"): bump `w_alias` → `0.15–0.20`
* **Remediation queries**: `--boost-section Mitigations` and/or `w_fts=0.30`
* **Exact CWE lookups**: Vector similarity works well with default weights

### 💰 Cost Optimization

1. **Always use `ingest-multi`** when you have multiple databases
2. **Use Gemini embeddings** for production quality with cost optimization
3. **Test with local embeddings** first to validate your setup
4. **Monitor embedding API usage** - multi-database can reduce costs by 50%

### 🔒 Security Recommendations

1. **Use Google Cloud SQL IAM** for production (no passwords in URLs)
2. **Set up proper service account roles** (`Cloud SQL Client`)
3. **Use environment variables** for all credentials
4. **Enable SSL** for all database connections (automatic with Google Cloud SQL)
5. **Rotate service account keys** regularly if using key files
