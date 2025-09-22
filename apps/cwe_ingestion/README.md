Of course, here is the updated `README.md` with the information about the Cloud SQL Proxy.

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

  * **Gemini (`gemini-embedding-001`)** – 3072-D (recommended for production)
      * **Smart batch processing**: Sequential for small batches, parallel for large batches
      * **Intelligent rate limiting**: Conditional delays, exponential backoff on failures
      * **High throughput**: Thread pool parallelization for production workloads
  * **Local Mock Embedder** – 384-D deterministic fallback (no external dependencies)
  * **Optional Sentence Transformers** – 384-D if library is available (development only)

### 🧠 Retrieval (Hybrid)

  * **Vector ANN** (HNSW or IVFFlat)
  * **FTS weights**: `Alternate_Terms` (A, highest) \> `name` (B) \> `full_text` (C)
  * **Alias boost**: `pg_trgm` similarity on aliases string
  * Optional **section intent** boost in chunked mode (e.g., “Mitigations”)

### 🧱 Storage Modes

  * **Single-row** (`cwe_embeddings`): one row per CWE
  * **Chunked** (`cwe_chunks`) (recommended): per-section rows (Title, Abstract, Extended, Mitigations, Examples, Related, Aliases)
      * **Safe re-ingestion**: Upserts prevent duplicates, keep data fresh

-----

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
                                      └───────────────────────────────────┘

```

# Network Architecture Diagram

```mermaid
  graph TD
    subgraph "LocalEnvironment"

        App[👩‍💻 Python Application]

        subgraph "Local Services"
            direction LR
            LocalDB[🐘<br><b>Local PostgreSQL</b><br>Docker<br>127.0.0.1:5432]
            Proxy[🔄<br><b>Cloud SQL Proxy</b><br>Local Process<br>127.0.0.1:5433]
        end
    end

    subgraph "GoogleCloudPlatformRemote"
        CloudSQL[☁️<br><b>Google Cloud SQL DB</b><br>Production Instance]
    end

    App -- "<b>Development Path</b><br>Connects to local DB" --> LocalDB
    App -- "<b>Production Path</b><br>Connects to local proxy" --> Proxy
    Proxy -.->|Secure Tunnel with IAM Auth| CloudSQL

    style App fill:#fffde7,stroke:#ffab00
    style LocalDB fill:#e8eaf6,stroke:#7986cb
    style Proxy fill:#e8f5e9,stroke:#81c784
    

    style GoogleCloudPlatformRemote fill:#e3f2f stroke:#64b5f6,stroke-width:2px
    style LocalEnvironment fill:#f0f4f8,stroke:#b0bec5,stroke-width:2px stroke-dasharray: 5 5

```


## 📝 Overview

The application is designed to operate in two distinct database environments:

1.  **Local Development**: For testing and development, the application connects directly to a local PostgreSQL database, typically running inside a Docker container. This connection happens on `127.0.0.1:5432`.

2.  **Production**: To securely access the production Google Cloud SQL database, the application connects to a locally running **Cloud SQL Auth Proxy** on `127.0.0.1:5433`. This proxy creates a secure, encrypted tunnel to the remote database and handles authentication automatically using Google Cloud IAM credentials. This avoids exposing the database to the public internet.

-----

## Diagram

The following diagram shows the flow of data for both paths from the Python application.

-----

## Data Model

### Single-row table (simpler)

  * One row per CWE entry.
  * `alternate_terms_text` is kept separate and heavily weighted in FTS.

<!-- end list -->

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
CREATE INDEX IF NOT EXISTS cwe_embeddings_cwe_id_idx ON cwe_embeddings(cwe_id);
-- Optimized vector indexes (created automatically):
-- HNSW (preferred): CREATE INDEX cwe_embed_hnsw_cos ON cwe_embeddings
--   USING hnsw (embedding vector_cosine_ops) WITH (m=24, ef_construction=200);
-- IVFFlat (fallback): CREATE INDEX cwe_embed_ivf_cos ON cwe_embeddings
--   USING ivfflat (embedding vector_cosine_ops) WITH (lists = sqrt(row_count));
```

### Chunked table (recommended)

  * Multiple rows per CWE (Title, Abstract, Extended, Mitigations, Examples, Related, Aliases).
  * Better recall and snippet relevance; supports **section intent** boost.
  * **Upsert-safe**: Re-ingesting updates content without creating duplicates.

<!-- end list -->

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

-- Natural unique key for preventing duplicates on re-ingest
CREATE UNIQUE INDEX IF NOT EXISTS cwe_chunks_unique ON cwe_chunks (cwe_id, section, section_rank);

-- Prefer HNSW if available; otherwise IVFFlat:
-- CREATE INDEX cwe_chunks_hnsw_cos ON cwe_chunks USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS cwe_chunks_ivf_cos ON cwe_chunks
  USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
```

-----

## Installation

```bash
# Install core dependencies via Poetry
poetry install

# Optional: Install sentence-transformers for local embeddings
poetry install --extras local-embeddings

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

  * `sentence-transformers` - Optional local embedding models (fallback if available)
  * `google-generativeai` - Gemini API integration for production embeddings (recommended)

### Development & Testing

  * `pytest` - Testing framework (if in dev dependencies)
  * All dependencies are managed via Poetry for consistent environments

**Note**: Core dependencies are automatically installed with `poetry install`. The system works perfectly with just these core dependencies using mock embeddings. For actual sentence-transformers local embeddings, use `poetry install --extras local-embeddings`.

-----

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
# Set up both database URLs (see 'Production Connection' section for PROD_DATABASE_URL)
export LOCAL_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"
export PROD_DATABASE_URL="postgresql://cwe-postgres-sa%40cwechatbot.iam@127.0.0.1:5433/cwe"

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

**4. Ready to Ingest\!**

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

-----

## Production Connection (Cloud SQL Proxy)

For production, we connect to the Google Cloud SQL database via the **Cloud SQL Auth Proxy**. This provides secure, IAM-based authentication without exposing the database to the public internet or managing SSL certificates manually.

**How it works:**

1.  The **Cloud SQL Proxy (v2)** runs locally (or as a sidecar container).
2.  It establishes a secure tunnel to the production Cloud SQL instance (`cwechatbot:us-central1:cwe-postgres-prod`).
3.  The application connects to the proxy on `127.0.0.1:5433`.
4.  The proxy forwards the connection, handling IAM authentication automatically using your local `gcloud` credentials or a service account.

**Setup:**

**1. Start the Cloud SQL Proxy**

```bash
# Start the proxy to listen on port 5433
cloud-sql-proxy cwechatbot:us-central1:cwe-postgres-prod --port 5433

# For IAM authentication, ensure you are logged in
gcloud auth application-default login
```

**2. Set Database Environment Variable**

The application connects to the *local proxy*, not the cloud instance directly.

```bash
# The DATABASE_URL points to the local proxy
export PROD_DATABASE_URL="postgresql://cwe-postgres-sa%40cwechatbot.iam@127.0.0.1:5433/cwe"

# Note: The username must be the IAM service account email, URL-encoded.
# psycopg does not require a password when connecting via the proxy with IAM.
```

When your application connects to `127.0.0.1:5433`, it's transparently and securely connected to:

  - **Real Destination**: Google Cloud SQL production database (`cwe-postgres-prod`) in `us-central1`.
  - **Authentication**: IAM service account `cwe-postgres-sa@cwechatbot.iam`.
  - **Security**: All traffic is encrypted through the secure proxy tunnel.

-----

## Usage (CLI)

### 📋 Available Commands

```bash
poetry run python cli.py --help
```

**Core Commands:**

  - **`ingest`** - Run CWE ingestion pipeline (single database)
  - **`ingest-multi`** - Run CWE ingestion to multiple databases (cost-optimized for Gemini)
  - **`query`** - Query similar CWEs with hybrid retrieval
  - **`stats`** - Database health check and collection statistics

**Key Options:**

  - **`--only-cwes-file PATH`** - Process only CWEs listed in file (supports incremental updates)
  - **`-c, --target-cwes ID`** - Target specific CWE IDs (can be combined with file)
  - **`--embedder-type {local,gemini}`** - Choose embedding provider
  - **`--chunked/--single`** - Storage mode (chunked recommended)

### 💰 Multi-Database Ingestion (Cost-Optimized)

**Generate embeddings once and distribute to multiple databases** - ideal for Gemini embeddings:

```bash
# Set up database URLs (see 'Production Connection' section for details)
export LOCAL_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"
export PROD_DATABASE_URL="postgresql://cwe-postgres-sa%40cwechatbot.iam@127.0.0.1:5433/cwe"

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

### 📈 Incremental Updates (New\!)

**Process only changed CWEs based on MITRE change reports** for maximum cost efficiency:

```bash
# Create file with changed CWE IDs (supports both formats)
cat > changed_cwes.txt << EOF
79
CWE-89
22
352
# Comments and empty lines are ignored
434
EOF

# Process only changed CWEs (cost-optimized for Gemini)
poetry run python cli.py ingest-multi --only-cwes-file changed_cwes.txt --embedder-type gemini

# Single database incremental update
poetry run python cli.py ingest --only-cwes-file changed_cwes.txt --chunked

# Mix file + inline flags (deduped, order preserved)
poetry run python cli.py ingest-multi \
  --only-cwes-file changed_cwes.txt \
  -c CWE-352 -c 434 \
  --embedder-type gemini
```

**File Format:**

  - One CWE ID per line
  - Supports both `79` and `CWE-79` formats
  - Comments start with `#`
  - Empty lines ignored
  - Automatic deduplication while preserving order

**Use Cases:**

  - 📊 **MITRE Updates**: Process [CWE diff reports](https://cwe.mitre.org/data/reports/diff_reports/) efficiently
  - 💰 **Cost Control**: Only generate embeddings for changed content
  - 🔄 **Selective Refresh**: Update specific CWEs without full re-ingestion
  - 🎯 **Targeted Testing**: Test specific vulnerability patterns

### 📊 Single Database Ingestion

```bash
# Mock embeddings (384-D), CHUNKED (recommended for development)
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

**Alias boost** activates when queries contain acronyms/aliases (e.g., "xss", "sqli").

### 🩺 Database Health Check

```bash
# Check chunked store health and record count
poetry run python cli.py stats --chunked

# Check single-row store health
poetry run python cli.py stats --single
```

**Example output:**

```
📊 PostgreSQL Chunked Store Health Check
----------------------------------------
✅ Database connection: OK
📦 Storage type: chunked (cwe_chunks table)
🎯 Collection: cwe_chunks
📈 Record count: 1,250
💡 Vector dimensions: 3072
✅ Database is healthy and contains data
```

-----

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
  * **Alias boost**: `pg_trgm` similarity against `alternate_terms_text` with case-insensitive normalization (helps fuzzy "xss/sqli/dir traversal" queries regardless of case).
  * **Section boost** (chunked): optional small bonus (e.g., **Mitigations** when query implies "prevent", "mitigate", "fix").

-----

## Retrieval Tuning Cheatsheet

### 🎯 Default Settings (General Queries)

```bash
poetry run python cli.py query -q "buffer overflow vulnerability" \
  --hybrid --chunked \
  --w-vec 0.65 --w-fts 0.25 --w-alias 0.10
```

**Use for**: Technical terms, descriptions, general vulnerability searches

### 🏷️ Acronym/Alias Queries

```bash
poetry run python cli.py query -q "xss csrf sqli" \
  --hybrid --chunked \
  --w-vec 0.60 --w-fts 0.25 --w-alias 0.15
```

**Bump alias weight to 0.15–0.20** when queries contain:

  - Common abbreviations: "xss", "sqli", "csrf", "xxe"
  - Security jargon: "dir traversal", "path traversal"
  - Alternative names that might appear in `alternate_terms_text`

### 🛡️ Prevention/Mitigation Queries

```bash
poetry run python cli.py query -q "how to prevent sql injection" \
  --hybrid --chunked --boost-section Mitigations \
  --w-vec 0.55 --w-fts 0.30 --w-alias 0.15
```

**Auto-detected** by `_infer_section_intent()` for queries containing:

  - "prevent", "mitigate", "remediate", "fix"

### 🔍 Very Short Queries (1-2 words)

```bash
poetry run python cli.py query -q "xss" \
  --hybrid --chunked \
  --w-vec 0.65 --w-fts 0.25 --w-alias 0.10 \
  -n 5  # Increase k_vec internally to 150+ for broader candidate set
```

**Short queries need more candidates**:

  - CLI automatically increases `k_vec` based on `n_results * 5`
  - Keep `limit_chunks` between 15–30 for good grouping
  - Consider increasing `-n` (results) to see more CWE matches

### ⚡ Performance vs Quality Trade-offs

```bash
# High recall (slower, more comprehensive)
poetry run python cli.py query -q "memory corruption" \
  --hybrid --chunked \
  --w-vec 0.70 --w-fts 0.20 --w-alias 0.10 \
  -n 10  # k_vec=50, limit_chunks=30

# Fast search (quicker, focused results)
poetry run python cli.py query -q "memory corruption" \
  --hybrid --chunked \
  --w-vec 0.65 --w-fts 0.25 --w-alias 0.10 \
  -n 3   # k_vec=15, limit_chunks=9
```

### 📊 Weight Guidelines

| Query Type   | w\_vec | w\_fts | w\_alias | Notes                    |
| :----------- | :---- | :---- | :------ | :----------------------- |
| **General** | 0.65  | 0.25  | 0.10    | Balanced approach        |
| **Acronyms** | 0.60  | 0.25  | 0.15    | Boost alias matching     |
| **Prevention** | 0.55  | 0.30  | 0.15    | Higher FTS for "how to"  |
| **Technical**| 0.70  | 0.20  | 0.10    | Vector-heavy for precise |
| **Fuzzy/Broad** | 0.50  | 0.35  | 0.15    | FTS-heavy for exploration|

**Rule of thumb**: Weights should sum to \~1.0 for consistent scoring

-----

## Worked Examples

> Assume chunked store + hybrid retrieval (`--chunked --hybrid`) with default weights `w_vec=0.65`, `w_fts=0.25`, `w_alias=0.10`.

### 1\) Alias-driven search

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

### 2\) Mitigation intent

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

### 3\) Exact ID

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

### 4\) Fuzzy jargon

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

-----

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
    w_vec=0.65, w_fts=0.25, w_alias=0.10,
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
        database_url="postgresql://cwe-postgres-sa%40cwechatbot.iam@127.0.0.1:5433/cwe",
        use_chunked=True,
        description="Production database (via Cloud SQL Proxy + IAM)"
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

# Generate Google Cloud SQL IAM connection URL for direct connection (no proxy)
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

-----

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

# Production database (via Cloud SQL Proxy with IAM - recommended)
export PROD_DATABASE_URL="postgresql://cwe-postgres-sa%40cwechatbot.iam@127.0.0.1:5433/cwe"

# See 'Production Connection (Cloud SQL Proxy)' section for setup instructions.
# Ensure proxy is running and you are authenticated to Google Cloud:
gcloud auth application-default login
# OR set service account credentials
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"

# Optional: Gemini embeddings (recommended for production)
export GEMINI_API_KEY="AIza..."
```

### Google Cloud SQL IAM Setup

Use the helper script to generate correct connection URLs for direct connections:

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

-----

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

-----

## Performance Optimization (halfvec)

### 🚀 Critical pgvector Limitation Discovery

**Problem:** pgvector 0.8.0 has a **2000 dimension maximum** for both HNSW and IVFFlat indexes:

```sql
ERROR: column cannot have more than 2000 dimensions for hnsw index
ERROR: column cannot have more than 2000 dimensions for ivfflat index
```

**Impact:** 3072D Gemini embeddings could not use accelerated vector indexes, forcing sequential scan with poor performance.

### ⚡ halfvec Optimization Solution

**Implementation:** halfvec(3072) + HNSW indexing bypasses dimension limits while maintaining semantic precision.

#### Migration Process

**Automatic Migration (Recommended):**
```bash
# Run migration script on both databases
GEMINI_API_KEY='your_key' \
LOCAL_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe" \
PROD_DATABASE_URL="postgresql://production_url" \
poetry run python migrate_to_halfvec.py
```

**Manual Migration:**
```sql
-- 1. Add normalized halfvec column (auto-maintained)
ALTER TABLE cwe_chunks
ADD COLUMN embedding_h halfvec(3072)
GENERATED ALWAYS AS (l2_normalize(embedding::halfvec)) STORED;

-- 2. Create HNSW index on halfvec column
CREATE INDEX cwe_chunks_embedding_h_hnsw
ON cwe_chunks USING hnsw (embedding_h halfvec_cosine_ops)
WITH (m = 16, ef_construction = 64);
```

#### Performance Results

| Method | Local Time | Production Time | Speedup | Index Type |
|--------|------------|-----------------|---------|------------|
| **Original vector(3072)** | 273.7ms | 1494.8ms | baseline | Sequential scan |
| **Optimized halfvec** | 150.7ms | 828.3ms | **1.8x faster** | HNSW |

**Key Benefits:**
- **1.8x speedup** in vector query performance
- **HNSW indexing** now works with 3072D embeddings
- **Backward compatibility** - original methods preserved
- **Zero application changes** required for existing code

#### Usage Examples

**New Optimized Methods:**
```python
# Fast vector similarity (halfvec + HNSW)
results = store.query_similar_fast(embedding, n_results=10)

# Fast hybrid search (FTS → halfvec rerank)
results = store.query_hybrid_fast(
    query_text="SQL injection",
    query_embedding=embedding,
    limit_chunks=20
)
```

**Existing Methods (Still Work):**
```python
# Original method (backward compatible)
results = store.query_similar(embedding, n_results=10)
```

#### PostgreSQL Optimization Settings

**Applied automatically in optimized methods:**
```sql
SET LOCAL hnsw.ef_search = 80;        -- High recall for HNSW
SET LOCAL jit = off;                  -- Disable JIT for small queries
SET LOCAL work_mem = '64MB';          -- Sufficient for sorting/limits
```

#### Architecture Decision

**Dual Vector Columns Strategy:**
- **`embedding`** - Original vector(3072) for backward compatibility
- **`embedding_h`** - Optimized halfvec(3072) with HNSW indexing
- **Auto-normalization** - L2 normalized via generated column
- **Method selection** - Choose based on performance requirements

### 📊 Performance Monitoring

**Test Performance:**
```bash
# Compare performance between methods
GEMINI_API_KEY='your_key' \
LOCAL_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe" \
poetry run python test_halfvec_performance.py
```

**Expected Results:**
- **Query time improvement:** 100ms+ saved per query
- **Consistency:** Same semantic results with better performance
- **Reliability:** HNSW index eliminates sequential scan bottlenecks

### 🎯 Path to <200ms p95 Target

**Current Status:**
- ✅ **halfvec optimization:** 1.8x speedup achieved
- ✅ **Local target met:** 150.7ms p95 (**under 200ms goal**)
- ⏳ **Production infrastructure optimization needed** for full <200ms target

**Next Steps:**
1. **Co-location:** Deploy app in us-central1 (eliminate 100-300ms network latency)
2. **Connection method:** Use Cloud SQL Connector instead of proxy
3. **Connection pooling:** Implement PgBouncer in transaction mode
4. **Prepared statements:** Use binary parameters for 3072D vectors

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
    1.  **Cloud SQL Proxy not running**:
          - Ensure the proxy is active and listening on the correct port (`127.0.0.1:5433`).
    2.  **Authentication not configured**:
        ```bash
        gcloud auth application-default login
        ```
    3.  **Service account missing permissions**:
          - Ensure service account has `Cloud SQL Client` role
          - Grant `cloudsql.instances.connect` permission
    4.  **Wrong URL format for proxy**:
        ```bash
        # ✅ Correct for proxy: No password, host is 127.0.0.1
        postgresql://iam-user@127.0.0.1:5433/dbname
        ```
    5.  **Cloud SQL instance not configured for IAM**:
          - Enable IAM authentication in Cloud SQL console
          - Create IAM database user (not traditional user)
  * **Multi-database configuration issues**:
    ```bash
    # Test multi-database setup
    poetry run python test_multi_db.py
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

-----

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

-----

## Security Notes

  * `defusedxml` prevents XXE.
  * Never log raw API keys; masked logging is already enforced.
  * Use a secrets manager for prod (`DATABASE_URL`, Gemini keys).
  * Use the **Cloud SQL Auth Proxy** for managed, secure Postgres connections.

-----

## Contributing

1.  TDD (write tests first).
2.  Keep security-first principles.
3.  Maintain backward compatibility across embedder choices (Gemini/local).
4.  Update README when changing retrieval/ranking.
5.  Test chunked and single-row paths.

-----

## License

This project is part of the CWE ChatBot BMad implementation, for **defensive security** use only.

-----

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
# Use multi-database with Google Cloud SQL IAM via the Cloud SQL Proxy
export LOCAL_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"
export PROD_DATABASE_URL="postgresql://cwe-postgres-sa%40cwechatbot.iam@127.0.0.1:5433/cwe"
gcloud auth application-default login
# Start the proxy in a separate terminal:
# cloud-sql-proxy cwechatbot:us-central1:cwe-postgres-prod --port 5433
poetry run python cli.py ingest-multi --embedder-type gemini  # 50% cost savings!
```

### ⚙️ Query Tuning

Start with **chunked + hybrid** and tune based on query type:

  * **General queries**: `w_vec=0.65, w_fts=0.25, w_alias=0.10`
  * **Short alias queries** ("xss", "sqli"): bump `w_alias` → `0.15–0.20`
  * **Remediation queries**: `--boost-section Mitigations` and/or `w_fts=0.30`
  * **Exact CWE lookups**: Vector similarity works well with default weights

### 💰 Cost Optimization

1.  **Always use `ingest-multi`** when you have multiple databases
2.  **Use Gemini embeddings** for production quality with cost optimization
3.  **Test with local embeddings** first to validate your setup
4.  **Monitor embedding API usage** - multi-database can reduce costs by 50%

### ⚡ Performance Optimization

**Gemini Batch Throughput Improvements**:

  - **Smart Strategy Selection**: Small batches (≤10) use sequential processing with minimal delays
  - **Parallel Processing**: Large batches (\>10) use thread pool with controlled concurrency
  - **Intelligent Rate Limiting**:
      - No delays for successful requests (maximum throughput)
      - Exponential backoff only after failures
      - Respectful delays every 20 requests to avoid rate limits
  - **Production Throughput**: 5-10x faster than previous 0.1s-per-request approach
  - **Configurable Concurrency**: Adjust `max_workers` parameter for optimal performance

**Query Performance After Bulk Inserts**:

  - **Automatic ANALYZE**: Refreshes table statistics after significant batch inserts (≥10 rows)
  - **Optimal Query Planning**: FTS and pgvector operations get accurate selectivity estimates
  - **Immediate Performance**: No waiting for autovacuum - queries are fast right after ingestion
  - **Minimal Overhead**: ANALYZE samples pages (doesn't rewrite tables) and runs in milliseconds

**Vector Search Quality Optimization**:

  - **IVFFlat Probe Tuning**: Automatically sets `ivfflat.probes = 10` for better recall
  - **Improved Search Quality**: Scans more clusters to find relevant vectors (vs default probes=1)
  - **HNSW Compatible**: Setting is harmless when HNSW index is used (HNSW ignores probe setting)
  - **Production Tuned**: Balanced for good recall with acceptable latency (tunable 5-20 range)

**Database Index Optimization**:

  - **Single-row store**: Added `cwe_id` index for efficient filtering when querying specific CWEs
  - **Chunked store covering indexes**:
      - `(cwe_id, section, section_rank)` unique index enables efficient grouping by CWE
      - `(section, section_rank)` index for section-based queries
      - Both indexes support the chunked retrieval display pattern (group by CWE → show 1-2 best chunks)
  - **Query Performance**: Covering indexes eliminate additional table lookups for common query patterns
  - **Automatic Creation**: All performance indexes are created automatically during schema setup

**Advanced pgvector Optimizations**:

  - **HNSW Index Parameters**: `m=24, ef_construction=200` for optimal recall/performance balance
  - **Dynamic IVF Lists**: Auto-calculated as `sqrt(row_count)` with min 100, max 2000 for optimal clustering
  - **Connection-Level Tuning**:
      - `hnsw.ef_search=80` for improved HNSW recall (default is 40)
      - `ivfflat.probes=10` for better IVFFlat search quality (default is 1)
  - **Robust Score Normalization**: COALESCE guards against NULL values in hybrid queries
  - **Intelligent Index Selection**: HNSW preferred, IVF created only when HNSW unavailable

### 🔒 Security Recommendations

1.  **Use the Cloud SQL Auth Proxy with IAM** for production (no passwords in URLs)
2.  **Set up proper service account roles** (`Cloud SQL Client`)
3.  **Use environment variables** for all credentials
4.  **Enable SSL** for all database connections (handled automatically by the proxy)
5.  **Rotate service account keys** regularly if using key files