# Multi-Database CWE Ingestion Setup

## Overview

The multi-database CWE ingestion feature generates embeddings **once** and distributes them to multiple PostgreSQL databases, providing significant cost savings when using Gemini embeddings.

## 💰 Cost Benefits

- **50% cost reduction** for Gemini embeddings (generate once, store twice)
- **Faster ingestion** - no duplicate embedding generation
- **Consistent data** - same embeddings across environments
- **Flexible storage** - different modes per database (chunked vs single-row)

## 📋 Prerequisites

### 1. Database Setup

**Local Database (Development):**
```bash
# Start local PostgreSQL with pgvector via Docker
docker compose up -d
export LOCAL_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"
```

**Production Database (Google Cloud SQL with IAM):**
```bash
# Option 1: Use helper script to create URL
poetry run python gcp_db_helper.py create-url \
  -p myproject -r us-central1 -i cwe-instance -u cwe-service

# Option 2: Set URL manually (no password - uses IAM authentication)
export PROD_DATABASE_URL="postgresql://username@project:region:instance/dbname"

# Ensure Google Cloud authentication is configured
gcloud auth application-default login
# OR set service account credentials
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"

# Test IAM authentication
poetry run python gcp_db_helper.py test-iam-auth
```

**Alternative: Production Database with Traditional Authentication:**
```bash
# Set production database URL with username/password
export PROD_DATABASE_URL="postgresql://user:pass@prod-host:5432/cwe_prod"
```

**Alternative Environment Variables:**
- `DATABASE_URL` - fallback for local database
- `PRODUCTION_DATABASE_URL` - alternative for production database

### 2. Test Configuration

```bash
# Test multi-database setup
poetry run python test_multi_db.py
```

Expected output:
```
🧪 Multi-Database CWE Ingestion Test
==================================================
🔍 Environment Configuration:
   ✅ Local database: postgresql://postgres:***@localhost:5432/cwe
   ✅ Production database: postgresql://username***@project:region:instance/dbname

🎯 Database Targets (2):
   • local: Local development database (chunked)
   • production: Production database (Google Cloud SQL + IAM) (chunked)

🎉 All 2 database connections successful!
```

## 🚀 Usage Examples

### Basic Multi-Database Ingestion

```bash
# Set environment variables
export LOCAL_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"
export PROD_DATABASE_URL="postgresql://username@project:region:instance/dbname"  # Google Cloud SQL IAM

# Ensure Google Cloud authentication
gcloud auth application-default login

# Ingest with Gemini embeddings (cost-optimized)
poetry run python cli.py ingest-multi --embedder-type gemini

# Ingest with local embeddings
poetry run python cli.py ingest-multi --embedder-type local
```

### Advanced Configuration

```bash
# Target specific CWEs
poetry run python cli.py ingest-multi \
  --embedder-type gemini \
  -c CWE-79 -c CWE-89 -c CWE-22

# Mixed storage modes (local chunked, production single-row)
poetry run python cli.py ingest-multi \
  --embedder-type gemini \
  --local-chunked --prod-single

# Both databases single-row mode
poetry run python cli.py ingest-multi \
  --embedder-type gemini \
  --local-single --prod-single
```

## 📊 Expected Output

```
🔧 CWE Data Ingestion Pipeline (PostgreSQL)
🎯 Multi-database ingestion configured for 2 targets:
   • local: Local development database (chunked)
   • production: Production database (chunked)
💰 Using Gemini embeddings - cost optimized with single generation!

--- Starting Multi-Database CWE Ingestion Pipeline ---
🔄 Generating embeddings once for all database targets...
✅ Generated 1000 single-row embeddings.
✅ Generated 4500 chunked embeddings.

📥 Storing data in local (Local development database)...
✅ local: Stored 4500 chunked records.
📊 local stats: {'collection_name': 'cwe_chunks', 'count': 4500}

📥 Storing data in production (Production database)...
✅ production: Stored 4500 chunked records.
📊 production stats: {'collection_name': 'cwe_chunks', 'count': 4500}

✅ Successfully ingested data into all 2 database targets.
✅ Multi-database CWE ingestion completed successfully!
💡 Embeddings were generated once and distributed to all targets.
```

## 🛠️ Architecture

### Pipeline Flow

```
1. Download & Parse CWE XML
           ↓
2. Generate Embeddings ONCE
   • Single-row format (if needed)
   • Chunked format (if needed)
           ↓
3. Distribute to All Databases
   • Local: chunked/single-row
   • Production: chunked/single-row
   • Any additional targets
```

### Database Target Configuration

Each database target supports:
- **Name**: Identifier (local, production, etc.)
- **Database URL**: PostgreSQL connection string
- **Storage Mode**: Chunked or single-row
- **Description**: Human-readable description

## 🔧 Troubleshooting

### Environment Variable Issues

```bash
# Check configuration
poetry run python test_multi_db.py

# Missing variables error
❌ No database targets found. Set LOCAL_DATABASE_URL and/or PROD_DATABASE_URL environment variables.
```

**Solution:** Set at least one database URL:
```bash
export LOCAL_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cwe"
```

### Google Cloud SQL IAM Authentication Issues

```bash
# Test IAM authentication
poetry run python gcp_db_helper.py test-iam-auth

# Check authentication status
poetry run python gcp_db_helper.py check-auth
```

**Common Issues:**

1. **Authentication not configured:**
   ```bash
   gcloud auth application-default login
   ```

2. **Service account missing permissions:**
   - Ensure service account has `Cloud SQL Client` role
   - Grant `cloudsql.instances.connect` permission

3. **Wrong URL format:**
   ```bash
   # Correct: No password for IAM
   postgresql://username@project:region:instance/dbname

   # Incorrect: Has password
   postgresql://username:password@project:region:instance/dbname
   ```

4. **Cloud SQL instance not configured for IAM:**
   - Enable IAM authentication in Cloud SQL console
   - Create IAM database user (not traditional user)

### Database Connection Failures

```bash
# Test individual connections
poetry run python test_db_connection.py

# Check database is running
docker compose ps
docker compose logs pg
```

### Import Errors

If you see relative import errors when running scripts directly:

```bash
# Use proper module execution
poetry run python -m cli ingest-multi --help

# Or run from parent directory
cd ..
poetry run python apps/cwe_ingestion/cli.py ingest-multi --help
```

## 💡 Best Practices

### 1. Cost Optimization
- **Always use `ingest-multi`** when you need data in multiple databases
- **Use Gemini embeddings** for production-quality results with cost optimization
- **Test with local embeddings** first to validate setup

### 2. Storage Strategy
- **Chunked mode** (recommended): Better recall, section-specific search
- **Single-row mode**: Simpler, faster for basic similarity search
- **Mixed modes**: Different modes per environment based on use case

### 3. Environment Management
- **Local development**: Use Docker Compose PostgreSQL
- **Production**: Use managed PostgreSQL (Cloud SQL, RDS, etc.)
- **Separate credentials**: Never share production credentials with development

### 4. Validation
- **Always run tests** before production ingestion
- **Verify embedding counts** match expectations
- **Check database statistics** after ingestion

## 📝 Files Added

- `multi_db_pipeline.py` - Multi-database ingestion pipeline
- `test_multi_db.py` - Multi-database configuration and connection tests
- `MULTI_DATABASE_SETUP.md` - This documentation
- Enhanced `cli.py` with `ingest-multi` command
- Updated `README.md` with multi-database usage examples

## 🚀 Next Steps

1. **Set up environment variables** for your databases
2. **Run test scripts** to verify configuration
3. **Start with local embeddings** to test the flow
4. **Switch to Gemini embeddings** for production ingestion
5. **Monitor costs** and compare with single-database approach

The multi-database pipeline provides significant cost savings and operational efficiency for maintaining consistent CWE data across multiple environments.