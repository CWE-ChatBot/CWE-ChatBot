# Real Integration Tests for CWE ChatBot

This directory contains **real integration tests** that follow CLAUDE.md principles:

> ✅ **"Write tests that verify real behavior (not mocked behavior)"**  
> ✅ **"Verify it works with the real system (no mocks!)"**  
> ✅ **"Understand the ACTUAL integration"**

## Test Files

- `test_integration_simple.py` - **Mocked integration tests** (safe to run always)
- `test_real_integration.py` - **Real integration tests** (requires actual services)

## Real Integration Test Architecture

The real integration tests verify the **actual intended architecture**:

```
User Query
    ↓
QueryProcessor (real input sanitization)
    ↓  
HybridRAGManager
    ├── DenseRetriever → PostgreSQL + pgvector (real vector search)
    ├── SparseRetriever → PostgreSQL + BM25 (real keyword search)  
    └── Score Fusion (real algorithm)
    ↓
ResponseFormatter (real formatting)
    ↓
User Response
```

## Prerequisites

### 1. PostgreSQL + pgvector Database

**Option A: Docker Setup (Recommended)**
```bash
# Start PostgreSQL with pgvector
docker-compose -f docker-compose.test.yml up -d

# Verify database is running
docker-compose -f docker-compose.test.yml ps
```

**Option B: Local PostgreSQL**
```bash
# Install PostgreSQL and pgvector extension
# Create database: cwe_chatbot_test
# Run: database/init/01-init-schema.sql
```

**Option C: Cloud SQL (Production)**
```bash
# Use Cloud SQL PostgreSQL instance with pgvector extension
# Import schema and test data
```

### 2. Dependencies Installation

```bash
# Install PostgreSQL client libraries
poetry add psycopg2-binary pgvector

# Install OpenAI client
poetry add openai

# Verify dependencies
poetry install
```

### 3. Environment Variables

Create `.env` file or set environment variables:

```bash
# Required for real integration tests
export POSTGRES_PASSWORD="testpassword123"
export OPENAI_API_KEY="sk-your-actual-openai-api-key"

# Optional (defaults provided)
export POSTGRES_HOST="localhost"
export POSTGRES_PORT="5433"  # Use 5433 for Docker setup
export POSTGRES_DATABASE="cwe_chatbot_test"
export POSTGRES_USER="postgres"
```

## Running Tests

### Skip Real Integration Tests (Default)
```bash
# Runs only mocked tests - safe to run in CI/CD
poetry run pytest apps/chatbot/tests/ -v
```

### Run Real Integration Tests
```bash
# Set environment variables and run real tests
POSTGRES_PASSWORD=testpassword123 OPENAI_API_KEY=sk-... \
poetry run pytest apps/chatbot/tests/test_real_integration.py -v

# Run specific real test
POSTGRES_PASSWORD=testpassword123 OPENAI_API_KEY=sk-... \
poetry run pytest apps/chatbot/tests/test_real_integration.py::TestRealDatabaseIntegration::test_database_connection -v
```

### Verify Test Environment
```bash
# Check if environment is properly configured
python apps/chatbot/tests/test_real_integration.py
```

## Test Coverage

### Real Database Integration Tests
- ✅ `test_database_connection` - Verifies PostgreSQL + pgvector setup
- ✅ `test_dense_retriever_real_database` - Tests semantic search with real pgvector
- ✅ `test_sparse_retriever_real_database` - Tests BM25 keyword search
- ✅ `test_hybrid_rag_manager_real_system` - Tests score fusion with real data
- ✅ `test_end_to_end_pipeline_real_systems` - Complete pipeline test

### Real OpenAI API Integration Tests  
- ✅ `test_real_embedding_service` - Tests actual OpenAI text-embedding-3-small API
- ✅ `test_batch_embedding_real_api` - Tests batch embedding API calls

### Configuration Validation Tests
- ✅ `test_config_validation_with_real_values` - Tests config with real environment

## Test Data

The database initialization script creates test CWE data:
- CWE-79 (Cross-site Scripting)
- CWE-89 (SQL Injection) 
- CWE-120 (Buffer Overflow)
- CWE-20 (Input Validation)
- CWE-787 (Out-of-bounds Write)

## Security Considerations

⚠️ **WARNING**: Real integration tests make actual API calls:
- **OpenAI API calls incur costs** (~$0.0001 per 1K tokens)
- **Database connections use real credentials** 
- **Tests create/modify real data**

### Safe Testing Practices:
1. Use dedicated test database (never production)
2. Use test API keys with spending limits
3. Run real tests only when necessary
4. Monitor API usage and costs

## Architecture Compliance

These tests verify the **actual architectural decisions**:

✅ **Database ADR Compliance**: Tests PostgreSQL + pgvector (not ChromaDB)  
✅ **Embedding ADR Compliance**: Tests OpenAI text-embedding-3-small  
✅ **Security Requirements**: Tests input sanitization and secure error handling  
✅ **Hybrid RAG Architecture**: Tests dense + sparse retrieval with score fusion

## Troubleshooting

### Database Connection Issues
```bash
# Check PostgreSQL is running
docker-compose -f docker-compose.test.yml logs postgres-test

# Verify pgvector extension
psql -h localhost -p 5433 -U postgres -d cwe_chatbot_test -c "SELECT extname FROM pg_extension WHERE extname = 'vector';"
```

### OpenAI API Issues
```bash
# Test API key
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models

# Check API quota
# Visit: https://platform.openai.com/usage
```

### Dependency Issues
```bash
# Reinstall PostgreSQL dependencies
poetry remove psycopg2-binary pgvector
poetry add psycopg2-binary pgvector

# Check imports
python -c "import psycopg2; from pgvector.psycopg2 import register_vector; print('✅ Dependencies OK')"
```

## Integration with CI/CD

### GitHub Actions Example
```yaml
- name: Setup PostgreSQL for Integration Tests
  run: |
    docker-compose -f docker-compose.test.yml up -d
    sleep 10  # Wait for database startup

- name: Run Real Integration Tests  
  env:
    POSTGRES_PASSWORD: testpassword123
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  run: |
    poetry run pytest apps/chatbot/tests/test_real_integration.py -v
```

## Next Steps

1. **Database Migration**: Migrate existing ChromaDB data to PostgreSQL
2. **Performance Testing**: Benchmark real retrieval performance
3. **Load Testing**: Test with larger CWE datasets
4. **Production Deployment**: Deploy to Cloud SQL with real data

## Comparison: Mocked vs Real Tests

| Aspect | Mocked Tests | Real Integration Tests |
|--------|-------------|----------------------|
| **Speed** | Fast (~5s) | Slower (~30s) |
| **Cost** | Free | ~$0.01 per run |
| **Reliability** | Always pass | May fail due to external issues |
| **Value** | Tests logic | Tests actual integration |
| **CI/CD** | Run always | Run on demand/release |
| **Dependencies** | None | PostgreSQL + OpenAI API |

Both are important: **Mocked tests for development velocity, Real tests for deployment confidence.**