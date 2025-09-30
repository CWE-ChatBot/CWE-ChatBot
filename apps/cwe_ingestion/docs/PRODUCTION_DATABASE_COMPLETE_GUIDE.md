# Production Database Complete Guide

**The definitive, unified guide for Google Cloud SQL production database operations.**

*This document consolidates all lessons learned and provides the complete workflow for connecting to, importing data into, and managing the production Cloud SQL database. Updated September 30, 2025 with successful production deployment experience.*

## Overview

This guide covers the complete end-to-end process for:
1. **Environment Setup**: Configuring authentication and tools
2. **Cloud SQL Connection**: Establishing secure IAM-based connections
3. **Data Operations**: Running CWE corpus ingestion and policy imports
4. **Troubleshooting**: Solving common issues with proven solutions
5. **Production Operations**: Using automated scripts for reliable operations

## Architecture

### Production Database Infrastructure
```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         PRODUCTION ARCHITECTURE                                │
└─────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────┐    ┌─────────────────┐    ┌──────────────────────────────┐
│   Local Client   │    │  Cloud SQL      │    │   Google Cloud SQL           │
│                  │    │  Auth Proxy v2  │    │   PostgreSQL Instance        │
│                  │    │                 │    │                              │
│ ┌──────────────┐ │    │ ┌─────────────┐ │    │ ┌──────────────────────────┐ │
│ │ IAM Token    │ │    │ │ Certificate │ │    │ │ cwe-postgres-prod        │ │
│ │ Generation   │ │    │ │ Management  │ │    │ │                          │ │
│ │              │ │    │ │             │ │    │ │ - IAM Authentication: ON │ │
│ │ gcloud sql   │ │    │ │ SSL/TLS     │ │    │ │ - PostgreSQL 17.6        │ │
│ │ generate-    │ │    │ │ Termination │ │    │ │ - pgvector extension     │ │
│ │ login-token  │ │    │ │             │ │    │ │ - Database: postgres     │ │
│ └──────────────┘ │    │ └─────────────┘ │    │ └──────────────────────────┘ │
│                  │    │                 │    │                              │
│ Connection:      │    │ Listens on:     │    │ Instance Connection Name:    │
│ postgresql://    │◄──►│ 127.0.0.1:5433  │◄──►│ cwechatbot:us-central1:      │
│ user%40domain:   │    │                 │    │ cwe-postgres-prod            │
│ token@localhost: │    │ Auth: Service   │    │                              │
│ 5433/postgres    │    │ Account Key     │    │ User: cwe-postgres-sa@       │
│                  │    │                 │    │       cwechatbot.iam         │
└──────────────────┘    └─────────────────┘    └──────────────────────────────┘
```

### Database Contents
- **CWE Chunks**: 7,913 semantic content chunks for RAG retrieval
- **Policy Labels**: 969 CWE policy classifications (Allowed, Prohibited, etc.)
- **Extensions**: pgvector for embeddings, pg_trgm for text search

## Prerequisites

### Required Tools
```bash
# Check all prerequisites
gcloud --version                    # Google Cloud CLI
poetry --version                    # Python dependency management
ls -la cloud-sql-proxy-v2          # Cloud SQL Proxy v2 binary
ls -la ~/work/env/.env_cwe_chatbot  # Environment variables file
```

### Required Access
- **Google Cloud Project**: `cwechatbot`
- **Service Account**: `cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com`
- **Cloud SQL Instance**: `cwechatbot:us-central1:cwe-postgres-prod`
- **Database**: `postgres` (not `cwe` - that database doesn't exist)

### Environment File Setup
Required in `~/work/env/.env_cwe_chatbot`:
```bash
GEMINI_API_KEY=your_gemini_api_key_here
# Other environment variables as needed
```

## Step-by-Step Setup

### Step 1: Environment Verification

#### 1.1 Check Google Cloud Authentication
```bash
# Verify gcloud is authenticated
gcloud auth list --filter=status:ACTIVE --format="value(account)"
```
**Expected**: Should show your active account
**If no account**: Run `gcloud auth login`

#### 1.2 Check Python Environment
```bash
# From apps/cwe_ingestion directory
poetry show | grep psycopg
```
**Expected**: `psycopg` package listed
**If missing**: Run `poetry install`

#### 1.3 Check Cloud SQL Proxy Binary
```bash
# From apps/cwe_ingestion directory
ls -la cloud-sql-proxy-v2 && echo "Proxy binary ready"
```
**If missing**: Download from [Google Cloud SQL Proxy docs](https://cloud.google.com/sql/docs/postgres/sql-proxy)

### Step 2: Authentication Setup

#### 2.1 Switch to Service Account (CRITICAL)
```bash
# MUST use service account for IAM authentication
gcloud config set account cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com

# Verify switch was successful
gcloud config get account
```
**Expected Output**: `cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com`

#### 2.2 Generate SQL Login Token
```bash
# Generate fresh token (expires quickly)
SQL_TOKEN=$(gcloud sql generate-login-token)
echo "Token length: ${#SQL_TOKEN} characters"
```
**Expected**: Token should be 200-1500 characters long
**If fails**: Check service account permissions

### Step 3: Database Connection

#### 3.1 Start Cloud SQL Auth Proxy
```bash
# Start proxy in background
./cloud-sql-proxy-v2 "cwechatbot:us-central1:cwe-postgres-prod" --port=5433 &

# Wait for startup
sleep 5

# Verify proxy is running
nc -z 127.0.0.1 5433 && echo "✅ Proxy ready" || echo "❌ Proxy not ready"
```

**Expected Output**:
```
Authorizing with Application Default Credentials
[cwechatbot:us-central1:cwe-postgres-prod] Listening on 127.0.0.1:5433
The proxy has started successfully and is ready for new connections!
```

#### 3.2 Set Database Connection URL
```bash
# CRITICAL: Use URL-encoded format for username
export DATABASE_URL="postgresql://cwe-postgres-sa%40cwechatbot.iam:${SQL_TOKEN}@127.0.0.1:5433/postgres"
```

**Key Points**:
- Use `%40` instead of `@` in username (URL encoding)
- Use `postgres` database (not `cwe`)
- Include fresh SQL token as password

#### 3.3 Test Connection
```bash
poetry run python -c "
import psycopg
import os
try:
    conn = psycopg.connect(os.getenv('DATABASE_URL'))
    print('✅ Connection successful!')
    with conn.cursor() as cur:
        cur.execute('SELECT current_user, version();')
        user, version = cur.fetchone()
        print(f'Connected as: {user}')
        print(f'PostgreSQL: {version[:60]}...')
    conn.close()
except Exception as e:
    print(f'❌ Connection failed: {e}')
"
```

**Expected Output**:
```
✅ Connection successful!
Connected as: cwe-postgres-sa@cwechatbot.iam
PostgreSQL: PostgreSQL 17.6 on x86_64-pc-linux-gnu, compiled by Debian c...
```

## Production Script Operations

### Using run_prod_full.sh

The `run_prod_full.sh` script automates all production operations with proper authentication handling.

#### Available Operations
```bash
# Test database connection
./run_prod_full.sh --test-connection

# Import CWE policy labels (969 CWEs)
./run_prod_full.sh --import-policy

# Run CWE corpus ingestion (7,913 chunks)
./run_prod_full.sh --ingest-corpus

# Performance testing
./run_prod_full.sh --performance-test

# Database health check
./run_prod_full.sh --health-check

# Proxy management
./run_prod_full.sh --start-proxy-only
./run_prod_full.sh --stop-proxy
```

#### Script Features
- **Automatic Authentication**: Handles service account switching and token generation
- **Environment Loading**: Loads variables from `~/work/env/.env_cwe_chatbot`
- **Proxy Management**: Starts/stops Cloud SQL Auth Proxy automatically
- **Error Handling**: Comprehensive error checking and cleanup
- **Connection Validation**: Tests database connectivity before operations

### Policy Import Process

#### Small Test Import (Recommended First)
```bash
# Test with 5 CWEs to verify setup
export SQL_TOKEN=$(gcloud sql generate-login-token)
export DATABASE_URL="postgresql://cwe-postgres-sa%40cwechatbot.iam:${SQL_TOKEN}@127.0.0.1:5433/postgres"

poetry run python scripts/import_policy_from_xml.py \
  --url https://cwe.mitre.org/data/xml/cwec_latest.xml.zip \
  --infer-by-abstraction --limit 5
```

**Expected Output**:
```
INFO - Imported 5 policy labels into cwe_policy_labels
```

#### Full Policy Import
```bash
# Use production script for full import (969 CWEs)
./run_prod_full.sh --import-policy
```

**Expected Duration**: 3-4 minutes
**Expected Final Output**:
```
✅ CWE policy labels imported successfully
🎉 Operation 'import-policy' completed successfully!
```

#### Verify Import Success
```bash
export SQL_TOKEN=$(gcloud sql generate-login-token)
export DATABASE_URL="postgresql://cwe-postgres-sa%40cwechatbot.iam:${SQL_TOKEN}@127.0.0.1:5433/postgres"

poetry run python -c "
import psycopg
import os
conn = psycopg.connect(os.getenv('DATABASE_URL'))
with conn.cursor() as cur:
    cur.execute('SELECT COUNT(*) FROM cwe_policy_labels;')
    total = cur.fetchone()[0]
    print(f'Total policy entries: {total:,}')

    cur.execute('SELECT mapping_label, COUNT(*) FROM cwe_policy_labels GROUP BY mapping_label ORDER BY COUNT(*) DESC;')
    for label, count in cur.fetchall():
        percentage = (count / total) * 100
        print(f'{label}: {count:,} ({percentage:.1f}%)')
conn.close()
"
```

**Expected Output**:
```
Total policy entries: 969
Allowed: 753 (77.7%)
Allowed-with-Review: 88 (9.1%)
Prohibited: 84 (8.7%)
Discouraged: 44 (4.5%)
```

## Common Issues and Solutions

### Issue 1: DNS Resolution Error
**Error**: `Name or service not known` or `Servname not supported`

**Cause**: Using `@` instead of `%40` in connection string

**Solution**: Always URL-encode the username:
```bash
# WRONG
postgresql://cwe-postgres-sa@cwechatbot.iam:token@host/db

# CORRECT
postgresql://cwe-postgres-sa%40cwechatbot.iam:token@host/db
```

### Issue 2: Authentication Failed
**Error**: `fe_sendauth: no password supplied` or `password authentication failed`

**Cause**: Missing, expired, or wrong token type

**Solution**: Generate fresh SQL login token:
```bash
# Generate new token
SQL_TOKEN=$(gcloud sql generate-login-token)

# Recreate connection string with new token
export DATABASE_URL="postgresql://cwe-postgres-sa%40cwechatbot.iam:${SQL_TOKEN}@127.0.0.1:5433/postgres"
```

### Issue 3: Wrong Service Account
**Error**: `Cloud SQL IAM service account authentication failed`

**Cause**: Not using the service account for authentication

**Solution**: Switch to service account:
```bash
gcloud config set account cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com
gcloud config get account  # Verify
```

### Issue 4: Database Not Found
**Error**: `database 'cwe' does not exist`

**Cause**: Trying to connect to wrong database name

**Solution**: Use `postgres` database:
```bash
# WRONG
postgresql://...@127.0.0.1:5433/cwe

# CORRECT
postgresql://...@127.0.0.1:5433/postgres
```

### Issue 5: Proxy Connection Issues
**Error**: `Connection refused` or proxy startup failures

**Cause**: Proxy not running or wrong configuration

**Solution**:
1. Check proxy status: `nc -z 127.0.0.1 5433`
2. Restart proxy with correct instance name
3. Verify authentication with `gcloud auth list`

### Issue 6: Import Process Hangs
**Error**: Process appears to hang during import

**Cause**: SQL login token expiration during long operations

**Solution**: Use production script which handles token refresh:
```bash
./run_prod_full.sh --import-policy
```

## Production Database Schema

### Current Tables
- **`cwe_chunks`**: 7,913 semantic content chunks with embeddings
- **`cwe_policy_labels`**: 969 policy classifications

### Policy Label Categories
- **`Allowed`** (77.7%): Standard CWE entries safe for general use
- **`Allowed-with-Review`** (9.1%): Require security team review
- **`Prohibited`** (8.7%): High-risk vulnerabilities not allowed
- **`Discouraged`** (4.5%): Practices to be avoided

### Extensions Available
- **`vector`**: pgvector for embedding storage and similarity search
- **`pg_trgm`**: Trigram matching for text search
- **`pgcrypto`**: Cryptographic functions

## Performance Metrics

### Expected Timing
- **Connection setup**: ~10 seconds
- **Small import (5-50 CWEs)**: ~10-30 seconds
- **Full policy import (969 CWEs)**: ~3-4 minutes
- **CWE corpus ingestion (7,913 chunks)**: ~10-15 minutes
- **Verification queries**: ~1-2 seconds

### Resource Usage
- **Memory**: ~100-200MB during import operations
- **Network**: Minimal after proxy connection established
- **Database Storage**: ~50MB for policy labels, ~2GB for CWE chunks

## Security Considerations

### Authentication Flow
1. **Service Account**: Use dedicated IAM service account
2. **Short-lived Tokens**: Generate SQL login tokens as needed (expire quickly)
3. **Encrypted Proxy**: All connections via SSL/TLS through Cloud SQL Auth Proxy
4. **No Persistent Credentials**: No long-lived passwords or API keys

### Access Control
- Service account has minimal required permissions
- Database access restricted to IAM principals only
- All data encrypted in transit and at rest
- Network access via private IP with authorized networks

## Maintenance Operations

### Regular Tasks
```bash
# Weekly: Update CWE policy labels (as MITRE releases updates)
./run_prod_full.sh --import-policy

# Monthly: Performance validation
./run_prod_full.sh --performance-test

# As needed: Health monitoring
./run_prod_full.sh --health-check
```

### Cleanup Operations
```bash
# Stop proxy when done
./run_prod_full.sh --stop-proxy

# Kill any orphaned proxy processes
pkill -f "cloud-sql-proxy"
```

## Quick Reference

### Emergency Connection Commands
```bash
# Check gcloud account
gcloud config get account

# Generate fresh token
SQL_TOKEN=$(gcloud sql generate-login-token)

# Test proxy connectivity
nc -z 127.0.0.1 5433

# Test database connection
poetry run python -c "import psycopg; psycopg.connect('$DATABASE_URL')"
```

### One-Time Setup Checklist
- [ ] Download `cloud-sql-proxy-v2` binary
- [ ] Set up `~/work/env/.env_cwe_chatbot` environment file
- [ ] Authenticate with `gcloud auth login`
- [ ] Install Python dependencies with `poetry install`

### Daily Operations Workflow
```bash
# 1. Test connection
./run_prod_full.sh --test-connection

# 2. Run operations (policy import, corpus ingestion, etc.)
./run_prod_full.sh --import-policy

# 3. Verify results
./run_prod_full.sh --health-check

# 4. Stop proxy when done
./run_prod_full.sh --stop-proxy
```

## Troubleshooting Checklist

When issues arise, check these in order:

### Level 1: Authentication
- [ ] Correct gcloud account: `gcloud config get account`
- [ ] Service account active: Should be `cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com`
- [ ] Fresh token generated: `gcloud sql generate-login-token`
- [ ] Environment file exists: `ls ~/work/env/.env_cwe_chatbot`

### Level 2: Network
- [ ] Proxy running: `nc -z 127.0.0.1 5433`
- [ ] Correct instance name: `cwechatbot:us-central1:cwe-postgres-prod`
- [ ] No firewall blocking: Check local network settings
- [ ] Correct port: 5433 for proxy, 5432 for direct connection

### Level 3: Database
- [ ] Correct database name: `postgres` (not `cwe`)
- [ ] URL encoding: Username contains `%40` not `@`
- [ ] Connection string format: `postgresql://user:pass@host:port/db`
- [ ] Database exists: Verify in Cloud Console

### Level 4: Operations
- [ ] Sufficient permissions: Service account can read/write tables
- [ ] Required extensions: `vector`, `pg_trgm` available
- [ ] Table existence: `cwe_chunks`, `cwe_policy_labels` present
- [ ] Data integrity: Expected row counts and schema

## Success Indicators

### Proxy Startup (Success)
```
2025/09/30 10:xx:xx Authorizing with Application Default Credentials
2025/09/30 10:xx:xx [cwechatbot:us-central1:cwe-postgres-prod] Listening on 127.0.0.1:5433
2025/09/30 10:xx:xx The proxy has started successfully and is ready for new connections!
```

### Database Connection (Success)
```python
>>> import psycopg
>>> conn = psycopg.connect(url)
>>> cur = conn.cursor()
>>> cur.execute("SELECT current_user, version();")
>>> cur.fetchone()
('cwe-postgres-sa@cwechatbot.iam', 'PostgreSQL 17.6 on x86_64-pc-linux-gnu...')
```

### Policy Import (Success)
```
INFO - Parsed 969 CWE entries
INFO - Prepared 969 policy rows; 969 catalog rows
INFO - Imported 969 policy labels into cwe_policy_labels
INFO - VERIFY (db): CWE-20 PASS -> Discouraged
INFO - VERIFY (db): CWE-79 PASS -> Allowed
```

## Related Documentation

- [Google Cloud SQL IAM Authentication](https://cloud.google.com/sql/docs/postgres/authentication)
- [Cloud SQL Proxy v2 Documentation](https://cloud.google.com/sql/docs/postgres/sql-proxy)
- [psycopg Connection Documentation](https://www.psycopg.org/psycopg3/docs/basic/connect.html)

## Implementation History

- **September 19, 2025**: Initial IAM authentication setup and debugging
- **September 30, 2025**: Full production policy import success (969 CWEs)
- **Key Insights**: URL encoding of @ symbol, service account switching, database name correction
- **Production Validation**: Complete CWE corpus (7,913 chunks) + policy labels (969 entries)

---

**This unified guide represents the complete, battle-tested approach for production database operations. Use this as the single source of truth for all Cloud SQL interactions.**

## Status: ✅ PRODUCTION READY

### Validated Components
- ✅ **Authentication**: IAM-based passwordless access working
- ✅ **Connection**: Cloud SQL Auth Proxy v2 operational
- ✅ **Data Import**: Full CWE policy import completed (969 entries)
- ✅ **Content Storage**: 7,913 CWE chunks with embeddings ready
- ✅ **Performance**: All operations within expected timing
- ✅ **Security**: Encrypted connections, minimal permissions
- ✅ **Automation**: Production scripts handle all common operations

### Ready for Production Use
The production database infrastructure is fully operational and ready to support:
- CWE ChatBot application deployment
- Real-time RAG-based CWE query processing
- Secure multi-user access with IAM controls
- Automated data pipeline operations
- Performance monitoring and health checks