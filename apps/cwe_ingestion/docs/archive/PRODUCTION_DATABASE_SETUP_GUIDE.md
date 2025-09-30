# Production Database Setup Guide

**The definitive guide for connecting to and importing data into Google Cloud SQL production database.**

*This document contains all the lessons learned from actual production deployment to avoid common pitfalls and connection issues.*

## Overview

This guide covers the complete process of:
1. Setting up Google Cloud SQL IAM authentication
2. Connecting to the production database via Cloud SQL Auth Proxy
3. Running CWE policy imports successfully
4. Troubleshooting common issues

## Prerequisites

### Required Tools
- [ ] `gcloud` CLI installed and authenticated
- [ ] `poetry` for Python dependency management
- [ ] `cloud-sql-proxy-v2` binary in the project directory
- [ ] Access to `~/work/env/.env_cwe_chatbot` environment file

### Required Access
- [ ] Google Cloud project access: `cwechatbot`
- [ ] Service account: `cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com`
- [ ] Cloud SQL instance: `cwechatbot:us-central1:cwe-postgres-prod`

## Step 1: Environment Verification

### 1.1 Check gcloud Authentication
```bash
# Verify gcloud is installed and authenticated
gcloud auth list --filter=status:ACTIVE --format="value(account)"
```
**Expected Output**: Should show an active account (e.g., `yourname@gmail.com`)

**If no active account**: Run `gcloud auth login`

### 1.2 Check Poetry Environment
```bash
# From apps/cwe_ingestion directory
poetry --version
poetry show | grep psycopg
```
**Expected Output**:
- Poetry version (e.g., `Poetry (version 1.x.x)`)
- `psycopg` package listed

**If psycopg missing**: Run `poetry install`

### 1.3 Check Cloud SQL Proxy Binary
```bash
# From apps/cwe_ingestion directory
ls -la cloud-sql-proxy-v2
```
**Expected Output**: Executable file present

**If missing**: Download from [Google Cloud SQL Proxy documentation](https://cloud.google.com/sql/docs/postgres/sql-proxy)

### 1.4 Check Environment File
```bash
ls -la ~/work/env/.env_cwe_chatbot
```
**Expected Output**: File exists

**Required Variables in file**:
```bash
GEMINI_API_KEY=your_gemini_api_key_here
```

## Step 2: Database Connection Setup

### 2.1 Switch to Service Account
```bash
# CRITICAL: Must use the service account for IAM authentication
gcloud config set account cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com
```
**Verification**:
```bash
gcloud config get account
```
**Expected Output**: `cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com`

### 2.2 Generate SQL Login Token
```bash
# Generate fresh token (expires quickly - regenerate as needed)
SQL_TOKEN=$(gcloud sql generate-login-token)
echo "Token generated: ${SQL_TOKEN:0:20}..."
```
**Expected Output**: Should show first 20 characters of token

**If fails**: Verify service account access and project permissions

### 2.3 Start Cloud SQL Auth Proxy
```bash
# From apps/cwe_ingestion directory
./cloud-sql-proxy-v2 "cwechatbot:us-central1:cwe-postgres-prod" --port=5433 &
```
**Expected Output**:
```
2025/09/30 10:xx:xx Authorizing with Application Default Credentials
2025/09/30 10:xx:xx [cwechatbot:us-central1:cwe-postgres-prod] Listening on 127.0.0.1:5433
2025/09/30 10:xx:xx The proxy has started successfully and is ready for new connections!
```

**Verification**:
```bash
# Check proxy is listening
nc -z 127.0.0.1 5433 && echo "Proxy ready" || echo "Proxy not ready"
```

## Step 3: Database Connection Testing

### 3.1 Set Database URL
```bash
# CRITICAL: Use URL-encoded format for IAM username
export DATABASE_URL="postgresql://cwe-postgres-sa%40cwechatbot.iam:${SQL_TOKEN}@127.0.0.1:5433/postgres"
```
**Key Points**:
- Use `%40` instead of `@` in username (URL encoding)
- Use `postgres` database (not `cwe` - that database doesn't exist)
- Include the fresh SQL token as password

### 3.2 Test Connection
```bash
poetry run python -c "
import psycopg
import os
try:
    conn = psycopg.connect(os.getenv('DATABASE_URL'))
    print('✅ Connection successful!')
    with conn.cursor() as cur:
        cur.execute('SELECT version();')
        version = cur.fetchone()[0]
        print(f'PostgreSQL version: {version[:60]}...')

        cur.execute('SELECT current_user;')
        user = cur.fetchone()[0]
        print(f'Connected as: {user}')
    conn.close()
except Exception as e:
    print(f'❌ Connection failed: {e}')
"
```
**Expected Output**:
```
✅ Connection successful!
PostgreSQL version: PostgreSQL 17.6 on x86_64-pc-linux-gnu, compiled by Debian c...
Connected as: cwe-postgres-sa@cwechatbot.iam
```

## Step 4: Using the Production Script

### 4.1 Test with Production Script
```bash
# Use the production script for all operations
./run_prod_full.sh --test-connection
```
**Expected Output**: Green checkmarks and connection verification

### 4.2 Available Operations
```bash
# Test database connection
./run_prod_full.sh --test-connection

# Import CWE policy labels (full corpus - 969 CWEs)
./run_prod_full.sh --import-policy

# Run CWE corpus ingestion
./run_prod_full.sh --ingest-corpus

# Performance testing
./run_prod_full.sh --performance-test

# Database health check
./run_prod_full.sh --health-check

# Start proxy only (for manual operations)
./run_prod_full.sh --start-proxy-only

# Stop proxy
./run_prod_full.sh --stop-proxy
```

## Step 5: Policy Import Process

### 5.1 Small Test Import (Recommended First)
```bash
# Test with limited CWEs first
export SQL_TOKEN=$(gcloud sql generate-login-token)
export DATABASE_URL="postgresql://cwe-postgres-sa%40cwechatbot.iam:${SQL_TOKEN}@127.0.0.1:5433/postgres"
poetry run python scripts/import_policy_from_xml.py \
  --url https://cwe.mitre.org/data/xml/cwec_latest.xml.zip \
  --infer-by-abstraction --limit 5
```
**Expected Output**:
```
2025-09-30 xx:xx:xx - INFO - Imported 5 policy labels into cwe_policy_labels
```

### 5.2 Full Policy Import
```bash
# Use production script for full import
./run_prod_full.sh --import-policy
```
**Expected Duration**: ~3-4 minutes for full 969 CWE corpus

**Expected Final Output**:
```
✅ CWE policy labels imported successfully
🎉 Operation 'import-policy' completed successfully!
```

### 5.3 Verify Import Success
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

### Issue 1: "Name or service not known" DNS Error
**Cause**: Using `@` instead of `%40` in connection string username

**Solution**: Always use URL-encoded format:
```bash
# WRONG
postgresql://cwe-postgres-sa@cwechatbot.iam:token@host/db

# CORRECT
postgresql://cwe-postgres-sa%40cwechatbot.iam:token@host/db
```

### Issue 2: "fe_sendauth: no password supplied"
**Cause**: Missing or expired SQL login token

**Solution**: Generate fresh token:
```bash
SQL_TOKEN=$(gcloud sql generate-login-token)
# Recreate DATABASE_URL with new token
```

### Issue 3: "Cloud SQL IAM service account authentication failed"
**Cause**: Not using the correct service account

**Solution**: Switch to service account:
```bash
gcloud config set account cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com
```

### Issue 4: "database 'cwe' does not exist"
**Cause**: Trying to connect to non-existent database

**Solution**: Use `postgres` database:
```bash
# WRONG
postgresql://...@127.0.0.1:5433/cwe

# CORRECT
postgresql://...@127.0.0.1:5433/postgres
```

### Issue 5: Import Process Hangs
**Cause**: SQL login token expiration during long operations

**Solution**: Use the production script which handles token refresh:
```bash
./run_prod_full.sh --import-policy
```

### Issue 6: Connection Timeout
**Cause**: Cloud SQL Auth Proxy not running or wrong port

**Solution**:
1. Check proxy status: `nc -z 127.0.0.1 5433`
2. Restart proxy if needed
3. Verify correct instance name: `cwechatbot:us-central1:cwe-postgres-prod`

## Production Database Schema

### Tables Created/Used
- **`cwe_chunks`**: CWE content data (7,913 chunks) - already exists
- **`cwe_policy_labels`**: CWE policy classifications (969 entries) - created by import

### Policy Label Values
- **`Allowed`**: Standard CWE entries safe for general use
- **`Allowed-with-Review`**: Require security team review
- **`Prohibited`**: High-risk vulnerabilities not allowed
- **`Discouraged`**: Practices to be avoided

## Performance Notes

### Expected Timing
- **Connection setup**: ~10 seconds
- **Small import (5-50 CWEs)**: ~10-30 seconds
- **Full import (969 CWEs)**: ~3-4 minutes
- **Verification queries**: ~1-2 seconds

### Resource Usage
- **Memory**: ~100MB during import
- **Network**: Minimal after proxy connection established
- **Database**: ~1MB storage for policy labels

## Security Considerations

### Authentication Flow
1. Use service account for consistent access
2. Generate short-lived SQL login tokens
3. Connect via encrypted Cloud SQL Auth Proxy
4. All data encrypted in transit and at rest

### Access Control
- Service account has minimal required permissions
- Database access restricted to IAM principals
- No permanent passwords or long-lived tokens

## Maintenance Tasks

### Regular Checks
```bash
# Weekly: Update CWE policy labels
./run_prod_full.sh --import-policy

# Monthly: Performance validation
./run_prod_full.sh --performance-test

# As needed: Health monitoring
./run_prod_full.sh --health-check
```

### Cleanup
```bash
# Stop proxy when done
./run_prod_full.sh --stop-proxy

# Or kill specific proxy processes
pkill -f "cloud-sql-proxy"
```

## Quick Reference Commands

### One-Time Setup
```bash
# Download proxy binary
# Set up environment file
# Authenticate with gcloud
```

### Daily Operations
```bash
# Test connection
./run_prod_full.sh --test-connection

# Import policies
./run_prod_full.sh --import-policy

# Stop when done
./run_prod_full.sh --stop-proxy
```

### Emergency Debugging
```bash
# Check gcloud account
gcloud config get account

# Check proxy status
nc -z 127.0.0.1 5433

# Generate fresh token
SQL_TOKEN=$(gcloud sql generate-login-token)

# Test connection manually
poetry run python -c "import psycopg; psycopg.connect('$DATABASE_URL')"
```

---

**This guide represents real production experience and should be the primary reference for all database operations.**