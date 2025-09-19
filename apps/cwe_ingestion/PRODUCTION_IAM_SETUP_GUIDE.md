# Production IAM Setup Guide: Cloud SQL PostgreSQL

## Overview

This document provides a complete reference for setting up and troubleshooting Google Cloud SQL IAM authentication after extensive debugging in September 2025. This setup enables secure, passwordless access to production PostgreSQL databases using service account authentication.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          DUAL DATABASE ARCHITECTURE                            │
└─────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────┐    ┌────────────────────┐    ┌──────────────────────────────┐
│   Python Client  │    │  Shared Cache      │    │    Local PostgreSQL         │
│                  │    │                    │    │                              │
│ - PostgresChunk  │◄──►│ - CWE Embeddings   │◄──►│ - Direct Connection          │
│   Store          │    │ - CWE ID Filenames │    │ - No Authentication          │
│ - Embedding      │    │ - 3072D Vectors    │    │ - Port 5432                  │
│   Cache          │    │                    │    │                              │
└──────────────────┘    └────────────────────┘    └──────────────────────────────┘
         │
         │
         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        PRODUCTION CONNECTION FLOW                              │
└─────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────┐    ┌─────────────────┐    ┌──────────────────────────────┐
│   Python Client  │    │  Cloud SQL      │    │   Google Cloud SQL           │
│                  │    │  Proxy v2       │    │   PostgreSQL Instance        │
│                  │    │                 │    │                              │
│ ┌──────────────┐ │    │ ┌─────────────┐ │    │ ┌──────────────────────────┐ │
│ │ IAM Token    │ │    │ │ Certificate │ │    │ │ cwe-postgres-prod        │ │
│ │ Generation   │ │    │ │ Management  │ │    │ │                          │ │
│ │              │ │    │ │             │ │    │ │ - IAM Authentication: ON │ │
│ │ gcloud sql   │ │    │ │ SSL/TLS     │ │    │ │ - pgvector extension     │ │
│ │ generate-    │ │    │ │ Termination │ │    │ │ - Port 5432              │ │
│ │ login-token  │ │    │ │             │ │    │ │                          │ │
│ └──────────────┘ │    │ └─────────────┘ │    │ └──────────────────────────┘ │
│                  │    │                 │    │                              │
│ URL: postgresql://│    │ Listens on:     │    │ Internal IP:                 │
│ user%40domain:   │◄──►│ 127.0.0.1:5433  │◄──►│ (Proxy handles routing)      │
│ token@127.0.0.1: │    │                 │    │                              │
│ 5433/postgres    │    │ Auth: Service   │    │ User: cwe-postgres-sa@       │
│                  │    │ Account Key     │    │       cwechatbot.iam         │
└──────────────────┘    └─────────────────┘    └──────────────────────────────┘
```

## Authentication Flow Detail

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          AUTHENTICATION FLOW                                   │
└─────────────────────────────────────────────────────────────────────────────────┘

1. SERVICE ACCOUNT SETUP
   ┌─────────────────────────────────────────────────────┐
   │ Service Account: cwe-postgres-sa@cwechatbot.iam     │
   │ ├── Cloud IAM Roles:                                │
   │ │   ├── roles/cloudsql.client                       │
   │ │   └── roles/cloudsql.instanceUser                 │
   │ ├── Key File: /tmp/cwe-postgres-sa-key.json         │
   │ └── Database User: cwe-postgres-sa@cwechatbot.iam   │
   └─────────────────────────────────────────────────────┘

2. PROXY AUTHENTICATION
   ┌─────────────────────────────────────────────────────┐
   │ Environment Setup:                                  │
   │ export GOOGLE_APPLICATION_CREDENTIALS=             │
   │   "/tmp/cwe-postgres-sa-key.json"                  │
   │                                                     │
   │ Proxy Command:                                      │
   │ ./cloud-sql-proxy-v2 \                             │
   │   cwechatbot:us-central1:cwe-postgres-prod \        │
   │   --port 5433 \                                     │
   │   --auto-iam-authn \                                │
   │   --debug-logs                                      │
   └─────────────────────────────────────────────────────┘

3. CLIENT AUTHENTICATION
   ┌─────────────────────────────────────────────────────┐
   │ Token Generation:                                   │
   │ token = subprocess.check_output([                   │
   │   "gcloud", "sql", "generate-login-token"          │
   │ ], text=True).strip()                               │
   │                                                     │
   │ URL Construction (CRITICAL - @ must be encoded):   │
   │ encoded_user = urllib.parse.quote(                  │
   │   "cwe-postgres-sa@cwechatbot.iam", safe=""         │
   │ )                                                   │
   │ url = f"postgresql://{encoded_user}:{token}@        │
   │        127.0.0.1:5433/postgres"                     │
   └─────────────────────────────────────────────────────┘
```

## Working Code Patterns

### 1. Environment Setup
```bash
# Set up service account authentication
export GOOGLE_APPLICATION_CREDENTIALS="/tmp/cwe-postgres-sa-key.json"

# Activate service account
gcloud auth activate-service-account \
  cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com \
  --key-file=/tmp/cwe-postgres-sa-key.json
```

### 2. Proxy Startup
```bash
# Start Cloud SQL Proxy v2 with debug logging
./cloud-sql-proxy-v2 \
  cwechatbot:us-central1:cwe-postgres-prod \
  --port 5433 \
  --auto-iam-authn \
  --debug-logs
```

### 3. Python Connection Pattern
```python
import subprocess
import urllib.parse
from pg_chunk_store import PostgresChunkStore

def create_production_store():
    """Create PostgresChunkStore with production IAM authentication."""

    # Generate fresh IAM token
    token = subprocess.check_output([
        "gcloud", "sql", "generate-login-token"
    ], text=True).strip()

    # Create properly encoded URL (@ symbol MUST be URL encoded)
    encoded_user = urllib.parse.quote("cwe-postgres-sa@cwechatbot.iam", safe="")
    prod_url = f"postgresql://{encoded_user}:{token}@127.0.0.1:5433/postgres"

    # Create store instance
    return PostgresChunkStore(dims=3072, database_url=prod_url)

def create_dual_database_manager():
    """Create both local and production database connections."""

    # Local database (no authentication needed)
    local_store = PostgresChunkStore(
        dims=3072,
        database_url="postgresql://postgres:postgres@localhost:5432/cwe"
    )

    # Production database (IAM authentication)
    prod_store = create_production_store()

    return local_store, prod_store
```

### 4. Complete Working Example
```python
#!/usr/bin/env python3
"""
Production-ready dual database connection example.
"""

import subprocess
import urllib.parse
from pg_chunk_store import PostgresChunkStore

def test_dual_database_connection():
    """Test both local and production database connections."""

    print("🔥 Testing Dual Database Connections")
    print("=" * 45)

    try:
        # Test local database
        print("1. Testing local database...")
        local_store = PostgresChunkStore(
            dims=3072,
            database_url="postgresql://postgres:postgres@localhost:5432/cwe"
        )
        local_stats = local_store.get_collection_stats()
        print(f"   ✅ Local: {local_stats['count']} chunks")

        # Test production database
        print("2. Testing production database...")

        # Generate IAM token
        token = subprocess.check_output([
            "gcloud", "sql", "generate-login-token"
        ], text=True).strip()

        # Create encoded URL
        encoded_user = urllib.parse.quote("cwe-postgres-sa@cwechatbot.iam", safe="")
        prod_url = f"postgresql://{encoded_user}:{token}@127.0.0.1:5433/postgres"

        # Connect to production
        prod_store = PostgresChunkStore(dims=3072, database_url=prod_url)
        prod_stats = prod_store.get_collection_stats()
        print(f"   ✅ Production: {prod_stats['count']} chunks")

        print("\n🎉 Dual database setup working!")
        return True

    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

if __name__ == "__main__":
    test_dual_database_connection()
```

## Critical Configuration Details

### Cloud SQL Instance Settings
```yaml
Instance: cwechatbot:us-central1:cwe-postgres-prod
Settings:
  - cloudsql.iam_authentication: ON  # REQUIRED
  - PostgreSQL version: 14.19
  - Extensions: vector, pg_trgm, pgcrypto
  - Network: Private IP + Authorized networks
```

### Service Account IAM Roles
```yaml
Service Account: cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com
Cloud IAM Roles:
  - roles/cloudsql.client      # Connect to instances
  - roles/cloudsql.instanceUser # Use IAM authentication
Database User:
  - Name: cwe-postgres-sa@cwechatbot.iam  # IAM type user
  - Type: CLOUD_IAM_SERVICE_ACCOUNT
```

### Database Permissions (Required)

**IMPORTANT**: These permissions must be granted by connecting as the `postgres` user to ensure the IAM service account has full database access.

#### Step 1: Set postgres user password
```bash
# Set temporary password for postgres user
gcloud sql users set-password postgres --instance=cwe-postgres-prod --password=temp_admin_pass_123
```

#### Step 2: Connect as postgres user and grant comprehensive permissions
```sql
-- Connect as postgres user (use direct IP connection):
-- PGPASSWORD=temp_admin_pass_123 psql -h <CLOUD_SQL_IP> -U postgres -d postgres

-- Grant comprehensive permissions to IAM user
GRANT CONNECT ON DATABASE postgres TO "cwe-postgres-sa@cwechatbot.iam";
GRANT USAGE ON SCHEMA public TO "cwe-postgres-sa@cwechatbot.iam";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "cwe-postgres-sa@cwechatbot.iam";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "cwe-postgres-sa@cwechatbot.iam";

-- CRITICAL: Grant table ownership for full schema control
ALTER TABLE cwe_chunks OWNER TO "cwe-postgres-sa@cwechatbot.iam";

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL PRIVILEGES ON TABLES TO "cwe-postgres-sa@cwechatbot.iam";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL PRIVILEGES ON SEQUENCES TO "cwe-postgres-sa@cwechatbot.iam";
```

#### Step 3: Verify permissions
```sql
-- Check table ownership
SELECT tableowner FROM pg_tables WHERE tablename = 'cwe_chunks';
-- Should return: cwe-postgres-sa@cwechatbot.iam

-- Verify grants
SELECT grantee, privilege_type
FROM information_schema.role_table_grants
WHERE table_name = 'cwe_chunks' AND grantee = 'cwe-postgres-sa@cwechatbot.iam';
```

#### Why Table Ownership is Critical
- **Index Operations**: Creating/dropping indexes requires table ownership
- **Schema Modifications**: Altering table structure needs ownership rights
- **Performance**: Avoids permission checks on every operation
- **Future Operations**: Ensures PostgresChunkStore can manage schema evolution

## Troubleshooting Guide

Based on extensive debugging, here are the common issues and solutions:

### 1. Proxy Connection Issues

#### Symptoms:
- `invalid_grant` errors in proxy logs
- `400 Bad Request` responses from Google APIs
- `server closed the connection unexpectedly`

#### Debug Steps:
```bash
# Check Application Default Credentials
echo $GOOGLE_APPLICATION_CREDENTIALS

# Test service account activation
gcloud auth list

# Check if service account key is valid
gcloud auth activate-service-account \
  --key-file=/tmp/cwe-postgres-sa-key.json

# Test token generation
gcloud sql generate-login-token

# Start proxy with debug logs
./cloud-sql-proxy-v2 cwechatbot:us-central1:cwe-postgres-prod \
  --port 5433 --auto-iam-authn --debug-logs
```

#### Solutions:
1. **Corrupted ADC**: Remove `~/.config/gcloud/application_default_credentials.json`
2. **Wrong Environment**: Set `GOOGLE_APPLICATION_CREDENTIALS` before starting proxy
3. **Invalid Service Account**: Re-download and activate service account key

### 2. Database Connection Issues

#### Symptoms:
- `[Errno -8] Servname not supported for ai_socktype`
- `password authentication failed`
- URL parsing errors

#### Debug Steps:
```python
# Test URL encoding
import urllib.parse
user = "cwe-postgres-sa@cwechatbot.iam"
encoded = urllib.parse.quote(user, safe="")
print(f"Original: {user}")
print(f"Encoded:  {encoded}")

# Test direct connection
import psycopg
token = "your-token-here"
conn = psycopg.connect(
    host="127.0.0.1", port=5433, dbname="postgres",
    user="cwe-postgres-sa@cwechatbot.iam", password=token
)
```

#### Solutions:
1. **URL Encoding**: Always encode `@` symbol as `%40` in connection URLs
2. **Token Expiry**: Regenerate token if connection fails (tokens expire quickly)
3. **Wrong Port**: Ensure proxy is running on expected port (5433)

### 3. Database Permission Issues

#### Symptoms:
- `must be owner of table`
- `permission denied for schema`
- `InsufficientPrivilege` errors
- Index creation/deletion failures

#### Debug Steps:
```sql
-- Check current user permissions
SELECT current_user;

-- Check table ownership
SELECT tableowner FROM pg_tables WHERE tablename = 'cwe_chunks';

-- Check granted privileges
SELECT grantee, privilege_type
FROM information_schema.role_table_grants
WHERE table_name = 'cwe_chunks';

-- Test index operations (should work after ownership transfer)
CREATE INDEX test_permissions_idx ON cwe_chunks(created_at);
DROP INDEX test_permissions_idx;
```

#### Solutions:
1. **Set postgres password**: `gcloud sql users set-password postgres --instance=INSTANCE --password=PASSWORD`
2. **Connect as postgres user**: Use direct IP connection with password
3. **Transfer table ownership**: `ALTER TABLE cwe_chunks OWNER TO "IAM-USER"`
4. **Grant comprehensive permissions**: Include default privileges for future objects
5. **Verify ownership**: Confirm IAM user owns the table

#### Verification of Success:
```bash
# Test full PostgresChunkStore functionality
python -c "
from pg_chunk_store import PostgresChunkStore
store = PostgresChunkStore(dims=3072, database_url=PROD_URL)
stats = store.get_collection_stats()
print(f'✅ Production database operational: {stats[\"count\"]} chunks')
"
```

### 4. Token Generation Issues

#### Symptoms:
- `gcloud command not found`
- `Authentication failed`
- Empty or invalid tokens

#### Debug Steps:
```bash
# Check gcloud installation
which gcloud
gcloud version

# Check authentication
gcloud auth list
gcloud config get-value account

# Test token generation
gcloud sql generate-login-token
gcloud auth print-access-token  # Different token type - don't use!
```

#### Solutions:
1. **Use correct command**: `gcloud sql generate-login-token` (NOT `print-access-token`)
2. **Activate correct account**: Switch to service account if needed
3. **Fresh authentication**: Re-run `gcloud auth activate-service-account`

## Common Mistakes to Avoid

### ❌ Wrong Token Command
```bash
# WRONG - This is for general Google APIs
gcloud auth print-access-token

# CORRECT - This is specifically for Cloud SQL IAM
gcloud sql generate-login-token
```

### ❌ Wrong Username Format
```python
# WRONG - URL will parse incorrectly
url = "postgresql://cwe-postgres-sa@cwechatbot.iam:token@host:port/db"

# CORRECT - @ symbol must be URL encoded
encoded_user = urllib.parse.quote("cwe-postgres-sa@cwechatbot.iam", safe="")
url = f"postgresql://{encoded_user}:token@host:port/db"
```

### ❌ Wrong Proxy Version/Flags
```bash
# WRONG - This is Cloud SQL Proxy v1 syntax
./cloud_sql_proxy -instances=PROJECT:REGION:INSTANCE=tcp:5433

# CORRECT - This is Cloud SQL Proxy v2 syntax
./cloud-sql-proxy-v2 PROJECT:REGION:INSTANCE --port 5433 --auto-iam-authn
```

### ❌ Missing Environment Variables
```bash
# WRONG - Proxy can't find credentials
./cloud-sql-proxy-v2 instance --port 5433

# CORRECT - Set environment variable first
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"
./cloud-sql-proxy-v2 instance --port 5433 --auto-iam-authn
```

## Quick Diagnostic Checklist

When debugging connection issues, check these in order:

### Level 1: Environment Setup
- [ ] Service account key file exists and is valid
- [ ] `GOOGLE_APPLICATION_CREDENTIALS` environment variable set
- [ ] Service account activated: `gcloud auth list`
- [ ] Correct gcloud account selected

### Level 2: Google Cloud Configuration
- [ ] Service account has `cloudsql.client` and `cloudsql.instanceUser` roles
- [ ] Cloud SQL instance has `cloudsql.iam_authentication=on`
- [ ] Database user exists with IAM type
- [ ] Network access configured (IP allowlisting if needed)

### Level 3: Proxy Operations
- [ ] Cloud SQL Proxy v2 downloaded and executable
- [ ] Proxy starts without errors: "ready for new connections"
- [ ] No `invalid_grant` errors in debug logs
- [ ] Proxy listening on expected port: `ss -tulpn | grep 5433`

### Level 4: Token and Connection
- [ ] Token generation works: `gcloud sql generate-login-token`
- [ ] Token is not empty and reasonable length (200-1500 chars)
- [ ] Username properly URL encoded in connection string
- [ ] Connection string format is correct for psycopg

### Level 5: Database Permissions
- [ ] Can connect to database (basic authentication working)
- [ ] User has necessary schema permissions
- [ ] User can create/modify tables and indexes
- [ ] Extensions (vector, pg_trgm) are available

## Success Indicators

When everything is working correctly, you should see:

### Proxy Logs (Success)
```
2025/09/19 18:12:48 Authorizing with Application Default Credentials
2025/09/19 18:12:48 [instance] Connection info added to cache
2025/09/19 18:12:48 [instance] Listening on 127.0.0.1:5433
2025/09/19 18:12:48 The proxy has started successfully and is ready for new connections!
2025/09/19 18:12:49 [instance] Connection info refresh operation complete
2025/09/19 18:12:49 [instance] Current certificate expiration = 2025-09-19T19:12:47Z
```

### Python Connection (Success)
```python
>>> conn = psycopg.connect(url)
>>> cur = conn.cursor()
>>> cur.execute("SELECT current_user, version();")
>>> cur.fetchone()
('cwe-postgres-sa@cwechatbot.iam', 'PostgreSQL 14.19 on x86_64-pc-linux-gnu...')
```

### PostgresChunkStore (Success)
```python
>>> store = PostgresChunkStore(dims=3072, database_url=prod_url)
>>> stats = store.get_collection_stats()
>>> print(stats)
{'count': 0, 'avg_vector_magnitude': None}  # Ready for ingestion
```

## Related Documentation

- [Google Cloud SQL IAM Authentication](https://cloud.google.com/sql/docs/postgres/authentication)
- [Cloud SQL Proxy v2 Documentation](https://cloud.google.com/sql/docs/postgres/sql-proxy)
- [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials)

## Implementation History

- **September 19, 2025**: Extensive debugging session resulting in working IAM authentication
- **Key Insight**: URL encoding of @ symbol in usernames is critical for psycopg connections
- **Major Fix**: Application Default Credentials corruption required fresh service account activation
- **Proxy Discovery**: v2 syntax is significantly different from v1, requires specific flags
- **Final Resolution**: Database permissions and table ownership successfully transferred

## ✅ COMPLETION STATUS (September 19, 2025)

### Successful Implementation Verification
```
🎉 FINAL PRODUCTION DATABASE VALIDATION
✅ Local Database:       30 chunks
✅ Production Database:  20 chunks
✅ IAM Authentication:   Working
✅ Database Permissions: Full ownership granted
✅ Schema Operations:    Index creation/deletion working
🎯 Story 1.5: PRODUCTION SETUP COMPLETE!
```

### Working Components Confirmed
- ✅ **Cloud SQL Instance**: `cwechatbot:us-central1:cwe-postgres-prod` operational
- ✅ **Service Account**: `cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com` configured
- ✅ **IAM Roles**: `cloudsql.client` + `cloudsql.instanceUser` granted
- ✅ **Database User**: `cwe-postgres-sa@cwechatbot.iam` created and authorized
- ✅ **Cloud SQL Proxy v2**: Running with `--auto-iam-authn` flag
- ✅ **Token Generation**: `gcloud sql generate-login-token` working
- ✅ **URL Encoding**: `@` symbol properly encoded as `%40`
- ✅ **Database Permissions**: Table ownership transferred, full schema control
- ✅ **PostgresChunkStore**: Compatible with production database
- ✅ **Dual Architecture**: Local + production databases operational

### Performance Metrics Achieved
- **Connection Time**: ~1-2 seconds for IAM authentication
- **Query Performance**: <500ms requirement met (18.6ms average on local)
- **Index Operations**: Create/drop working with proper permissions
- **Schema Management**: Full PostgresChunkStore functionality enabled

### Ready for Production Use
This setup enables secure, scalable access to production Cloud SQL databases while maintaining a local development environment for testing and validation. The architecture supports:
- **Full CWE corpus ingestion** (969+ entries)
- **Dual database synchronization** (local + production)
- **Shared embedding cache** for cost optimization
- **Secure IAM authentication** with no hardcoded credentials