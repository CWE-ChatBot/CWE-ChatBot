# Production Database Guide - Current Implementation Status

**Status:** September 30, 2025 - Fully operational production database with IAM authentication and Secret Manager integration.

---

## Current Production Setup (Implemented)

### **✅ Fully Working Components**

1. **Database Instance**: `cwe-postgres-prod` (PostgreSQL 17.6)
2. **IAM Authentication**: Zero-password flow with service account impersonation
3. **Secret Manager**: Gemini API key secure storage and retrieval
4. **Proxy Management**: Cloud SQL Auth Proxy v2 with automatic IAM authentication
5. **Extensions**: pgvector, pg_trgm available and tested

### **Current Network Security**
- **Public IP**: Enabled with restricted access
- **Authorized Networks**: Single IP restriction (`109.78.13.36` - development machine)
- **SSL Enforcement**: `requireSsl: true`
- **Certificate Mode**: `TRUSTED_CLIENT_CERTIFICATE_REQUIRED`
- **Risk Level**: LOW (multiple security layers provide strong protection)

---

## Connection Architecture (Current State)

```
┌──────────────────┐    ┌─────────────────┐    ┌──────────────────────────────┐
│   App / Client   │    │  Cloud SQL      │    │   Cloud SQL PostgreSQL       │
│ (Python/psycopg) │    │  Auth Proxy v2  │    │   Instance (17.6)            │
│                  │    │  --auto-iam-     │    │  cwe-postgres-prod           │
│  user=SA@proj.iam│◄──►│  authn + TLS +  │◄──►│  Public IP (restricted)      │
│  (no password)   │    │  IAM token      │    │  SSL + certificate required  │
└──────────────────┘    └─────────────────┘    └──────────────────────────────┘
     localhost:5433           automatic               database enforces
     plain connection         SSL/TLS handling        SSL + certificates
```

### **🔑 Key Security Point: No Manual SSL Certificate Management**

**Your application connects to `localhost:5433` with NO SSL configuration required.**

The Cloud SQL Auth Proxy automatically:
- ✅ Establishes secure TLS connection to the database
- ✅ Handles SSL certificate validation and rotation
- ✅ Manages IAM token injection
- ✅ Satisfies database SSL requirements (`TRUSTED_CLIENT_CERTIFICATE_REQUIRED`)

**You get enterprise-grade security with zero certificate management overhead.**

---

## Implemented IAM Setup

### **Prerequisites (Completed)**

1. **Service Account Credentials API**: ✅ Enabled
2. **Impersonation Permissions**: ✅ Configured for current user
3. **Cloud SQL IAM User**: ✅ Created (`cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com`)
4. **Secret Manager**: ✅ Enabled with Gemini API key stored

### **Current IAM Configuration**
```bash
# Service account has required permissions
gcloud iam service-accounts get-iam-policy cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com

# Returns:
# - roles/iam.serviceAccountTokenCreator (user:Crashedmind@gmail.com)
# - roles/iam.serviceAccountUser (user:Crashedmind@gmail.com)
```

---

## Daily Operations Script

The `run_prod_secure.sh` script provides production-ready operations:

### **Available Commands**
```bash
./run_prod_secure.sh --test-connection      # Test database connectivity
./run_prod_secure.sh --ingest-corpus        # Run CWE corpus ingestion
./run_prod_secure.sh --import-policy        # Import CWE policy labels
./run_prod_secure.sh --performance-test     # Run performance tests
./run_prod_secure.sh --health-check         # Check system health
./run_prod_secure.sh --start-proxy-only     # Start proxy and keep running
./run_prod_secure.sh --stop-proxy          # Stop running proxy

# Options:
./run_prod_secure.sh --db cwe_prod --test-connection    # Use specific database
./run_prod_secure.sh --embedder-type gemini             # Specify embedding model
./run_prod_secure.sh --target-cwes 79,89 --ingest      # Target specific CWEs
```

### **Security Features (Active)**
- ✅ ADC verification with service account impersonation
- ✅ Automatic IAM authentication via Cloud SQL Auth Proxy
- ✅ **Automatic SSL/TLS handling** (no certificate management required)
- ✅ Gemini API key retrieval from Secret Manager
- ✅ TLS encryption enforced at database level
- ✅ **Instance hardening status display** (shows current security settings)
- ✅ Production-grade error handling and user guidance
- ✅ **Robustness improvements** (handles missing nc command gracefully)

---

## Current Database Configuration

### **Instance Settings**
```bash
# Verify current configuration
gcloud sql instances describe cwe-postgres-prod --project=cwechatbot \
  --format="table(name,settings.ipConfiguration.ipv4Enabled,settings.ipConfiguration.requireSsl)"
```

### **Database Layout (Current)**
- **Database**: `postgres` (current working database)
- **Extensions**: `vector`, `pg_trgm` (confirmed available)
- **IAM User**: `cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com`

### **Connection String (Production)**
```
postgresql://cwe-postgres-sa%40cwechatbot.iam@127.0.0.1:5433/postgres
```

---

## Secret Manager Integration

### **Gemini API Key Setup (Completed)**
```bash
# Secret created and accessible
gcloud secrets versions access latest --secret="gemini-api-key" --project=cwechatbot

# Service account has access
gcloud secrets get-iam-policy gemini-api-key --project=cwechatbot
```

### **Script Integration**
The production script automatically:
1. Attempts to retrieve API key from Secret Manager
2. Falls back gracefully if not available for database-only operations
3. Exports the key for embedding operations

---

## Performance & Testing

### **Connection Testing Results**
```bash
# Successful connection output:
# ✅ ADC available
# ✅ API key loaded from Secret Manager
# ✅ Proxy ready on :5433
# ('cwe-postgres-sa@cwechatbot.iam', 'PostgreSQL 17.6...')
# Extensions: ['pg_trgm', 'vector']
```

### **Proxy Performance**
- **Startup Time**: ~1-2 seconds
- **Connection Ready**: Immediate after proxy start
- **Clean Shutdown**: PID-based process management

---

## Troubleshooting Guide

### **Common Issues & Solutions**

1. **IAM Authentication Failed**
   ```bash
   # Verify impersonation setup
   gcloud auth application-default print-access-token
   ```

2. **Port Already in Use**
   ```bash
   # Stop existing proxy processes
   ./run_prod_secure.sh --stop-proxy
   ```

3. **Secret Manager Access Denied**
   ```bash
   # Check service account permissions
   gcloud secrets get-iam-policy gemini-api-key --project=cwechatbot
   ```

4. **"Do I need SSL certificates?"**
   ```
   NO! The Cloud SQL Auth Proxy handles all SSL/TLS automatically.
   Your application connects to localhost:5433 with no SSL configuration.
   The proxy creates a secure tunnel to the database for you.
   ```

---

## Transition Steps (Low-Risk Security Hardening)

### **Step 1: Prep Private Access**

**If your ops will run from Google Cloud:**
```bash
# Option A: Use Cloud Workstations (recommended)
# Console → Cloud Workstations → Create workstation in target VPC

# Option B: Create GCE bastion in target VPC
gcloud compute instances create cwe-bastion \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --subnet=default \
  --project=cwechatbot
```

**If apps run on Cloud Run/GKE/GCE:** Ensure they can reach Private IP or PSC.

### **Step 2: Enable Private Connectivity**

**Console method (recommended):**
1. Instance → Connections → Add network → Private IP
2. Select VPC network and allocated IP range
3. Confirm connectivity from your runtime

**CLI method:**
```bash
# Enable private IP (requires VPC setup)
gcloud sql instances patch cwe-postgres-prod \
  --project=cwechatbot \
  --network=projects/cwechatbot/global/networks/default
```

### **Step 3: Disable Public Exposure**

⚠️ **Only after private connectivity is confirmed working**

```bash
gcloud sql instances patch cwe-postgres-prod \
  --project=cwechatbot \
  --no-assign-ip \
  --authorized-networks=""
```

### **Step 4: TLS Backstop** (protects any future raw TCP)

```bash
gcloud sql instances patch cwe-postgres-prod \
  --project=cwechatbot \
  --ssl-mode=ENCRYPTED_ONLY
```

### **Step 5: Enable pgAudit**

```bash
# Instance flags (restart required)
gcloud sql instances patch cwe-postgres-prod \
  --project=cwechatbot \
  --database-flags=cloudsql.enable_pgaudit=on,pgaudit.log=write,ddl

# Then, in each database via psql
CREATE EXTENSION IF NOT EXISTS pgaudit;
```

### **Step 6: Migrate to cwe_prod** (one-time, privileged session via proxy)

```sql
-- Create dedicated database and app role
CREATE DATABASE cwe_prod;
\c cwe_prod
CREATE ROLE cwe_app;
CREATE SCHEMA cwe AUTHORIZATION cwe_app;

-- Set up default privileges
ALTER DEFAULT PRIVILEGES IN SCHEMA cwe
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cwe_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA cwe
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO cwe_app;

-- Grant role to service account
GRANT cwe_app TO "cwe-postgres-sa@cwechatbot.iam";

-- Move existing objects (example)
\c postgres
ALTER TABLE public.cwe_chunks SET SCHEMA cwe;
ALTER TABLE cwe.cwe_chunks OWNER TO cwe_app;
ALTER TABLE public.cwe_policy_labels SET SCHEMA cwe;
ALTER TABLE cwe.cwe_policy_labels OWNER TO cwe_app;
```

**After the move, point scripts to cwe_prod:**
```bash
./run_prod_secure.sh --db cwe_prod --test-connection
```

---

## Current TODO Items

### **Immediate (Next Sprint)**
1. **VPC Setup**: Configure private IP connectivity
2. **Database Migration**: Execute `postgres` → `cwe_prod` migration
3. **Script Enhancement**: Add `--db` option and hardening status

### **Future Security Hardening**
1. **Disable Public IP**: Once private connectivity is confirmed
2. **Enable pgAudit**: Comprehensive audit logging
3. **TLS Enforcement**: `ENCRYPTED_ONLY` mode for raw TCP protection
4. **Enterprise Features**: CMEK, HA, monitoring setup

---

## Testing Commands

### **Verify Current Setup**
```bash
# Full connection test
./run_prod_secure.sh --test-connection

# Health check
./run_prod_secure.sh --health-check

# Secret Manager test
gcloud secrets versions access latest --secret="gemini-api-key" --project=cwechatbot
```

### **Database Connectivity**
```bash
# Direct psql connection via proxy
psql -h 127.0.0.1 -p 5433 -U "cwe-postgres-sa@cwechatbot.iam" -d postgres -c "SELECT current_user, version();"
```

---

## Current Security Assessment

### **✅ Strong Security Posture**
- **IAM Authentication**: No passwords, service account impersonation
- **TLS Encryption**: All connections encrypted with certificate verification
- **Access Control**: Single IP restriction with multiple authentication layers
- **Secret Management**: API keys secured in Google Secret Manager
- **Audit Trail**: All connections logged via Cloud SQL

### **Risk Mitigation**
The current "public IP with restrictions" approach provides:
- **Defense in Depth**: Multiple security layers (IP + TLS + certificates + IAM)
- **Zero Password Risk**: No password-based authentication vectors
- **Limited Attack Surface**: Single authorized IP reduces exposure
- **Secure Development**: Safe for current development and testing phase

---

**Status: ✅ PRODUCTION OPERATIONAL**

Current implementation provides enterprise-grade security with:
- Zero-password authentication flow
- Multi-layer network security
- Secure secret management
- Production-ready operational scripts
- Comprehensive testing and validation

Ready for CWE corpus ingestion and application development.