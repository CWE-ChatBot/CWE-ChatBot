# Phase D: OAuth Configuration & Full End-to-End Verification - Complete

**Date**: 2025-10-09
**Status**: ✅ COMPLETE
**Based on**: [docs/plans/domain.md](./domain.md) Phase D
**Prerequisites**: Phase A (Load Balancer), Phase B (DNS), Phase C (Cloud Run Config)

---

## Summary

Successfully resolved OAuth configuration issues, database connectivity problems, and deployed fully functional CWE ChatBot at **https://cwe.crashedmind.com** with OAuth authentication, database access, and RAG-based CWE query capabilities.

---

## Issues Encountered and Resolved

### Issue 1: OAuth `redirect_uri_mismatch` Error

**Error Message**:
```
Access blocked: CWE ChatBot's request is invalid
Error 400: redirect_uri_mismatch
```

**Root Causes**:
1. Missing `CHAINLIT_URL` environment variable
2. Incorrect OAuth redirect URIs configured (missing `/oauth/` path component)

**Solution**:
1. Added `CHAINLIT_URL=https://cwe.crashedmind.com` environment variable
2. Corrected OAuth redirect URIs in provider consoles:

**Google OAuth Console**:
- ❌ Old: `https://cwe.crashedmind.com/auth/callback/google`
- ✅ New: `https://cwe.crashedmind.com/auth/oauth/google/callback`

**GitHub OAuth App**:
- ❌ Old: `https://cwe.crashedmind.com/auth/callback/github`
- ✅ New: `https://cwe.crashedmind.com/auth/oauth/github/callback`

### Issue 2: Startup Error - Configuration Missing

**Error Message**:
```
Startup error: configuration missing or database unavailable.
Please check environment (GEMINI_API_KEY/DB).
```

**Root Causes**:
1. Missing database environment variables (`DB_HOST`, `DB_USER`, `DB_PORT`)
2. App code expects `DB_*` variables but only `POSTGRES_*` were set initially
3. OAuth disabled (`ENABLE_OAUTH` not set to `true`)

**Solution**:
Added all required environment variables:
```bash
DB_HOST=10.43.0.3         # Private IP of Cloud SQL instance
DB_PORT=5432
DB_USER=app_user
ENABLE_OAUTH=true
```

### Issue 3: Database Table Not Found

**Error Message** (from logs):
```
UndefinedTable: relation "cwe_chunks" does not exist
Failed to initialize CWEQueryHandler: UndefinedTable
```

**Root Cause**:
- App connecting to wrong database (`cwe` instead of `postgres`)
- CWE ingestion pipeline stored data in `postgres` database

**Solution**:
Changed database name:
```bash
DB_NAME=postgres    # Was incorrectly set to 'cwe'
```

### Issue 4: ModuleNotFoundError

**Error** (from logs):
```
Failed to initialize CWEQueryHandler: ModuleNotFoundError
```

**Root Cause**:
- Stale Docker image missing dependencies

**Solution**:
Rebuilt Docker image with current code:
```bash
gcloud builds submit --config=apps/chatbot/cloudbuild.yaml
gcloud run services update cwe-chatbot --region=us-central1 --image=gcr.io/cwechatbot/cwe-chatbot:latest
```

---

## Final Configuration

### Cloud Run Environment Variables

**Production Revision**: `cwe-chatbot-00166-djt`

**Database Configuration**:
```
DB_HOST=10.43.0.3           # Private IP (via VPC connector)
DB_PORT=5432
DB_NAME=postgres             # Database with cwe_chunks table
DB_USER=app_user
DB_PASSWORD=SECRET:db-password-app-user
```

**OAuth Configuration**:
```
ENABLE_OAUTH=true
CHAINLIT_URL=https://cwe.crashedmind.com
CHAINLIT_AUTH_SECRET=SECRET:chainlit-auth-secret
OAUTH_GOOGLE_CLIENT_ID=SECRET:oauth-google-client-id
OAUTH_GOOGLE_CLIENT_SECRET=SECRET:oauth-google-client-secret
OAUTH_GITHUB_CLIENT_ID=SECRET:oauth-github-client-id
OAUTH_GITHUB_CLIENT_SECRET=SECRET:oauth-github-client-secret
```

**Security & App Configuration**:
```
PUBLIC_ORIGIN=https://cwe.crashedmind.com
CSP_MODE=compatible
HSTS_MAX_AGE=31536000
GOOGLE_CLOUD_PROJECT=cwechatbot
GEMINI_API_KEY=SECRET:gemini-api-key
```

**Other Configuration**:
```
PDF_WORKER_URL=https://pdf-worker-bmgj6wj65a-uc.a.run.app
POSTGRES_HOST=10.43.0.3     # Duplicate of DB_HOST (app supports both)
POSTGRES_PORT=5432
POSTGRES_DATABASE=postgres   # Duplicate of DB_NAME (app supports both)
POSTGRES_USER=app_user      # Duplicate of DB_USER (app supports both)
```

---

## OAuth Provider Configuration

### Google OAuth 2.0 Client

**Console**: https://console.cloud.google.com/apis/credentials

**Configuration**:
- **Authorized redirect URI**: `https://cwe.crashedmind.com/auth/oauth/google/callback`
- **Scopes**: `userinfo.email`, `userinfo.profile`

### GitHub OAuth App

**Console**: https://github.com/settings/developers

**Configuration**:
- **Homepage URL**: `https://cwe.crashedmind.com`
- **Authorization callback URL**: `https://cwe.crashedmind.com/auth/oauth/github/callback`

---

## Verification Results

### 1. HTTPS Endpoint
```bash
$ curl -I https://cwe.crashedmind.com/
HTTP/2 200
content-type: application/json
server: Google Frontend
```
✅ **Status**: Working

### 2. OAuth Authentication
**Test**: Navigate to https://cwe.crashedmind.com and sign in

**Google OAuth**:
- ✅ Redirects to Google login
- ✅ Authenticates successfully
- ✅ Returns to app with user session

**GitHub OAuth**:
- ✅ Redirects to GitHub login
- ✅ Authenticates successfully
- ✅ Returns to app with user session

### 3. Database Connectivity
**Logs Show**:
```
2025-10-09 13:24:58 - Private IP database engine initialized successfully
2025-10-09 13:24:58 - ✓ Connection pool warmed with 3 connections
2025-10-09 13:24:58 - ✓ Created connection pool: size=4, overflow=-4, sslmode=require
```
✅ **Status**: Database connected

### 4. CWE Query Processing
**Test Query**: "What is CWE-79 and how do I prevent it?"

**Result**:
- ✅ Query processed successfully
- ✅ Retrieved relevant CWE data from database
- ✅ Generated accurate response about Cross-Site Scripting (XSS)
- ✅ Provided prevention recommendations

**Logs Show**:
```
2025-10-09 13:25:00 - CWEQueryHandler initialized with Story 1.5 production infrastructure
2025-10-09 13:25:00 - RRF weights: {'w_vec': 0.65, 'w_fts': 0.25, 'w_alias': 0.1}
```

### 5. Component Initialization
**All components initialized successfully**:
- ✅ Database connection (Private IP via VPC connector)
- ✅ Gemini API embedder
- ✅ CWEQueryHandler (RAG retrieval)
- ✅ ConversationManager
- ✅ SecurityValidator
- ✅ InputSanitizer
- ✅ FileProcessor

---

## Architecture Status

```
Internet
    ↓
https://cwe.crashedmind.com (34.49.0.7 - static IP)
    ↓
HTTPS Load Balancer
    ├─ SSL Certificate: ACTIVE ✅
    ├─ Backend: cwe-chatbot-be
    └─ Forwarding Rule: cwe-chatbot-fr
           ↓
    Serverless NEG (cwe-chatbot-neg)
           ↓
    Cloud Run Service (cwe-chatbot)
        ├─ Revision: cwe-chatbot-00166-djt ✅
        ├─ Ingress: internal-and-cloud-load-balancing ✅
        ├─ OAuth: ENABLED ✅
        ├─ VPC Connector: run-us-central1 ✅
        └─ Private IP Database Access ✅
               ↓
        Cloud SQL (cwe-postgres-prod)
            ├─ Database: postgres ✅
            ├─ Private IP: 10.43.0.3 ✅
            └─ Table: cwe_chunks (7,913 chunks, 969 CWEs) ✅
```

---

## Deployment Iterations

| Revision | Issue | Fix |
|----------|-------|-----|
| cwe-chatbot-00161-qqh | OAuth disabled | Added ENABLE_OAUTH=true |
| cwe-chatbot-00162-4bj | OAuth still disabled | Added CHAINLIT_URL |
| cwe-chatbot-00163-nv2 | DB connection failed | Added POSTGRES_* env vars |
| cwe-chatbot-00164-8ng | Still DB errors | Added DB_* env vars |
| cwe-chatbot-00165-thl | cwe_chunks not found | Rebuilt Docker image |
| cwe-chatbot-00166-djt | Wrong database | Changed DB_NAME to postgres ✅ |

---

## Updated Documentation

**Files Updated**:
1. `apps/chatbot/deploy.sh`:
   - Added ENABLE_OAUTH, CHAINLIT_URL, PUBLIC_ORIGIN, CSP_MODE, HSTS_MAX_AGE
   - Fixed DB_NAME to postgres
   - Corrected OAuth redirect URI documentation paths

2. `docs/plans/phase-a-complete.md`: Phase A documentation
3. `docs/plans/phase-c-complete.md`: Phase C documentation
4. `docs/plans/phase-d-complete.md`: This document

---

## Lessons Learned

### 1. OAuth Configuration Requirements
- Chainlit requires `CHAINLIT_URL` environment variable for OAuth redirect URI construction
- OAuth redirect paths use `/auth/oauth/{provider}/callback` format (not `/auth/callback/{provider}`)
- Both `ENABLE_OAUTH=true` AND valid OAuth credentials required

### 2. Database Connectivity
- App code supports both `DB_*` and `POSTGRES_*` environment variable naming conventions
- Private IP requires: `DB_HOST`, `DB_USER`, `DB_PORT`, `DB_NAME`, `DB_PASSWORD` (secret)
- VPC connector must be configured for Cloud Run to access private IPs

### 3. Database Schema Location
- CWE ingestion pipeline stores data in `postgres` database by default
- Check actual database/table location before deployment
- Table: `cwe_chunks` contains 7,913 chunks from 969 CWEs

### 4. Deployment Best Practices
- Always rebuild Docker image after significant code changes
- Use `--update-env-vars` to add new variables without replacing existing ones
- Test OAuth redirect URIs match exactly what provider expects (including `/oauth/` path)
- Verify database connectivity and table existence before deployment

---

## Commands Reference

### Check Current Configuration
```bash
gcloud run services describe cwe-chatbot --region=us-central1 \
  --format=json | jq -r '.spec.template.spec.containers[0].env[] | "\(.name)=\(if .value then .value elif .valueFrom.secretKeyRef then "SECRET:" + .valueFrom.secretKeyRef.name else "null" end)"'
```

### Update Environment Variables
```bash
gcloud run services update cwe-chatbot --region=us-central1 \
  --update-env-vars="KEY1=value1,KEY2=value2"
```

### Check Logs
```bash
gcloud logging read "resource.type=cloud_run_revision \
  AND resource.labels.service_name=cwe-chatbot \
  AND timestamp>\"2025-10-09T13:00:00Z\"" \
  --limit 50 --format=json | jq -r '.[] | select(.textPayload) | .textPayload'
```

### Rebuild and Deploy
```bash
# Build
gcloud builds submit --config=apps/chatbot/cloudbuild.yaml

# Deploy
gcloud run services update cwe-chatbot --region=us-central1 \
  --image=gcr.io/cwechatbot/cwe-chatbot:latest
```

### Test Endpoint
```bash
curl -I https://cwe.crashedmind.com/
```

---

## Related Documentation

- **Phase A (Load Balancer)**: [phase-a-complete.md](./phase-a-complete.md)
- **Phase C (Cloud Run Config)**: [phase-c-complete.md](./phase-c-complete.md)
- **Domain Setup Plan**: [domain.md](./domain.md)
- **OAuth Setup Guide**: [apps/chatbot/OAUTH_SETUP.md](../../apps/chatbot/OAUTH_SETUP.md)
- **Deployment Script**: [apps/chatbot/deploy.sh](../../apps/chatbot/deploy.sh)

---

## Next Steps

### Phase E: Monitoring and Optimization (Optional)

1. **Set up Cloud Monitoring alerts**:
   - Response time > 2s
   - Error rate > 1%
   - Database connection pool exhaustion

2. **Performance optimization**:
   - Monitor query latency
   - Optimize vector search parameters if needed
   - Consider connection pooling tuning

3. **Security enhancements**:
   - Deploy Story S-12 security headers middleware
   - Enable Cloud Armor rate limiting
   - Configure CORS policies

4. **User management**:
   - Configure user whitelist if needed
   - Set up admin users
   - Monitor OAuth authentication metrics

---

## Summary

✅ **Phase D Complete** - OAuth authentication and full application functionality verified

**Production URL**: https://cwe.crashedmind.com

**Capabilities**:
- OAuth authentication (Google + GitHub)
- RAG-based CWE query processing
- Vector + full-text + alias hybrid search
- Gemini-powered response generation
- Secure database access via private IP
- TLS encryption via Google-managed certificate
- Static IP for DNS stability

**User-Verified Test**:
- Query: "What is CWE-79 and how do I prevent it?"
- Result: ✅ Accurate response about XSS with prevention guidance

**All systems operational** 🎉
