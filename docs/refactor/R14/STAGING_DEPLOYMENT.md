# Staging Deployment Guide

**Status**: ✅ Production-Ready
**Environment**: https://staging-cwe.crashedmind.com
**Authentication**: OAuth-only (Google + GitHub) - Production Parity

---

## Overview

The staging environment is **simple, same, and secure** - identical to production but isolated for safe testing.

### Simple

One command deploys both services:
```bash
./apps/chatbot/deploy_staging.sh
```

Optionally run integration tests:
```bash
RUN_TESTS=true ./apps/chatbot/deploy_staging.sh
```

### Same

Staging **exactly mirrors** production:
- ✅ **Same authentication**: OAuth-only (Google/GitHub), no API keys
- ✅ **Same security**: Private ingress, IAM-gated, Cloud Armor protected
- ✅ **Same infrastructure**: Cloud Run + Cloud SQL + PDF Worker
- ✅ **Same configuration**: Environment variables, secrets, service accounts

### Secure

Security-first architecture with 4 layers of defense:
1. **Load Balancer**: Cloud Armor WAF with rate limiting
2. **Cloud Run IAM**: Private ingress, authenticated access only
3. **OAuth**: Google/GitHub Bearer tokens required
4. **Container**: SHA256-pinned images, non-root user, hardened dependencies

---

## Architecture

```
Internet
    ↓
Load Balancer (34.49.0.7)
    ├── Cloud Armor WAF
    ├── SSL Certificate (staging-cwe.crashedmind.com)
    └── Host Routing
        ↓
    staging-cwe.crashedmind.com
        ↓
Cloud Run: cwe-chatbot-staging
    ├── Private ingress (internal-and-cloud-load-balancing)
    ├── OAuth Authentication (Google/GitHub)
    ├── Service Account: cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com
    └── Connects to:
        ├── Cloud SQL PostgreSQL (10.43.0.3:5432)
        └── PDF Worker Staging
            └── Private, service-account-only access
```

### Components

| Component | URL/Endpoint | Access Control |
|-----------|-------------|----------------|
| **Load Balancer** | https://staging-cwe.crashedmind.com | Public, Cloud Armor protected |
| **ChatBot Staging** | Internal Cloud Run URL | Private, IAM + OAuth required |
| **PDF Worker Staging** | Internal Cloud Run URL | Service-account-only |
| **Cloud SQL** | 10.43.0.3:5432 | Private VPC, IAM authentication |

---

## Deployment

### Prerequisites

- GCP authentication: `gcloud auth login`
- Project set: `gcloud config set project cwechatbot`
- Secrets configured in Secret Manager (automatically mounted)

### Deploy Staging

```bash
# Deploy both ChatBot and PDF Worker
./apps/chatbot/deploy_staging.sh
```

**Deployed Services:**
1. **PDF Worker Staging**: Secure PDF processing (service-account-only)
2. **ChatBot Staging**: OAuth-only web application

**Deployment Time**: ~5-8 minutes (includes building Docker images)

### Deploy with Integration Tests

```bash
# Get OAuth refresh token (one-time setup)
./scripts/ops/get_refresh_token_localhost.sh
export GOOGLE_REFRESH_TOKEN='your_token_here'

# Deploy and test
RUN_TESTS=true ./apps/chatbot/deploy_staging.sh
```

**Test Coverage:**
- ✅ Service deployment status
- ✅ OAuth configuration verification
- ✅ Headless OAuth authentication flow (refresh token → ID token → API calls)
- ✅ Response validation

---

## Configuration

### Environment Variables

**Authentication (OAuth-only)**:
```bash
AUTH_MODE=oauth                      # OAuth-only mode (no API keys)
ENABLE_OAUTH=true                    # OAuth providers enabled
CHAINLIT_URL=https://staging-cwe.crashedmind.com
PUBLIC_ORIGIN=https://staging-cwe.crashedmind.com
```

**Database**:
```bash
DB_HOST=10.43.0.3                    # Cloud SQL private IP
DB_PORT=5432
DB_NAME=postgres
DB_USER=app_user
DB_SSLMODE=require
CLOUD_SQL_CONNECTION_NAME=cwechatbot:us-central1:cwe-postgres-prod
```

**Services**:
```bash
PDF_WORKER_URL=https://pdf-worker-staging-*.run.app
GOOGLE_CLOUD_PROJECT=cwechatbot
```

**Security**:
```bash
CSP_MODE=strict                      # Content Security Policy
ISOLATE_SANITIZER=true               # PDF Worker isolation
MODEL_ARMOR_ENABLED=true             # AI safety guardrails
```

### Secrets (Secret Manager)

Automatically mounted from GCP Secret Manager:
- `gemini-api-key` - Gemini API key
- `db-password-app-user` - PostgreSQL password
- `chainlit-auth-secret` - Session encryption key
- `oauth-google-client-id` - Google OAuth client ID
- `oauth-google-client-secret` - Google OAuth client secret
- `oauth-github-client-id` - GitHub OAuth client ID
- `oauth-github-client-secret` - GitHub OAuth client secret

**No secrets in code, environment variables, or git history.**

### Resource Limits

**ChatBot Staging**:
- Memory: 512Mi
- CPU: 1
- Min instances: 0 (scales to zero)
- Max instances: 5
- Concurrency: 80 requests/container
- Timeout: 300s

**PDF Worker Staging**:
- Memory: 1Gi
- CPU: 1
- Min instances: 0
- Max instances: 10
- Concurrency: 10 requests/container
- Timeout: 60s

---

## Access Control

### Browser Access

**URL**: https://staging-cwe.crashedmind.com

**Authentication Flow**:
1. User navigates to staging URL
2. Cloud Armor WAF validates request
3. Load balancer routes to Cloud Run
4. Cloud Run IAM checks invoker permissions
5. OAuth login prompt (Google or GitHub)
6. User authenticates with OAuth provider
7. Application validates OAuth token
8. User gains access to ChatBot interface

**Requirements**:
- Valid Google or GitHub account
- Account must be authorized in OAuth app configuration

### API Access (Headless)

**Authentication**: OAuth Bearer token

**Getting an ID Token**:
```bash
# 1. Get refresh token (one-time)
./scripts/ops/get_refresh_token_localhost.sh
export GOOGLE_REFRESH_TOKEN='1//09...'

# 2. Get ID token (expires after 1 hour)
poetry run python scripts/ops/pretest_get_id_token.py
# Outputs: ID_TOKEN=eyJhbGc...
```

**Making API Calls**:
```bash
# Set ID token
ID_TOKEN="eyJhbGc..."

# Example: Query CWE information
curl -X POST https://staging-cwe.crashedmind.com/api/v1/query \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What is CWE-79?",
    "persona": "Developer"
  }'
```

**Response**:
```json
{
  "response": "CWE-79, **Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')**, is a fundamental web security vulnerability...",
  "sources": ["CWE-79"],
  "persona": "Developer"
}
```

### Service Account Access

**PDF Worker** is private - only accessible to ChatBot service account:
- Service Account: `cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com`
- Role: `roles/run.invoker`
- Authentication: Automatic (service-to-service OIDC)

---

## Security

### Cloud Armor WAF

**Policy**: `cwe-chatbot-armor`

**Rules**:
1. **Default Deny** (priority 2147483647): Block all traffic by default
2. **WebSocket Allow** (priority 1000): Allow WebSocket connections from staging origin
3. **Baseline Allow** (priority 2000): Allow GET/HEAD requests and JSON API calls ≤10MB
4. **Rate Limiting** (priority 1500): 100 requests/minute per user

**Protection**:
- ✅ DDoS mitigation
- ✅ Bot detection and blocking
- ✅ OWASP Top 10 protection
- ✅ Geographic blocking (if configured)

### OAuth Configuration

**Providers**:
- **Google**: OAuth 2.0 with OpenID Connect
- **GitHub**: OAuth 2.0

**OAuth App Settings**:
- **Authorized redirect URIs**:
  - `https://staging-cwe.crashedmind.com/auth/oauth/google/callback`
  - `https://staging-cwe.crashedmind.com/auth/oauth/github/callback`
  - `http://localhost:8080/` (for getting refresh tokens locally)

**Token Lifecycle**:
- **ID Token**: Expires after 1 hour
- **Refresh Token**: Long-lived (use to get new ID tokens)
- **Session**: Managed by Chainlit with encrypted cookies

### Container Security

**Base Image**: SHA256-pinned Python 3.11
```dockerfile
FROM python:3.11-slim@sha256:8df0e8f...
```

**User**: Non-root (appuser, UID 1000)
```dockerfile
RUN useradd -m -u 1000 appuser
USER appuser
```

**Dependencies**: Exact version pinning
```
functions-framework==3.9.2
google-cloud-modelarmor==0.2.8
pdfminer.six==20250506
pikepdf==9.11.0
```

---

## Testing

### Manual Browser Testing

1. Navigate to https://staging-cwe.crashedmind.com
2. Click "Sign in with Google" or "Sign in with GitHub"
3. Authenticate with your account
4. Verify ChatBot interface loads
5. Ask a question: "What is CWE-79?"
6. Verify response is generated

### Automated Integration Tests

```bash
# Get refresh token (one-time)
./scripts/ops/get_refresh_token_localhost.sh
export GOOGLE_REFRESH_TOKEN='your_token'

# Run all tests
./tests/integration/run_staging_tests.sh
```

**Test Results**:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Test Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Service deployment: Verified
✓ OAuth configuration: Verified
✓ OAuth flow: Tested and working
✓ Staging integration tests completed successfully!
```

### PDF Upload Testing

1. Open staging URL in browser
2. Click "Upload PDF" button
3. Select a PDF file (max 10MB)
4. Verify upload succeeds
5. Ask: "What's in this PDF?"
6. Verify content is extracted and analyzed

---

## Monitoring

### Service Health

```bash
# Check service status
gcloud run services describe cwe-chatbot-staging \
  --region=us-central1 \
  --project=cwechatbot \
  --format='value(status.conditions[0].status)'
# Output: True (service is ready)
```

### Latest Deployment

```bash
# Get latest revision
gcloud run services describe cwe-chatbot-staging \
  --region=us-central1 \
  --project=cwechatbot \
  --format='value(status.latestReadyRevisionName)'
```

### Logs

**ChatBot Logs**:
```bash
gcloud logging read \
  'resource.type=cloud_run_revision
   resource.labels.service_name=cwe-chatbot-staging
   severity>=ERROR' \
  --limit=50 \
  --project=cwechatbot
```

**PDF Worker Logs**:
```bash
gcloud logging read \
  'resource.type=cloud_run_revision
   resource.labels.service_name=pdf-worker-staging
   severity>=ERROR' \
  --limit=50 \
  --project=cwechatbot
```

### Metrics

**Cloud Run Console**:
- https://console.cloud.google.com/run/detail/us-central1/cwe-chatbot-staging

**Key Metrics**:
- Request count
- Request latency (p50, p95, p99)
- Error rate
- Container instance count
- CPU/memory utilization

---

## Troubleshooting

### "Access Forbidden (403)"

**Cause**: OAuth app not authorized or redirect URI mismatch

**Solution**:
1. Verify redirect URIs in OAuth app settings:
   - `https://staging-cwe.crashedmind.com/auth/oauth/google/callback`
   - `https://staging-cwe.crashedmind.com/auth/oauth/github/callback`
2. Ensure your Google/GitHub account is authorized
3. Clear browser cookies and try again

### "Service Unavailable (503)"

**Cause**: Service not ready or crashed

**Solution**:
```bash
# Check service status
gcloud run services describe cwe-chatbot-staging \
  --region=us-central1 --project=cwechatbot

# Check logs for errors
gcloud logging read \
  'resource.labels.service_name=cwe-chatbot-staging severity>=ERROR' \
  --limit=20 --project=cwechatbot
```

### OAuth Token Expired

**Symptom**: API calls return 401 Unauthorized

**Solution**: Get a fresh ID token (tokens expire after 1 hour)
```bash
export GOOGLE_REFRESH_TOKEN='your_refresh_token'
poetry run python scripts/ops/pretest_get_id_token.py
```

### PDF Upload Fails

**Cause**: PDF Worker not running or permission issues

**Solution**:
```bash
# Check PDF Worker status
gcloud run services describe pdf-worker-staging \
  --region=us-central1 --project=cwechatbot

# Check PDF Worker logs
gcloud logging read \
  'resource.labels.service_name=pdf-worker-staging severity>=ERROR' \
  --limit=20 --project=cwechatbot
```

---

## Differences from Production

**Only 2 differences** (intentional isolation):

| Aspect | Production | Staging |
|--------|-----------|---------|
| **URL** | https://cwe.crashedmind.com | https://staging-cwe.crashedmind.com |
| **Cloud Run Service** | cwe-chatbot | cwe-chatbot-staging |

**Everything else is identical**: authentication, security, infrastructure, database, secrets.

---

## Quick Reference

### Deploy
```bash
./apps/chatbot/deploy_staging.sh
```

### Test
```bash
export GOOGLE_REFRESH_TOKEN='your_token'
./tests/integration/run_staging_tests.sh
```

### Access
- **Browser**: https://staging-cwe.crashedmind.com
- **API**: Use OAuth Bearer token

### Get Refresh Token
```bash
./scripts/ops/get_refresh_token_localhost.sh
```

### Get ID Token
```bash
poetry run python scripts/ops/pretest_get_id_token.py
```

### View Logs
```bash
gcloud logging read 'resource.labels.service_name=cwe-chatbot-staging severity>=ERROR' --limit=20
```

---

## Summary

✅ **Simple**: One command deploys everything
✅ **Same**: Identical to production (OAuth-only, private, secure)
✅ **Secure**: 4-layer defense (Cloud Armor → IAM → OAuth → Container)

**Staging is production-ready and verified working.**

Test freely without affecting production - the architecture is identical, just isolated.
