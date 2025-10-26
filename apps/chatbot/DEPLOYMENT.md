# CWE ChatBot Deployment Guide

## Overview

This guide ensures consistent, optimized deployments of the CWE ChatBot to staging and production environments.

## Prerequisites

1. **GCP Project**: Ensure you have a GCP project with billing enabled
2. **APIs Enabled**: Enable the following APIs:
   - Cloud Run API
   - Artifact Registry API
   - Cloud Build API
   - Cloud SQL Admin API
   - Secret Manager API
3. **Authentication**: Configure authentication with `gcloud auth login`

## Critical Files for Deployment

Three files control the deployment process and **must be kept synchronized**:

1. **`.gcloudignore`** (project root) - Controls what files are uploaded to Cloud Build
2. **`apps/chatbot/cloudbuild.yaml`** - Defines the Docker build process
3. **`apps/chatbot/deploy_staging.sh`** - Staging deployment script

## Build Optimization

### Performance Metrics

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| **Size** | 713 MiB | 232 MiB | 67% reduction |
| **Files** | 23,658 files | 5,594 files | 76% fewer |
| **Build Time** | 10+ minutes | ~3-4 minutes | 60%+ faster |

### Key Exclusions in `.gcloudignore`

The following patterns in `.gcloudignore` are **critical** for build optimization:

```
# Node modules (241 MB)
node_modules/

# Embeddings cache (223 MB)
**/cwe_embeddings_cache*

# Binary executables (33 MB)
**/cloud-sql-proxy*

# Cache directories
**/*_cache/
**/*_cache_*/

# Coverage reports (4.8 MB)
htmlcov/
.coverage
coverage.xml

# Security scan results (1+ MB)
checkov.json
bandit.json
*.sarif

# Documentation (not needed in runtime)
docs/
*.md
# Exception: Chainlit needs these
!apps/chatbot/chainlit.md
!apps/chatbot/prompt.md

# Tests (not needed in runtime)
tests/
*_test.py
test_*.py

# CI/CD configurations
.github/
.gitlab-ci.yml

# Development tools
web-bundles/
scripts/
bmad-agent/
.bmad-core/
```

## Deployment Process

### Staging Deployment

The `deploy_staging.sh` script handles the complete staging deployment:

```bash
# Public mode (for testing with external access)
PROJECT=cwechatbot REGION=us-central1 EXPOSURE_MODE=public ./apps/chatbot/deploy_staging.sh

# Private mode (IAM-gated, requires Cloud Run Invoker role)
PROJECT=cwechatbot REGION=us-central1 EXPOSURE_MODE=private ./apps/chatbot/deploy_staging.sh

# Private mode with tester access
PROJECT=cwechatbot REGION=us-central1 EXPOSURE_MODE=private \
TESTER_PRINCIPAL='user:alice@example.com' \
./apps/chatbot/deploy_staging.sh
```

### What the Script Does

The deployment script performs these steps in order:

1. **Builds PDF Worker** - Secure service for PDF processing
   ```bash
   gcloud builds submit apps/pdf_worker --tag="gcr.io/${PROJECT}/pdf-worker:latest"
   ```

2. **Deploys PDF Worker** - With service-account-only access (no public access)
   ```bash
   gcloud run deploy pdf-worker-staging --no-allow-unauthenticated
   ```

3. **Builds ChatBot Image** - Using `cloudbuild.yaml` from project root
   ```bash
   gcloud builds submit --config=apps/chatbot/cloudbuild.yaml
   ```

4. **Deploys ChatBot Staging** - With OAuth authentication and all required secrets
   ```bash
   gcloud run deploy cwe-chatbot-staging --set-secrets="GEMINI_API_KEY=gemini-api-key:latest,..."
   ```

5. **Sets IAM Policies** - Grants necessary access permissions

### Build Context (CRITICAL)

**The Docker build MUST run from the project root:**

```yaml
# cloudbuild.yaml (CORRECT)
- name: 'gcr.io/cloud-builders/docker'
  args:
    - 'build'
    - '--tag=gcr.io/$PROJECT_ID/cwe-chatbot:latest'
    - '-f'
    - 'apps/chatbot/Dockerfile'
    - '.'  # <-- Build context is project root (NOT apps/chatbot/)
```

**Why**: The Dockerfile references both `apps/chatbot/` and `apps/cwe_ingestion/` which are only available from the project root.

**WRONG**: Do not build from `apps/chatbot/` directory:
```bash
# ❌ This will fail
gcloud builds submit --tag gcr.io/PROJECT/cwe-chatbot apps/chatbot/
```

### Environment Variables

```bash
# Required
PROJECT=cwechatbot
REGION=us-central1

# Optional
EXPOSURE_MODE=public|private  # Default: private
TESTER_PRINCIPAL='user:alice@example.com'  # For private mode access
VPC_CONNECTOR=run-us-central1  # For VPC egress
RUN_TESTS=true  # Run integration tests after deployment
```

## Dependency Management

### Python Dependencies in Docker

All Python dependencies must be declared in `apps/chatbot/requirements.txt` for the Docker container build.

**Recent Critical Fix**: Added `python-jose[cryptography]==3.3.0` for JWT authentication:

```txt
# apps/chatbot/requirements.txt
pyjwt==2.10.1 ; python_version >= "3.10" and python_version < "4.0"
python-jose[cryptography]==3.3.0 ; python_version >= "3.10" and python_version < "4.0"
```

### Symptom of Missing Dependency

If you see this error in Cloud Run logs:
```
Could not set conversation manager for API: No module named 'jose'
```

**Fix**:
1. Add the missing dependency to `apps/chatbot/requirements.txt`
2. Rebuild: `gcloud builds submit --config=apps/chatbot/cloudbuild.yaml`
3. Redeploy: `./apps/chatbot/deploy_staging.sh`

## Verification After Deployment

### 1. Check Service Status

```bash
gcloud run services describe cwe-chatbot-staging --region=us-central1
```

### 2. Test API Endpoint

```bash
# Get service URL
SERVICE_URL=$(gcloud run services describe cwe-chatbot-staging --region=us-central1 --format='value(status.url)')

# Test without auth (should get 401)
curl -X POST $SERVICE_URL/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What is CWE-79?"}'
```

**Expected Response**: `401 Unauthorized` with error message about missing/invalid authentication

### 3. Check Logs

```bash
gcloud logging read \
  'resource.type=cloud_run_revision AND resource.labels.service_name=cwe-chatbot-staging' \
  --limit=50 \
  --format=json
```

### 4. Run E2E JWT Security Tests

```bash
poetry run pytest tests/e2e/test_jwt_auth_staging.py -v
```

**Expected**: All 16 JWT security tests should pass:
- ✅ Unauthenticated access rejected
- ✅ Malformed tokens rejected
- ✅ Algorithm confusion attacks blocked (CVE-2015-9235)
- ✅ Expired tokens rejected
- ✅ Invalid signatures rejected
- ✅ Modified payloads rejected
- ✅ Wrong issuer/audience rejected
- ✅ Unverified email rejected
- ✅ Non-allowlisted email rejected

## Security Features

### OAuth Authentication (Production Parity)

Staging uses **OAuth-only authentication** matching production:

```bash
# Environment variables set in deploy_staging.sh
ENABLE_OAUTH=true
AUTH_MODE=oauth
```

### Required Secrets

Secrets must exist in GCP Secret Manager:

1. `gemini-api-key` - Gemini API key for LLM
2. `db-password-app-user` - PostgreSQL password
3. `chainlit-auth-secret` - Session encryption key
4. `oauth-google-client-id` - Google OAuth client ID
5. `oauth-google-client-secret` - Google OAuth client secret
6. `oauth-github-client-id` - GitHub OAuth client ID
7. `oauth-github-client-secret` - GitHub OAuth client secret

### Service Account

- **Name**: `cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com`
- **Permissions**:
  - `roles/run.invoker` - Execute Cloud Run services
  - `roles/cloudsql.client` - Access Cloud SQL
  - `roles/secretmanager.secretAccessor` - Read secrets
  - `roles/logging.logWriter` - Write application logs

### Network Security
- **Ingress Control**: Configurable via `EXPOSURE_MODE` (private|public)
- **VPC Egress**: Private ranges only via VPC connector
- **Cloud SQL**: Private IP connection only

### Container Security
- **Base Image**: `python:3.11-slim` with SHA256 pinning
- **Non-root User**: Container runs as non-root user `appuser`
- **Minimal Attack Surface**: Only required dependencies included

## Monitoring and Logging

### Cloud Logging
Application logs are automatically sent to Cloud Logging and can be viewed at:
```
https://console.cloud.google.com/logs/query;query=resource.type%3D%22cloud_run_revision%22%0Aresource.labels.service_name%3D%22cwe-chatbot%22
```

### Health Check
- Production verification shows `GET /health` returns the Chainlit app HTML with HTTP 200 (no JSON body). This is expected since we do not expose a dedicated health endpoint.
- Cloud Run relies on its own TCP probe and does not use Docker `HEALTHCHECK`.
- You can verify availability with either endpoint:
```bash
# HTML response (expected): should return 200
curl -s -o /dev/null -w "%{http_code}\n" https://YOUR_SERVICE_URL/health

# Or check the root page
curl -s -o /dev/null -w "%{http_code}\n" https://YOUR_SERVICE_URL/
```

## Local Development

### Run Locally
```bash
cd apps/chatbot
pip install -r requirements.txt
chainlit run main.py
```

### Build and Test Container
```bash
cd apps/chatbot
docker build -t cwe-chatbot .
docker run -p 8080:8080 cwe-chatbot
```

## Deployment Success ✅

The CWE ChatBot has been successfully deployed to Cloud Run at:
**https://cwe-chatbot-258315443546.us-central1.run.app**

### Verified Functionality
- ✅ Chainlit interface loads correctly
- ✅ Welcome message displays: "Hello, welcome to CWE ChatBot!"
- ✅ Application logs available in Google Cloud Logging
- ✅ Secure configuration with minimal IAM permissions

## Common Issues and Solutions

### Issue: Build Too Large / Takes Too Long

**Symptom**: Build over 500 MB, takes 10+ minutes

**Cause**: `.gcloudignore` missing critical exclusions

**Solution**: Verify `.gcloudignore` includes all patterns from "Key Exclusions" section. Should achieve:
- Build size: ~232 MiB (vs 713 MiB before)
- File count: ~5,600 files (vs 23,658 before)
- Build time: ~3-4 minutes (vs 10+ minutes before)

### Issue: API Returns 405 Method Not Allowed

**Symptom**: POST requests to `/api/v1/query` return 405

**Root Causes**:
1. Missing Python dependency in `requirements.txt`
2. API router failed to initialize (check logs)

**Solution**:
1. Check logs for import errors:
   ```bash
   gcloud logging read 'resource.labels.service_name="cwe-chatbot-staging" severity>=ERROR' --limit=10
   ```
2. Look for errors like `No module named 'jose'`
3. Add missing dependency to `apps/chatbot/requirements.txt`
4. Rebuild: `gcloud builds submit --config=apps/chatbot/cloudbuild.yaml`
5. Redeploy: `./apps/chatbot/deploy_staging.sh`

### Issue: Module Import Errors

**Symptom**: Logs show `ModuleNotFoundError` or `ImportError`

**Example**:
```
Could not set conversation manager for API: No module named 'jose'
```

**Cause**: Missing dependency in `requirements.txt`

**Solution**:
1. Add to `apps/chatbot/requirements.txt`:
   ```txt
   python-jose[cryptography]==3.3.0
   ```
2. Rebuild and redeploy

### Issue: Wrong Build Context

**Symptom**: Docker build fails with `COPY failed: file not found` errors

**Cause**: Building from wrong directory

**Solution**: Always build from project root:
```bash
# CORRECT
gcloud builds submit --config=apps/chatbot/cloudbuild.yaml

# WRONG - do not do this
gcloud builds submit --tag gcr.io/PROJECT/cwe-chatbot apps/chatbot/
```

## Best Practices

### Before Every Deployment

- ✅ Verify `.gcloudignore` excludes large files
- ✅ Check `requirements.txt` has all dependencies
- ✅ Verify `cloudbuild.yaml` uses correct build context
- ✅ Test locally: `poetry run chainlit run apps/chatbot/main.py`

### After Every Deployment

- ✅ Check service status
- ✅ Test API endpoint (verify 401 without auth)
- ✅ Review logs for errors
- ✅ Run E2E tests: `poetry run pytest tests/e2e/test_jwt_auth_staging.py`

## Troubleshooting Commands

```bash
# Check current revision
gcloud run revisions list --service=cwe-chatbot-staging --region=us-central1

# View environment variables
gcloud run services describe cwe-chatbot-staging --region=us-central1 --format=json | jq '.spec.template.spec.containers[0].env'

# Check IAM policy
gcloud run services get-iam-policy cwe-chatbot-staging --region=us-central1

# Tail logs in real-time
gcloud logging tail "resource.type=cloud_run_revision AND resource.labels.service_name=cwe-chatbot-staging"

# Check for errors
gcloud logging read 'resource.labels.service_name="cwe-chatbot-staging" severity>=ERROR' --limit=20
```

## Quick Reference

### Key URLs

- **Staging Service**: https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app
- **Staging Domain**: https://staging-cwe.crashedmind.com
- **API Endpoint**: `/api/v1/query`
- **Health Check**: `/api/v1/health`

### Current Production Deployment

**Revision**: cwe-chatbot-staging-00036-75z

**Verified Functionality**:
- ✅ Build optimized (232 MiB, 3m38s build time)
- ✅ JWT authentication enforced (401 on unauthenticated requests)
- ✅ All 16 E2E security tests passing
- ✅ OAuth-only authentication (Google/GitHub)
- ✅ PDF Worker deployed with service-account-only access
- ✅ Cloud SQL integration working
- ✅ All secrets properly configured
