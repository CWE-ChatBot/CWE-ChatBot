# CWE ChatBot Deployment Guide

## Overview

This project has **two separate deployment scripts** to ensure production safety:

1. **`deploy.sh`** - Production deployment with OAuth-only authentication
2. **`deploy_staging.sh`** - Staging deployment with hybrid auth mode for E2E testing

## Quick Start

### Production Deployment
```bash
# From project root
./apps/chatbot/deploy.sh
```

**Configuration:**
- Service: `cwe-chatbot`
- AUTH_MODE: `oauth` (test-login endpoint disabled)
- Max instances: 10
- Concurrency: 80
- **Verification**: Script fails if test-login endpoint is accessible

### Staging Deployment
```bash
# From project root
./apps/chatbot/deploy_staging.sh
```

**Configuration:**
- Service: `cwe-chatbot-staging`
- AUTH_MODE: `hybrid` (test-login endpoint enabled for E2E tests)
- Max instances: 5
- Concurrency: 40
- **Verification**: Script confirms test-login endpoint is available

## Architecture: Hybrid Auth Mode

### Problem
Playwright E2E tests need to interact with the chatbot UI via WebSocket, but:
- OAuth dance is brittle in automation
- Anonymous access is a security risk
- We need secure authentication for testing

### Solution: AUTH_MODE Environment Variable
```
AUTH_MODE=oauth   → Production (test-login returns 404)
AUTH_MODE=hybrid  → Staging/Testing (test-login enabled)
```

### How Hybrid Auth Works

1. **Test Setup Phase**:
   ```bash
   # Playwright test obtains API key
   TEST_API_KEY=$(gcloud secrets versions access latest --secret=test-api-key)

   # Exchange API key for session cookie
   curl -X POST https://staging.example.com/api/v1/test-login \
     -H "X-API-Key: $TEST_API_KEY"

   # Response sets session cookie (30 min expiry, HttpOnly, Secure)
   ```

2. **Test Execution Phase**:
   ```python
   # Playwright uses session cookie for WebSocket/UI access
   await page.goto("https://staging.example.com")
   await page.fill("#message-input", "What is CWE-79?")
   await page.click("#send-button")
   # ... WebSocket authenticated via cookie
   ```

3. **Production Safety**:
   ```bash
   # In production (AUTH_MODE=oauth)
   curl -X POST https://production.example.com/api/v1/test-login
   # Returns 404 (endpoint hidden)
   ```

## Deployment Scripts Comparison

| Feature | Production (`deploy.sh`) | Staging (`deploy_staging.sh`) |
|---------|--------------------------|-------------------------------|
| Service Name | `cwe-chatbot` | `cwe-chatbot-staging` |
| AUTH_MODE | `oauth` (hardcoded) | `hybrid` (hardcoded) |
| test-login Endpoint | Disabled (404) | Enabled (401 for invalid key) |
| TEST_API_KEY Secret | Not included | From Secret Manager |
| Max Instances | 10 | 5 |
| Concurrency | 80 | 40 |
| Min Instances | 1 (always running) | 0 (scale to zero) |
| Image Tag | `latest` | `staging` |
| Safety Check | Fails if test-login accessible | Prevents production service name |
| Verification | test-login returns 404 | test-login returns 401 |

## Security Guarantees

### Production Deployment Safety
1. **Explicit AUTH_MODE**: Script hardcodes `AUTH_MODE=oauth`
2. **Post-Deployment Verification**: Script tests `/api/v1/test-login` and fails if it returns anything other than 404
3. **No TEST_API_KEY**: Production deployment does not include test-api-key secret

### Staging Deployment Safety
1. **Service Name Check**: Script fails if `SERVICE=cwe-chatbot` (production)
2. **Confirmation Required**: User must type "yes" to proceed
3. **Clear Warnings**: Script displays warnings about hybrid mode
4. **Separate Image Tag**: Uses `staging` tag instead of `latest`

## Prerequisites

### For Both Deployments
- gcloud CLI installed and authenticated
- Docker installed (for Cloud Build)
- Project set to `cwechatbot`
- Run from project root directory

### For Staging Deployment Only
```bash
# Create test-api-key secret (one-time setup)
python3 -c "import secrets; print(secrets.token_urlsafe(32))" | \
  gcloud secrets create test-api-key --data-file=-

# Grant service account access
gcloud secrets add-iam-policy-binding test-api-key \
  --member="serviceAccount:cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

## Testing After Deployment

### Production Verification
```bash
# Get service URL
PROD_URL=$(gcloud run services describe cwe-chatbot --region=us-central1 --format='value(status.url)')

# Verify health endpoint
curl $PROD_URL/health

# CRITICAL: Verify test-login is disabled
curl -X POST $PROD_URL/api/v1/test-login -H "X-API-Key: test"
# Expected: 404 Not Found
# If you get 401 or 200, AUTH_MODE is wrong - SECURITY ISSUE!
```

### Staging Verification
```bash
# Get service URL
STAGING_URL=$(gcloud run services describe cwe-chatbot-staging --region=us-central1 --format='value(status.url)')

# Get test API key
TEST_API_KEY=$(gcloud secrets versions access latest --secret=test-api-key)

# Verify test-login is enabled
curl -X POST $STAGING_URL/api/v1/test-login -H "X-API-Key: invalid-key"
# Expected: 401 Unauthorized (endpoint exists but key is invalid)

# Test valid API key
curl -X POST $STAGING_URL/api/v1/test-login -H "X-API-Key: $TEST_API_KEY"
# Expected: 200 OK with session cookie

# Run E2E tests
cd apps/chatbot/tests
CHATBOT_URL=$STAGING_URL TEST_API_KEY=$TEST_API_KEY \
  poetry run pytest integration/test_cwe_e2e_playwright.py
```

## Monitoring

### View Logs
```bash
# Production logs
gcloud logging tail 'resource.type="cloud_run_revision" resource.labels.service_name="cwe-chatbot"'

# Staging logs
gcloud logging tail 'resource.type="cloud_run_revision" resource.labels.service_name="cwe-chatbot-staging"'
```

### View Metrics
```bash
# Production metrics
https://console.cloud.google.com/run/detail/us-central1/cwe-chatbot/metrics?project=cwechatbot

# Staging metrics
https://console.cloud.google.com/run/detail/us-central1/cwe-chatbot-staging/metrics?project=cwechatbot
```

## Troubleshooting

### Production: test-login endpoint returns 401/200 instead of 404
**Problem**: AUTH_MODE is set to `hybrid` in production (CRITICAL SECURITY ISSUE)

**Solution**:
```bash
# Immediately redeploy with correct AUTH_MODE
./apps/chatbot/deploy.sh

# Verify fix
PROD_URL=$(gcloud run services describe cwe-chatbot --region=us-central1 --format='value(status.url)')
curl -X POST $PROD_URL/api/v1/test-login
# Must return 404
```

### Staging: test-login endpoint returns 404
**Problem**: AUTH_MODE is set to `oauth` in staging (E2E tests will fail)

**Solution**:
```bash
# Redeploy staging with correct AUTH_MODE
./apps/chatbot/deploy_staging.sh

# Verify fix
STAGING_URL=$(gcloud run services describe cwe-chatbot-staging --region=us-central1 --format='value(status.url)')
curl -X POST $STAGING_URL/api/v1/test-login -H "X-API-Key: invalid"
# Must return 401 (endpoint exists)
```

### Deployment script fails: "Must run from project root"
**Problem**: Script executed from wrong directory

**Solution**:
```bash
cd /path/to/cwe_chatbot_bmad
./apps/chatbot/deploy.sh  # or deploy_staging.sh
```

### Cloud Build fails: Cannot access apps/cwe_ingestion
**Problem**: Build context is wrong (building from apps/chatbot/ instead of project root)

**Solution**: The deployment scripts already handle this correctly by running `gcloud builds submit` from project root. If you're running gcloud commands manually, ensure you're in project root.

## CI/CD Integration (Future)

Example GitHub Actions workflow for branch-based deployment:

```yaml
name: Deploy CWE ChatBot

on:
  push:
    branches:
      - main       # Production
      - staging    # Staging

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Cloud SDK
        uses: google-github-actions/setup-gcloud@v1
        with:
          service_account_key: ${{ secrets.GCP_SA_KEY }}
          project_id: cwechatbot

      - name: Deploy to Production
        if: github.ref == 'refs/heads/main'
        run: ./apps/chatbot/deploy.sh

      - name: Deploy to Staging
        if: github.ref == 'refs/heads/staging'
        run: ./apps/chatbot/deploy_staging.sh
```

## Related Documentation

- [Hybrid Auth Pattern](./HYBRID_AUTH_PATTERN.md) - Detailed auth architecture
- [REST API Documentation](./tests/README_CWE_TESTING.md) - API usage and testing
- [Deployment Auth Modes](./DEPLOYMENT_AUTH_MODES.md) - Comprehensive deployment reference

## Summary

**Production**: Use `deploy.sh` for OAuth-only authentication with test-login disabled
**Staging**: Use `deploy_staging.sh` for hybrid auth mode with E2E testing support

Both scripts include safety checks and post-deployment verification to prevent misconfiguration.
