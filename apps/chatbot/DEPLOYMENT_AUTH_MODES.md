# Authentication Modes - Deployment Guide

## Overview

The CWE ChatBot supports two authentication modes via the `AUTH_MODE` environment variable:

- **`oauth`** (default, production): OAuth only, test endpoints disabled
- **`hybrid`** (staging/testing): OAuth + test-login endpoint for E2E tests

## ⚠️ CRITICAL: Production Safety

**NEVER deploy to production with `AUTH_MODE=hybrid`**

The `hybrid` mode enables the `/api/v1/test-login` endpoint which:
- Accepts API key authentication (less secure than OAuth for user access)
- Intended ONLY for automated testing in staging/CI environments
- Hidden when `AUTH_MODE=oauth` (returns 404)

## Deployment Configurations

### Production Deployment (REQUIRED)

**Environment Variables**:
```yaml
env:
  - name: AUTH_MODE
    value: "oauth"  # REQUIRED - disables test-login endpoint
  - name: ENABLE_OAUTH
    value: "true"
  - name: OAUTH_GOOGLE_CLIENT_ID
    valueFrom:
      secretKeyRef:
        name: oauth-google-client-id
        key: value
  - name: OAUTH_GOOGLE_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: oauth-google-client-secret
        key: value
  # TEST_API_KEY not needed in production
```

**Verification**:
```bash
# Test that test-login is disabled
curl -X POST https://cwe.crashedmind.com/api/v1/test-login \
  -H "X-API-Key: any-key"
# Expected: 404 Not Found

# Verify OAuth login page accessible
curl https://cwe.crashedmind.com/
# Expected: 200 OK with OAuth login UI
```

### Staging Deployment

**Environment Variables**:
```yaml
env:
  - name: AUTH_MODE
    value: "hybrid"  # Enables test-login for E2E tests
  - name: ENABLE_OAUTH
    value: "true"     # OAuth still works for manual testing
  - name: TEST_API_KEY
    valueFrom:
      secretKeyRef:
        name: test-api-key
        key: value
  - name: OAUTH_GOOGLE_CLIENT_ID
    valueFrom:
      secretKeyRef:
        name: oauth-google-client-id-staging
        key: value
  - name: OAUTH_GOOGLE_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: oauth-google-client-secret-staging
        key: value
```

**Verification**:
```bash
# Test that test-login is enabled
curl -X POST https://staging.cwe.example.com/api/v1/test-login \
  -H "X-API-Key: $TEST_API_KEY"
# Expected: 200 OK with session cookie

# Verify OAuth still works
curl https://staging.cwe.example.com/
# Expected: 200 OK with OAuth login option
```

### Local Development

**Option 1: Hybrid Mode (for E2E test development)**:
```bash
# .env file
AUTH_MODE=hybrid
ENABLE_OAUTH=false
TEST_API_KEY=your-local-api-key
DATABASE_URL=postgresql://...
GEMINI_API_KEY=your-key
```

**Option 2: OAuth Disabled (simplest for development)**:
```bash
# .env file
AUTH_MODE=oauth  # or omit (defaults to oauth)
ENABLE_OAUTH=false
DATABASE_URL=postgresql://...
GEMINI_API_KEY=your-key
```

## GCP Secret Manager Setup

### Production Secrets

```bash
# OAuth secrets (production)
gcloud secrets create oauth-google-client-id --data-file=- <<< "your-google-client-id"
gcloud secrets create oauth-google-client-secret --data-file=- <<< "your-google-client-secret"
gcloud secrets create oauth-github-client-id --data-file=- <<< "your-github-client-id"
gcloud secrets create oauth-github-client-secret --data-file=- <<< "your-github-client-secret"

# NO test-api-key in production (not needed)
```

### Staging Secrets

```bash
# OAuth secrets (staging - separate from production)
gcloud secrets create oauth-google-client-id-staging --data-file=- <<< "your-staging-google-client-id"
gcloud secrets create oauth-google-client-secret-staging --data-file=- <<< "your-staging-google-client-secret"

# Test API key for E2E tests
python -c "import secrets; print(secrets.token_urlsafe(32))" | \
  gcloud secrets create test-api-key --data-file=-
```

## Cloud Run Deployment Commands

### Deploy to Production

```bash
#!/bin/bash
# deploy-production.sh

gcloud run deploy cwe-chatbot \
  --image gcr.io/cwechatbot/cwe-chatbot:latest \
  --region us-central1 \
  --platform managed \
  --set-env-vars AUTH_MODE=oauth \
  --set-env-vars ENABLE_OAUTH=true \
  --update-secrets OAUTH_GOOGLE_CLIENT_ID=oauth-google-client-id:latest \
  --update-secrets OAUTH_GOOGLE_CLIENT_SECRET=oauth-google-client-secret:latest \
  --update-secrets OAUTH_GITHUB_CLIENT_ID=oauth-github-client-id:latest \
  --update-secrets OAUTH_GITHUB_CLIENT_SECRET=oauth-github-client-secret:latest \
  --update-secrets GEMINI_API_KEY=gemini-api-key:latest \
  --update-secrets DB_PASSWORD=db-password-app-user:latest \
  --allow-unauthenticated

echo "✅ Production deployed with AUTH_MODE=oauth (test-login disabled)"
```

### Deploy to Staging

```bash
#!/bin/bash
# deploy-staging.sh

gcloud run deploy cwe-chatbot-staging \
  --image gcr.io/cwechatbot/cwe-chatbot:latest \
  --region us-central1 \
  --platform managed \
  --set-env-vars AUTH_MODE=hybrid \
  --set-env-vars ENABLE_OAUTH=true \
  --update-secrets TEST_API_KEY=test-api-key:latest \
  --update-secrets OAUTH_GOOGLE_CLIENT_ID=oauth-google-client-id-staging:latest \
  --update-secrets OAUTH_GOOGLE_CLIENT_SECRET=oauth-google-client-secret-staging:latest \
  --update-secrets GEMINI_API_KEY=gemini-api-key:latest \
  --update-secrets DB_PASSWORD=db-password-app-user:latest \
  --allow-unauthenticated

echo "✅ Staging deployed with AUTH_MODE=hybrid (test-login enabled for E2E tests)"
```

## Testing After Deployment

### Production Verification

```bash
#!/bin/bash
# verify-production.sh

PROD_URL="https://cwe.crashedmind.com"

echo "1. Testing that test-login is disabled (should return 404)..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST $PROD_URL/api/v1/test-login \
  -H "X-API-Key: fake-key")

if [ "$STATUS" = "404" ]; then
  echo "✅ PASS: test-login endpoint disabled (404)"
else
  echo "❌ FAIL: test-login returned $STATUS (expected 404)"
  exit 1
fi

echo "2. Testing OAuth login page accessible..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" $PROD_URL/)

if [ "$STATUS" = "200" ]; then
  echo "✅ PASS: OAuth login page accessible"
else
  echo "❌ FAIL: Login page returned $STATUS"
  exit 1
fi

echo "3. Testing health endpoint..."
HEALTH=$(curl -s $PROD_URL/api/v1/health)
if echo "$HEALTH" | grep -q "healthy"; then
  echo "✅ PASS: Health endpoint working"
else
  echo "❌ FAIL: Health check failed"
  exit 1
fi

echo "
✅ Production deployment verified:
   - test-login endpoint: DISABLED (404)
   - OAuth login: ENABLED
   - Health check: PASSING
"
```

### Staging Verification

```bash
#!/bin/bash
# verify-staging.sh

STAGING_URL="https://cwe-chatbot-staging-<hash>-uc.a.run.app"
TEST_API_KEY=$(gcloud secrets versions access latest --secret=test-api-key)

echo "1. Testing that test-login is enabled..."
RESPONSE=$(curl -s -X POST $STAGING_URL/api/v1/test-login \
  -H "X-API-Key: $TEST_API_KEY")

if echo "$RESPONSE" | grep -q '"ok":true'; then
  echo "✅ PASS: test-login endpoint enabled and working"
else
  echo "❌ FAIL: test-login not working: $RESPONSE"
  exit 1
fi

echo "2. Testing OAuth still works..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" $STAGING_URL/)

if [ "$STATUS" = "200" ]; then
  echo "✅ PASS: OAuth login page accessible"
else
  echo "❌ FAIL: Login page returned $STATUS"
  exit 1
fi

echo "
✅ Staging deployment verified:
   - test-login endpoint: ENABLED
   - OAuth login: ENABLED
   - Ready for E2E tests
"
```

## CI/CD Integration

### GitHub Actions Example

```yaml
# .github/workflows/deploy.yml
name: Deploy CWE ChatBot

on:
  push:
    branches:
      - main        # Production deployment
      - staging     # Staging deployment

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

      - name: Build Docker image
        run: |
          gcloud builds submit --config=apps/chatbot/cloudbuild.yaml

      - name: Deploy to Production
        if: github.ref == 'refs/heads/main'
        run: |
          gcloud run deploy cwe-chatbot \
            --image gcr.io/cwechatbot/cwe-chatbot:${{ github.sha }} \
            --set-env-vars AUTH_MODE=oauth \
            --region us-central1

      - name: Deploy to Staging
        if: github.ref == 'refs/heads/staging'
        run: |
          gcloud run deploy cwe-chatbot-staging \
            --image gcr.io/cwechatbot/cwe-chatbot:${{ github.sha }} \
            --set-env-vars AUTH_MODE=hybrid \
            --region us-central1

      - name: Verify Deployment
        run: |
          if [ "${{ github.ref }}" = "refs/heads/main" ]; then
            ./verify-production.sh
          else
            ./verify-staging.sh
          fi
```

## Troubleshooting

### Issue: test-login returns 404 in staging

**Cause**: AUTH_MODE not set to `hybrid`

**Fix**:
```bash
gcloud run services update cwe-chatbot-staging \
  --set-env-vars AUTH_MODE=hybrid \
  --region us-central1
```

### Issue: test-login accessible in production

**Cause**: AUTH_MODE incorrectly set to `hybrid` in production

**Fix** (IMMEDIATE):
```bash
gcloud run services update cwe-chatbot \
  --set-env-vars AUTH_MODE=oauth \
  --region us-central1
```

### Issue: OAuth not working in hybrid mode

**Cause**: OAuth and hybrid mode are compatible - check OAuth secrets

**Fix**:
```bash
# Verify OAuth secrets are set
gcloud run services describe cwe-chatbot-staging --region us-central1 \
  | grep -A 10 "secrets:"

# Update OAuth secrets if needed
gcloud run services update cwe-chatbot-staging \
  --update-secrets OAUTH_GOOGLE_CLIENT_ID=oauth-google-client-id-staging:latest \
  --region us-central1
```

## Environment Variable Reference

| Variable | Production | Staging | Local Dev | Description |
|----------|-----------|---------|-----------|-------------|
| `AUTH_MODE` | `oauth` | `hybrid` | `hybrid` or `oauth` | Authentication mode |
| `ENABLE_OAUTH` | `true` | `true` | `false` (dev) | Enable OAuth providers |
| `TEST_API_KEY` | ❌ Not set | ✅ Required | ✅ Required | API key for test-login |
| `OAUTH_*_CLIENT_ID` | ✅ Required | ✅ Required | Optional | OAuth provider client ID |
| `OAUTH_*_CLIENT_SECRET` | ✅ Required | ✅ Required | Optional | OAuth provider secret |

## Security Checklist

Before deploying to production:

- [ ] `AUTH_MODE=oauth` (NOT `hybrid`)
- [ ] `ENABLE_OAUTH=true`
- [ ] OAuth secrets configured
- [ ] `TEST_API_KEY` NOT set
- [ ] Verify test-login returns 404
- [ ] OAuth login accessible
- [ ] Health check passes

Before deploying to staging:

- [ ] `AUTH_MODE=hybrid`
- [ ] `ENABLE_OAUTH=true` (optional but recommended)
- [ ] `TEST_API_KEY` secret created
- [ ] OAuth secrets configured (staging)
- [ ] Verify test-login returns 200 with valid key
- [ ] Health check passes

## References

- **Architecture**: `apps/chatbot/tests/HYBRID_AUTH_PATTERN.md`
- **API Implementation**: `apps/chatbot/api.py` (test_login endpoint)
- **Config**: `apps/chatbot/src/app_config.py` (AUTH_MODE setting)
- **Production URL**: https://cwe.crashedmind.com
- **Staging URL**: (varies - check Cloud Run console)
