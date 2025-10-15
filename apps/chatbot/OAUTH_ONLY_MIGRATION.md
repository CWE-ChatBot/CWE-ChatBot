# OAuth-Only Staging Migration Guide

**Unified Authentication: Staging = Production**

This guide explains the transition from hybrid authentication (OAuth + TEST_API_KEY) to OAuth-only authentication in staging, achieving production parity.

---

## What Changed

### Before (Hybrid Mode)
```bash
# Staging had dual authentication:
AUTH_MODE=hybrid
API_AUTH_MODE=hybrid

# Two ways to authenticate:
1. OAuth (Google/GitHub) - production-like
2. TEST_API_KEY - staging-only bypass for automation
```

### After (OAuth-Only Mode)
```bash
# Staging now matches production:
AUTH_MODE=oauth
API_AUTH_MODE=oauth

# Single authentication method:
1. OAuth (Google/GitHub) - same as production
```

---

## Why This Change?

### Production Parity
- **Before**: Staging behaved differently than production (had TEST_API_KEY bypass)
- **After**: Staging authentication is identical to production
- **Benefit**: Catch OAuth-related issues before production deployment

### Security Improvements
- **Eliminates staging-specific bypass**: No TEST_API_KEY secret to manage
- **Real OAuth testing**: All automation uses actual OAuth tokens
- **Unified security model**: Same authentication everywhere
- **Audit trail**: All access tied to OAuth user identity

### Simplified Operations
- **Fewer secrets**: No need to rotate TEST_API_KEY
- **Fewer code paths**: Remove hybrid authentication logic
- **Clearer security model**: OAuth everywhere, no exceptions

---

## Migration Impact

### ✅ No Impact (Still Works)

#### Browser Testing
```bash
# Grant yourself access
TESTER_PRINCIPAL='user:your-email@example.com' ./deploy_staging.sh

# Open in browser - OAuth login works as before
open "$(gcloud run services describe cwe-chatbot-staging --region=us-central1 --format='value(status.url)')"
```

**No change**: Browser users still authenticate via OAuth (Google/GitHub)

---

### ⚠️ Requires Changes (Automation)

#### Old Approach (TEST_API_KEY - No Longer Works)
```bash
# ❌ THIS NO LONGER WORKS
TEST_API_KEY=$(gcloud secrets versions access latest --secret=test-api-key)

curl -X POST "$STAGING_URL/api/v1/test-login" \
  -H "X-API-Key: $TEST_API_KEY"
# Returns: 404 Not Found (endpoint disabled in oauth mode)
```

#### New Approach (OAuth Tokens - Required)
```bash
# ✅ USE THIS INSTEAD
# Option 1: Device flow token (for scripts)
# Option 2: Service account impersonation (for CI/CD)
# Option 3: User OAuth token from browser
```

---

## New Authentication Methods

### Method 1: OAuth Device Flow (Recommended for Scripts)

**Use Case**: Local development, manual API testing

```bash
#!/bin/bash
# get_oauth_token.sh - Get OAuth token for API access

# Google OAuth Device Flow
echo "Authenticating with Google OAuth..."
gcloud auth application-default login --scopes=openid,email,profile

# Get ID token
TOKEN=$(gcloud auth application-default print-access-token)

# Use token for API calls
STAGING_URL=$(gcloud run services describe cwe-chatbot-staging \
  --region=us-central1 --format='value(status.url)')

# Step 1: Get Cloud Run IAM token
IAM_TOKEN=$(gcloud auth print-identity-token --audiences="$STAGING_URL")

# Step 2: Call API with OAuth token
curl -X POST "$STAGING_URL/api/v1/query" \
  -H "Authorization: Bearer $IAM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What is CWE-89?",
    "persona": "DEVELOPER",
    "max_results": 5
  }'
```

**How It Works**:
1. User authenticates via browser OAuth flow
2. gcloud stores credentials locally
3. Script mints tokens from stored credentials
4. Tokens valid for 1 hour (auto-refresh)

---

### Method 2: Service Account (Recommended for CI/CD)

**Use Case**: Automated testing, CI/CD pipelines

**Setup (One-Time)**:
```bash
# Create service account for CI/CD
gcloud iam service-accounts create staging-ci-bot \
  --display-name="Staging CI/CD Bot"

# Grant Cloud Run Invoker
gcloud run services add-iam-policy-binding cwe-chatbot-staging \
  --region=us-central1 \
  --member="serviceAccount:staging-ci-bot@cwechatbot.iam.gserviceaccount.com" \
  --role="roles/run.invoker"

# Grant OAuth access (for app-level auth)
# This service account needs OAuth credentials configured
```

**Usage in CI/CD**:
```bash
#!/bin/bash
# ci_test_staging.sh

STAGING_URL="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app"
SA_EMAIL="staging-ci-bot@cwechatbot.iam.gserviceaccount.com"

# Get Cloud Run IAM token (for service access)
IAM_TOKEN=$(gcloud auth print-identity-token \
  --impersonate-service-account="$SA_EMAIL" \
  --audiences="$STAGING_URL")

# For API calls, you'll need OAuth token
# Option 1: Configure service account with OAuth (recommended)
# Option 2: Use user credentials (gcloud auth login)

# Make API call
curl -X POST "$STAGING_URL/api/v1/query" \
  -H "Authorization: Bearer $IAM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "test", "persona": "DEVELOPER"}'
```

---

### Method 3: Extract OAuth Token from Browser (Manual Testing)

**Use Case**: Quick API testing with your own credentials

**Steps**:

1. **Login to staging in browser**:
   ```bash
   open "$(gcloud run services describe cwe-chatbot-staging --region=us-central1 --format='value(status.url)')"
   ```

2. **Complete OAuth login** (Google or GitHub)

3. **Extract session cookie** from browser:
   - Open DevTools (F12)
   - Go to Application → Cookies
   - Copy `chainlit-session` cookie value

4. **Use session cookie for API calls**:
   ```bash
   STAGING_URL="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app"
   IAM_TOKEN=$(gcloud auth print-identity-token --audiences="$STAGING_URL")
   SESSION_COOKIE="<paste-from-browser>"

   curl -X POST "$STAGING_URL/api/v1/query" \
     -H "Authorization: Bearer $IAM_TOKEN" \
     -H "Cookie: chainlit-session=$SESSION_COOKIE" \
     -H "Content-Type: application/json" \
     -d '{"query": "What is XSS?", "persona": "DEVELOPER"}'
   ```

---

## Headless Testing Updates

### Playwright (Python)

**Updated Script**:
```python
#!/usr/bin/env python3
"""
Playwright test for OAuth-only staging environment.
"""
import asyncio
import subprocess
from playwright.async_api import async_playwright

async def get_iam_token(staging_url):
    """Get Cloud Run IAM identity token."""
    result = subprocess.run(
        [
            "gcloud", "auth", "print-identity-token",
            f"--audiences={staging_url}"
        ],
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout.strip()

async def test_staging_oauth():
    """
    Test staging with OAuth authentication.

    Note: For full automation, configure service account with OAuth,
    or use gcloud auth application-default login for user credentials.
    """
    staging_url = "https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app"

    # Get Cloud Run IAM token
    iam_token = await get_iam_token(staging_url)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)  # Non-headless to see OAuth flow
        context = await browser.new_context()

        # Add Cloud Run IAM token
        await context.set_extra_http_headers({
            "Authorization": f"Bearer {iam_token}"
        })

        page = await context.new_page()
        await page.goto(staging_url)

        # Wait for OAuth redirect or app to load
        await page.wait_for_load_state("networkidle")

        # Check if we hit OAuth login
        if "accounts.google.com" in page.url or "github.com/login" in page.url:
            print("OAuth login required - authenticate manually or use stored credentials")

            # Option 1: Manual login (for first-time setup)
            # User completes OAuth in browser
            await page.wait_for_url(staging_url + "/**", timeout=60000)

            # Option 2: Programmatic login (requires credentials)
            # await handle_google_oauth(page, email, password)

        # After OAuth, extract session cookie for API calls
        cookies = await context.cookies()
        session_cookie = next(
            (c for c in cookies if c['name'] == 'chainlit-session'),
            None
        )

        if session_cookie:
            print(f"Session cookie: {session_cookie['value'][:20]}...")

            # Now can make API calls with session cookie
            response = await page.request.post(
                f"{staging_url}/api/v1/query",
                headers={
                    "Authorization": f"Bearer {iam_token}",
                    "Content-Type": "application/json"
                },
                data={
                    "query": "What is CWE-79?",
                    "persona": "DEVELOPER",
                    "max_results": 5
                }
            )

            print(f"API response status: {response.status}")
            result = await response.json()
            print(f"CWEs found: {len(result.get('cwes', []))}")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(test_staging_oauth())
```

**Key Changes**:
- Removed TEST_API_KEY authentication
- Uses OAuth session cookies after login
- Can automate OAuth flow with stored credentials
- Cloud Run IAM token still required for service access

---

### Puppeteer (Node.js)

**Updated Script**:
```javascript
#!/usr/bin/env node
/**
 * Puppeteer test for OAuth-only staging environment.
 */
const puppeteer = require('puppeteer');
const { exec } = require('child_process');
const util = require('util');

const execPromise = util.promisify(exec);

async function getIAMToken(stagingUrl) {
  const { stdout } = await execPromise(
    `gcloud auth print-identity-token --audiences=${stagingUrl}`
  );
  return stdout.trim();
}

async function testStagingOAuth() {
  const stagingUrl = 'https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app';

  // Get Cloud Run IAM token
  const iamToken = await getIAMToken(stagingUrl);

  // Launch browser (non-headless to see OAuth)
  const browser = await puppeteer.launch({ headless: false });
  const page = await browser.newPage();

  // Add Cloud Run IAM token to requests
  await page.setExtraHTTPHeaders({
    'Authorization': `Bearer ${iamToken}`
  });

  // Navigate to staging
  await page.goto(stagingUrl, { waitUntil: 'networkidle2' });

  // Check if OAuth login required
  const currentUrl = page.url();
  if (currentUrl.includes('accounts.google.com') || currentUrl.includes('github.com')) {
    console.log('OAuth login required - authenticate manually');

    // Wait for OAuth completion (user logs in)
    await page.waitForNavigation({
      url: url => url.startsWith(stagingUrl),
      timeout: 60000
    });
  }

  // Extract session cookie
  const cookies = await page.cookies();
  const sessionCookie = cookies.find(c => c.name === 'chainlit-session');

  if (sessionCookie) {
    console.log(`Session cookie: ${sessionCookie.value.substring(0, 20)}...`);

    // Make API call with session
    const response = await page.evaluate(async (url, token, cookie) => {
      const res = await fetch(`${url}/api/v1/query`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'Cookie': `chainlit-session=${cookie}`
        },
        body: JSON.stringify({
          query: 'What is SQL injection?',
          persona: 'DEVELOPER',
          max_results: 5
        })
      });
      return res.json();
    }, stagingUrl, iamToken, sessionCookie.value);

    console.log(`API response:`, response);
  }

  await browser.close();
}

testStagingOAuth().catch(console.error);
```

---

## Troubleshooting

### Problem: API Returns 401 Unauthorized

**Old Error** (when using TEST_API_KEY):
```json
{
  "detail": "Invalid API key"
}
```

**New Behavior** (OAuth-only):
```json
{
  "detail": "Not authenticated - OAuth session required"
}
```

**Solution**: Use OAuth authentication instead of API key

```bash
# Get OAuth session via browser login
# Then use session cookie for API calls

# OR use gcloud auth for programmatic access
gcloud auth application-default login
TOKEN=$(gcloud auth application-default print-access-token)
```

---

### Problem: /api/v1/test-login Returns 404

**Symptom**:
```bash
curl -X POST "$STAGING_URL/api/v1/test-login" -H "X-API-Key: $KEY"
# Returns: 404 Not Found
```

**Cause**: `test-login` endpoint only exists in `AUTH_MODE=hybrid`, disabled in `oauth` mode

**Solution**: Endpoint removed - use OAuth login flow instead

```bash
# Instead of test-login endpoint:
# 1. Login via browser OAuth
# 2. Extract session cookie
# 3. Use cookie for API calls

# OR use gcloud auth for programmatic tokens
```

---

### Problem: CI/CD Pipeline Breaks

**Symptom**: Automated tests fail with authentication errors

**Old CI Script** (TEST_API_KEY - broken):
```bash
# ❌ NO LONGER WORKS
TEST_API_KEY=$(gcloud secrets versions access latest --secret=test-api-key)
curl -X POST "$URL/api/v1/test-login" -H "X-API-Key: $TEST_API_KEY"
```

**New CI Script** (OAuth - required):
```bash
# ✅ UPDATED APPROACH

# Option 1: Service account with OAuth
SA_EMAIL="staging-ci-bot@cwechatbot.iam.gserviceaccount.com"
IAM_TOKEN=$(gcloud auth print-identity-token \
  --impersonate-service-account="$SA_EMAIL" \
  --audiences="$STAGING_URL")

# Make API calls with IAM token
curl -X POST "$STAGING_URL/api/v1/query" \
  -H "Authorization: Bearer $IAM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "test"}'

# Option 2: gcloud auth application-default (for GitHub Actions)
# Configure gcloud auth in CI environment
# Use gcloud auth application-default print-access-token
```

---

## Production Migration Checklist

Staging is now production-ready! Here's the migration path:

### ✅ Already Complete (Staging = Production)

- [x] `AUTH_MODE=oauth` (no hybrid mode)
- [x] `API_AUTH_MODE=oauth` (no API key bypass)
- [x] `CSP_MODE=strict` (strict Content Security Policy)
- [x] Private ingress with IAM authentication
- [x] OAuth-only authentication (Google + GitHub)
- [x] No TEST_API_KEY dependency

### 🚀 Production Deployment

**Deploy script** (`deploy_production.sh`):
```bash
#!/usr/bin/env bash
# Production deployment - identical config to staging

# Same auth settings as staging (now OAuth-only)
AUTH_MODE=oauth
API_AUTH_MODE=oauth
CSP_MODE=strict
EXPOSURE_MODE=private  # Keep private unless using HTTPS LB

# Deploy with same security model
# ... (same as deploy_staging.sh but with production service name)
```

**No Configuration Changes Needed**:
- Authentication: Already OAuth-only ✅
- Security: Already production-grade ✅
- Ingress: Already private by default ✅

---

## Rollback Plan (If Needed)

If you need to temporarily revert to hybrid mode:

```bash
# Re-enable hybrid mode (NOT RECOMMENDED)
API_AUTH_MODE=hybrid ./deploy_staging.sh

# This will:
# - Set AUTH_MODE=oauth (still OAuth for UI)
# - Set API_AUTH_MODE=hybrid (allows TEST_API_KEY for API)
# - Re-enable /api/v1/test-login endpoint
# - Restore TEST_API_KEY secret mount
```

**Why Not Recommended**:
- Creates production parity gap
- Maintains staging-specific bypass code
- Requires TEST_API_KEY secret management
- Delays OAuth automation implementation

**Better Approach**: Fix automation to use OAuth instead

---

## Benefits of OAuth-Only

### Security
- ✅ No staging-specific bypass to compromise
- ✅ All access tied to real user identities
- ✅ Unified audit trail (OAuth user in all logs)
- ✅ Fewer secrets to manage and rotate

### Operations
- ✅ Staging behavior identical to production
- ✅ Catch OAuth issues before production
- ✅ Simplified authentication code (no hybrid logic)
- ✅ Easier to reason about security model

### Development
- ✅ Real OAuth testing in staging
- ✅ Learn OAuth automation early (before production)
- ✅ Better documentation (single auth method)
- ✅ Clearer error messages (no hybrid confusion)

---

## Next Steps

1. **Update automation scripts** to use OAuth instead of TEST_API_KEY
2. **Test OAuth flows** in staging (device flow, service accounts)
3. **Document OAuth automation** for your team
4. **Remove TEST_API_KEY secret** (if no longer used)
5. **Deploy to production** with confidence (same config as staging)

---

## Support

### OAuth Authentication Help
- **Device Flow**: `gcloud auth application-default login`
- **Service Accounts**: Create with `roles/run.invoker`
- **Browser Sessions**: Extract `chainlit-session` cookie
- **Headless Testing**: See Playwright/Puppeteer examples above

### Deployment Issues
- **Check auth mode**: `gcloud run services describe cwe-chatbot-staging --format='yaml' | grep AUTH_MODE`
- **Verify IAM access**: `gcloud run services get-iam-policy cwe-chatbot-staging --region=us-central1`
- **Check logs**: `gcloud logging read "resource.labels.service_name=cwe-chatbot-staging" --limit=50`

---

**Last Updated**: 2025-10-15
**Migration**: Hybrid → OAuth-Only
**Status**: ✅ Complete
