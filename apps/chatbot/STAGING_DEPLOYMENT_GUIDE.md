# CWE ChatBot Staging Deployment Guide

**Secure-by-Default Deployment Strategy**

This guide explains how to deploy and access the hardened staging environment with private-by-default security.

---

## Table of Contents

1. [Security Architecture](#security-architecture)
2. [Deployment Modes](#deployment-modes)
3. [Quick Start](#quick-start)
4. [Access Methods](#access-methods)
5. [Testing Workflows](#testing-workflows)
6. [Troubleshooting](#troubleshooting)

---

## Security Architecture

### Defense-in-Depth Model

The staging deployment implements multiple security layers:

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Cloud Run Ingress Control                             │
│ - PRIVATE: internal-and-cloud-load-balancing (default)         │
│ - PUBLIC: all (requires HTTPS LB + Cloud Armor)                │
└─────────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 2: IAM Authentication (Private Mode)                     │
│ - Requires Cloud Run Invoker role                              │
│ - Granted per user/service account                             │
└─────────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 3: Application Authentication                            │
│ - OAuth (Google/GitHub) for UI access                          │
│ - API_AUTH_MODE=hybrid in staging                              │
│   - OAuth Bearer tokens for production-like testing            │
│   - TEST_API_KEY for automation (staging only)                 │
└─────────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│ Layer 4: Service-to-Service Security                           │
│ - PDF Worker: private, chatbot SA only                         │
│ - OIDC-based service authentication                            │
└─────────────────────────────────────────────────────────────────┘
```

### Security Benefits

**Private Mode (Default)**:
- ✅ No public internet exposure
- ✅ IAM-based access control
- ✅ Defense against DDoS/scraping
- ✅ Audit trail of all access
- ✅ Granular per-user permissions

**Public Mode** (requires HTTPS LB + Cloud Armor):
- ⚠️ Internet-accessible
- ⚠️ Requires additional DDoS protection
- ⚠️ App-level auth only (no IAM layer)

---

## Deployment Modes

### Mode 1: Private Staging (Default - Recommended)

**Security**: ✅ Maximum Security
**Use Case**: Development, QA testing, controlled access

```bash
# Deploy in private mode (default)
./deploy_staging.sh

# OR explicitly
EXPOSURE_MODE=private ./deploy_staging.sh
```

**Characteristics**:
- Service requires IAM authentication
- Only authorized users can access
- URL returns 403 for unauthorized requests
- Perfect for development/testing

**Access Requirements**:
- User must have `roles/run.invoker` on service
- Browser/automation must authenticate with IAM
- TEST_API_KEY bypasses IAM for automation (app-level auth)

---

### Mode 2: Private with Tester Access

**Security**: ✅ Controlled Access
**Use Case**: Grant specific users/groups access for testing

```bash
# Grant access to a specific user
TESTER_PRINCIPAL='user:alice@example.com' ./deploy_staging.sh

# Grant access to a group
TESTER_PRINCIPAL='group:qa-team@example.com' ./deploy_staging.sh

# Grant access to service account (for CI/CD)
TESTER_PRINCIPAL='serviceAccount:ci-bot@project.iam.gserviceaccount.com' ./deploy_staging.sh
```

**What This Does**:
- Deploys in private mode
- Grants Cloud Run Invoker role to specified principal
- User can access via browser with gcloud auth
- Automation can use service account credentials

---

### Mode 3: Public Staging (Use with Caution)

**Security**: ⚠️ Requires Additional Protection
**Use Case**: External testing, public demos (requires HTTPS LB + Cloud Armor)

```bash
# Deploy in public mode (STRONGLY RECOMMEND HTTPS LB + CLOUD ARMOR)
EXPOSURE_MODE=public ./deploy_staging.sh
```

**Characteristics**:
- Service allows unauthenticated HTTP access
- No IAM authentication layer
- Exposed to internet (DDoS, scraping risks)
- Relies solely on app-level OAuth

**Required Protections** (if using public mode):
1. Deploy HTTPS Load Balancer
2. Configure Cloud Armor rate limiting
3. Enable DDoS protection policies
4. Monitor for abuse

---

## Quick Start

### For Developers (Browser Testing)

**Step 1**: Deploy staging with your user access
```bash
# Replace with your email
TESTER_PRINCIPAL='user:your-email@example.com' ./deploy_staging.sh
```

**Step 2**: Access in browser
```bash
# Get staging URL
STAGING_URL=$(gcloud run services describe cwe-chatbot-staging \
  --region=us-central1 \
  --format='value(status.url)')

# Open with browser (will prompt for gcloud auth)
open "$STAGING_URL"
```

**Browser will**:
1. Detect IAM authentication requirement
2. Redirect to gcloud OAuth flow
3. Validate your Cloud Run Invoker permission
4. Forward you to application OAuth (Google/GitHub)

---

### For Automation (API Testing)

**Option 1: Using TEST_API_KEY (Staging Only)**

```bash
# Step 1: Get test API key from Secret Manager
TEST_API_KEY=$(gcloud secrets versions access latest --secret=test-api-key --project=cwechatbot)

# Step 2: Authenticate to get session cookie
STAGING_URL=$(gcloud run services describe cwe-chatbot-staging \
  --region=us-central1 \
  --format='value(status.url)')

curl -X POST "$STAGING_URL/api/v1/test-login" \
  -H "X-API-Key: $TEST_API_KEY" \
  -c cookies.txt

# Step 3: Use session cookie for API calls
curl -X POST "$STAGING_URL/api/v1/query" \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What is CWE-89?",
    "persona": "DEVELOPER",
    "max_results": 5
  }'
```

**Option 2: Using Service Account (IAM + API Key)**

```bash
# Step 1: Create service account with Cloud Run Invoker role
gcloud iam service-accounts create staging-tester \
  --display-name="Staging Test Automation"

# Grant Cloud Run Invoker
gcloud run services add-iam-policy-binding cwe-chatbot-staging \
  --region=us-central1 \
  --member="serviceAccount:staging-tester@cwechatbot.iam.gserviceaccount.com" \
  --role="roles/run.invoker"

# Step 2: Get identity token
TOKEN=$(gcloud auth print-identity-token \
  --impersonate-service-account=staging-tester@cwechatbot.iam.gserviceaccount.com \
  --audiences="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app")

# Step 3: Authenticate with TEST_API_KEY
TEST_API_KEY=$(gcloud secrets versions access latest --secret=test-api-key)

curl -X POST "https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app/api/v1/test-login" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-API-Key: $TEST_API_KEY" \
  -c cookies.txt

# Step 4: Use session cookie
curl -X POST "https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app/api/v1/query" \
  -H "Authorization: Bearer $TOKEN" \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"query": "What is SQL injection?", "persona": "DEVELOPER"}'
```

---

## Access Methods

### Method 1: Browser Access (Manual Testing)

**Prerequisites**:
- IAM permission: `roles/run.invoker` on service
- gcloud CLI authenticated

**Access Steps**:

```bash
# 1. Ensure you have access
gcloud run services add-iam-policy-binding cwe-chatbot-staging \
  --region=us-central1 \
  --member="user:$(gcloud config get-value account)" \
  --role="roles/run.invoker"

# 2. Get staging URL
STAGING_URL=$(gcloud run services describe cwe-chatbot-staging \
  --region=us-central1 \
  --format='value(status.url)')

# 3. Open in browser
echo "Opening: $STAGING_URL"
open "$STAGING_URL"  # macOS
# xdg-open "$STAGING_URL"  # Linux
# start "$STAGING_URL"  # Windows
```

**Authentication Flow**:
1. Browser hits Cloud Run service
2. Cloud Run checks IAM permission
3. If no permission: 403 Forbidden
4. If permission granted: Forward to app
5. App requires OAuth (Google/GitHub)
6. User logs in via OAuth
7. Session established

---

### Method 2: Python Playwright (Headless Browser Testing)

**Install Dependencies**:
```bash
pip install playwright google-auth
playwright install chromium
```

**Test Script** (`test_staging_playwright.py`):
```python
#!/usr/bin/env python3
"""
Playwright test for staging environment with IAM authentication.
"""
import asyncio
import subprocess
from playwright.async_api import async_playwright

async def get_iam_token():
    """Get IAM identity token for staging service."""
    result = subprocess.run(
        [
            "gcloud", "auth", "print-identity-token",
            "--audiences=https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app"
        ],
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout.strip()

async def test_staging():
    """Test staging environment with Playwright."""
    # Get IAM token
    token = await get_iam_token()

    async with async_playwright() as p:
        # Launch browser
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()

        # Add IAM token to all requests
        await context.set_extra_http_headers({
            "Authorization": f"Bearer {token}"
        })

        # Navigate to staging
        page = await context.new_page()
        await page.goto("https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app")

        # Wait for OAuth login page or app
        await page.wait_for_load_state("networkidle")

        # Check if we reached the app or OAuth page
        title = await page.title()
        print(f"Page title: {title}")

        # If OAuth required, you can programmatically login:
        # await page.click('button[aria-label="Sign in with Google"]')
        # ... handle OAuth flow ...

        # Take screenshot
        await page.screenshot(path="staging_test.png")
        print("Screenshot saved: staging_test.png")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(test_staging())
```

**Run Test**:
```bash
python3 test_staging_playwright.py
```

---

### Method 3: Puppeteer (Node.js Headless Testing)

**Install Dependencies**:
```bash
npm install puppeteer
```

**Test Script** (`test_staging_puppeteer.js`):
```javascript
#!/usr/bin/env node
/**
 * Puppeteer test for staging environment with IAM authentication.
 */
const puppeteer = require('puppeteer');
const { exec } = require('child_process');
const util = require('util');

const execPromise = util.promisify(exec);

async function getIAMToken() {
  const { stdout } = await execPromise(
    'gcloud auth print-identity-token --audiences=https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app'
  );
  return stdout.trim();
}

async function testStaging() {
  // Get IAM token
  const token = await getIAMToken();

  // Launch browser
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();

  // Add IAM token to all requests
  await page.setExtraHTTPHeaders({
    'Authorization': `Bearer ${token}`
  });

  // Navigate to staging
  await page.goto('https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app', {
    waitUntil: 'networkidle2'
  });

  // Get page title
  const title = await page.title();
  console.log(`Page title: ${title}`);

  // Take screenshot
  await page.screenshot({ path: 'staging_test.png' });
  console.log('Screenshot saved: staging_test.png');

  await browser.close();
}

testStaging().catch(console.error);
```

**Run Test**:
```bash
node test_staging_puppeteer.js
```

---

### Method 4: curl with IAM Token (API Testing)

**Basic API Access**:
```bash
# Get IAM identity token
TOKEN=$(gcloud auth print-identity-token \
  --audiences="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app")

# Step 1: Authenticate with TEST_API_KEY to get session
TEST_API_KEY=$(gcloud secrets versions access latest --secret=test-api-key)

curl -X POST https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app/api/v1/test-login \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-API-Key: $TEST_API_KEY" \
  -c cookies.txt \
  -v

# Step 2: Use session cookie for API queries
curl -X POST https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app/api/v1/query \
  -H "Authorization: Bearer $TOKEN" \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What is CWE-79?",
    "persona": "DEVELOPER",
    "max_results": 5
  }' | jq .
```

**Health Check**:
```bash
TOKEN=$(gcloud auth print-identity-token \
  --audiences="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app")

curl -H "Authorization: Bearer $TOKEN" \
  https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app/health
```

---

## Testing Workflows

### Workflow 1: Developer Feature Testing

**Scenario**: Test new chatbot feature in staging before production

```bash
# 1. Deploy staging with your access
TESTER_PRINCIPAL="user:$(gcloud config get-value account)" ./deploy_staging.sh

# 2. Open in browser
STAGING_URL=$(gcloud run services describe cwe-chatbot-staging \
  --region=us-central1 --format='value(status.url)')
open "$STAGING_URL"

# 3. Login with Google/GitHub OAuth
# 4. Test feature manually in UI
# 5. Check logs for errors
gcloud logging read "resource.type=cloud_run_revision \
  resource.labels.service_name=cwe-chatbot-staging \
  severity>=WARNING" --limit=50
```

---

### Workflow 2: Automated API Testing (CI/CD)

**Scenario**: Run automated API tests in CI pipeline

```bash
#!/bin/bash
# ci_test_staging.sh

set -euo pipefail

# Get service URL
STAGING_URL=$(gcloud run services describe cwe-chatbot-staging \
  --region=us-central1 --format='value(status.url)')

# Get IAM token (CI service account)
TOKEN=$(gcloud auth print-identity-token \
  --impersonate-service-account=ci-bot@cwechatbot.iam.gserviceaccount.com \
  --audiences="$STAGING_URL")

# Get test API key
TEST_API_KEY=$(gcloud secrets versions access latest --secret=test-api-key)

# Authenticate
curl -X POST "$STAGING_URL/api/v1/test-login" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-API-Key: $TEST_API_KEY" \
  -c cookies.txt \
  --fail-with-body

# Run test queries
for cwe in "CWE-79" "CWE-89" "CWE-78"; do
  echo "Testing: $cwe"

  RESPONSE=$(curl -X POST "$STAGING_URL/api/v1/query" \
    -H "Authorization: Bearer $TOKEN" \
    -b cookies.txt \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"What is $cwe?\", \"persona\": \"DEVELOPER\"}" \
    --fail-with-body)

  # Validate response
  if echo "$RESPONSE" | jq -e '.cwes | length > 0' >/dev/null; then
    echo "✓ $cwe query successful"
  else
    echo "✗ $cwe query failed"
    exit 1
  fi
done

echo "All tests passed!"
```

---

### Workflow 3: Security Testing

**Scenario**: Verify security controls in staging

```bash
#!/bin/bash
# security_test_staging.sh

# Test 1: Verify IAM protection (should fail without token)
echo "Test 1: Unauthenticated access (expect 403)"
curl -s -o /dev/null -w "%{http_code}" \
  https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app | grep -q 403 && \
  echo "✓ IAM protection working" || echo "✗ IAM bypass detected!"

# Test 2: Verify TEST_API_KEY required (should fail without key)
echo "Test 2: API key requirement (expect 401)"
TOKEN=$(gcloud auth print-identity-token \
  --audiences="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app")

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app/api/v1/test-login \
  -H "Authorization: Bearer $TOKEN")

if [[ "$HTTP_CODE" == "401" ]]; then
  echo "✓ API key protection working"
else
  echo "✗ API key bypass detected!"
fi

# Test 3: Verify rate limiting
echo "Test 3: Rate limiting (send 100 requests)"
# ... rate limit testing ...

echo "Security tests complete"
```

---

## Troubleshooting

### Problem: 403 Forbidden in Browser

**Symptom**:
```
Error: Forbidden
Your client does not have permission to get URL / from this server.
```

**Cause**: Missing Cloud Run Invoker permission

**Solution**:
```bash
# Grant yourself access
gcloud run services add-iam-policy-binding cwe-chatbot-staging \
  --region=us-central1 \
  --member="user:$(gcloud config get-value account)" \
  --role="roles/run.invoker"

# Verify permission
gcloud run services get-iam-policy cwe-chatbot-staging --region=us-central1
```

---

### Problem: curl Returns 403

**Symptom**:
```bash
curl https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app
# Returns: 403 Forbidden
```

**Cause**: Missing IAM token in request

**Solution**:
```bash
# Add Authorization header with IAM token
TOKEN=$(gcloud auth print-identity-token \
  --audiences="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app")

curl -H "Authorization: Bearer $TOKEN" \
  https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app
```

---

### Problem: TEST_API_KEY Not Working

**Symptom**:
```bash
curl -X POST .../api/v1/test-login -H "X-API-Key: $TEST_API_KEY"
# Returns: 401 Unauthorized
```

**Possible Causes**:
1. Wrong API key value
2. Missing IAM token
3. API_AUTH_MODE not set to hybrid

**Solution**:
```bash
# Verify API key
gcloud secrets versions access latest --secret=test-api-key

# Verify environment variable
gcloud run services describe cwe-chatbot-staging \
  --region=us-central1 \
  --format='yaml(spec.template.spec.containers[0].env)' | grep API_AUTH_MODE

# Should show: API_AUTH_MODE=hybrid

# Ensure IAM token included
TOKEN=$(gcloud auth print-identity-token \
  --audiences="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app")

curl -X POST https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app/api/v1/test-login \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-API-Key: $TEST_API_KEY"
```

---

### Problem: Playwright/Puppeteer Hangs

**Symptom**: Browser automation hangs waiting for page load

**Cause**: OAuth redirect or IAM auth not handled

**Solution**:
```python
# Add longer timeout
await page.goto(url, timeout=60000)  # 60 seconds

# OR handle OAuth programmatically
if "accounts.google.com" in page.url:
    # Automate OAuth login
    await page.fill('input[type="email"]', 'test@example.com')
    await page.click('#next')
    # ... handle password ...
```

---

### Problem: Service Account Impersonation Fails

**Symptom**:
```
ERROR: (gcloud.auth.print-identity-token) PERMISSION_DENIED:
Permission 'iam.serviceAccounts.getAccessToken' denied
```

**Cause**: User doesn't have permission to impersonate service account

**Solution**:
```bash
# Grant yourself Service Account Token Creator role
gcloud iam service-accounts add-iam-policy-binding \
  staging-tester@cwechatbot.iam.gserviceaccount.com \
  --member="user:$(gcloud config get-value account)" \
  --role="roles/iam.serviceAccountTokenCreator"

# Retry
TOKEN=$(gcloud auth print-identity-token \
  --impersonate-service-account=staging-tester@cwechatbot.iam.gserviceaccount.com \
  --audiences="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app")
```

---

## Security Best Practices

### ✅ DO

1. **Use Private Mode** for staging by default
2. **Grant Least Privilege** - only give access to users who need it
3. **Use Service Accounts** for CI/CD automation
4. **Rotate TEST_API_KEY** regularly (quarterly minimum)
5. **Monitor Access Logs** for unauthorized attempts
6. **Use TEST_API_KEY only in staging** - never in production

### ❌ DON'T

1. **Don't use public mode** without HTTPS LB + Cloud Armor
2. **Don't share TEST_API_KEY** publicly (Secret Manager only)
3. **Don't grant `allUsers` or `allAuthenticatedUsers`** Cloud Run Invoker
4. **Don't deploy staging with production data** (use test data only)
5. **Don't skip IAM authentication** - it's your first defense layer

---

## Migration Path to Production

When promoting from staging to production:

1. **Change AUTH_MODE**:
   - Staging: `AUTH_MODE=hybrid` (OAuth + TEST_API_KEY)
   - Production: `AUTH_MODE=oauth` (OAuth only, no test bypass)

2. **Change API_AUTH_MODE**:
   - Staging: `API_AUTH_MODE=hybrid`
   - Production: `API_AUTH_MODE=oauth` (Bearer tokens only)

3. **Remove TEST_API_KEY**:
   - Don't include `TEST_API_KEY` secret in production deployment

4. **Tighten CSP**:
   - Staging: `CSP_MODE=strict` (already set in hardened script)
   - Production: `CSP_MODE=strict`

5. **Review IAM Permissions**:
   - Production should have minimal invoker permissions
   - Consider using HTTPS LB + Cloud Armor for public production

---

## Reference

### Environment Variables

| Variable | Staging Value | Production Value | Description |
|----------|---------------|------------------|-------------|
| `EXPOSURE_MODE` | `private` | `private` | Cloud Run ingress control |
| `AUTH_MODE` | `hybrid` | `oauth` | Application auth mode |
| `API_AUTH_MODE` | `hybrid` | `oauth` | API authentication mode |
| `CSP_MODE` | `strict` | `strict` | Content Security Policy |
| `ENABLE_OAUTH` | `true` | `true` | Enable OAuth providers |

### Deployment Commands Summary

```bash
# Private staging (default)
./deploy_staging.sh

# Private staging with user access
TESTER_PRINCIPAL='user:you@example.com' ./deploy_staging.sh

# Public staging (requires LB + Cloud Armor)
EXPOSURE_MODE=public ./deploy_staging.sh

# Custom VPC connector
VPC_CONNECTOR=custom-connector ./deploy_staging.sh
```

### IAM Roles Reference

| Role | Purpose | Grant To |
|------|---------|----------|
| `roles/run.invoker` | Access Cloud Run service | End users, test accounts |
| `roles/iam.serviceAccountTokenCreator` | Impersonate service accounts | CI/CD users |
| `roles/secretmanager.secretAccessor` | Read TEST_API_KEY | CI/CD service accounts |

---

## Support

For issues or questions:
- **Security Issues**: Report to security team
- **Deployment Issues**: Check Cloud Run logs
- **IAM Issues**: Verify permissions with `gcloud run services get-iam-policy`
- **API Issues**: Check application logs for authentication errors

---

**Last Updated**: 2025-10-15
**Script Version**: 2.0 (Security Hardened)
**Deployment**: `apps/chatbot/deploy_staging.sh`
