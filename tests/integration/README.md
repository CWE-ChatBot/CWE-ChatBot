# Integration Tests

This directory contains integration tests for the CWE ChatBot staging environment.

## Test Structure

```
tests/integration/
├── run_staging_tests.sh        # Main test runner for staging deployment
├── test_staging_oauth.sh        # OAuth authentication flow tests
└── README.md                    # This file
```

## Running Tests

### Automated Testing After Deployment

To run integration tests automatically after staging deployment:

```bash
# Deploy with tests enabled
RUN_TESTS=true ./apps/chatbot/deploy_staging.sh
```

**Prerequisites:**
- `GOOGLE_REFRESH_TOKEN` environment variable must be set
- To obtain a refresh token: `./scripts/ops/get_refresh_token_localhost.sh`

### Manual Testing

Run the complete staging integration test suite:

```bash
# Set refresh token first
export GOOGLE_REFRESH_TOKEN='your_token_here'

# Run all tests
./tests/integration/run_staging_tests.sh
```

Run only OAuth flow tests:

```bash
export GOOGLE_REFRESH_TOKEN='your_token_here'
./tests/integration/test_staging_oauth.sh
```

## Test Coverage

### Test 1: Service Deployment Status
- Verifies Cloud Run service is ready and running
- Checks latest revision deployment time
- **Exit code 1 if service not ready**

### Test 2: OAuth Configuration
- Verifies `AUTH_MODE=oauth` (OAuth-only mode)
- Checks OAuth secrets are configured (4+ environment variables)
- **Exit code 1 if misconfigured**

### Test 3: Headless OAuth Authentication Flow
Comprehensive OAuth flow validation:
- **Step 1**: Refresh token → ID token exchange
- **Step 2**: Health endpoint accessibility (no auth required)
- **Step 3**: API rejects unauthenticated requests (401)
- **Step 4**: API accepts OAuth Bearer token (200)
- **Step 5**: Response validation (valid JSON with expected fields)

**Exit code 1 if any OAuth test fails**

## Environment Variables

Required for OAuth tests:
```bash
GOOGLE_REFRESH_TOKEN   # Google OAuth refresh token (required)
```

Optional configuration:
```bash
STAGING_URL            # Staging URL (default: https://staging-cwe.crashedmind.com)
PROJECT                # GCP project (default: cwechatbot)
REGION                 # GCP region (default: us-central1)
```

## Getting a Refresh Token

### Interactive Method (Local Development)

```bash
# 1. Run the localhost OAuth flow
./scripts/ops/get_refresh_token_localhost.sh

# 2. Browser will open for OAuth approval
# 3. After approval, refresh token will be displayed

# 4. Export the token
export GOOGLE_REFRESH_TOKEN='1//09...'

# 5. Run tests
./tests/integration/run_staging_tests.sh
```

### CI/CD Method (Future)

For automated CI/CD pipelines, create a service account with refresh token stored in Secret Manager:

```bash
# Store refresh token in Secret Manager
echo -n "YOUR_REFRESH_TOKEN" | gcloud secrets create google-refresh-token \
  --data-file=- \
  --project=cwechatbot

# In CI/CD, retrieve and export
export GOOGLE_REFRESH_TOKEN=$(gcloud secrets versions access latest \
  --secret=google-refresh-token \
  --project=cwechatbot)
```

## Integration with Deployment Script

The staging deployment script supports automatic test execution:

```bash
# apps/chatbot/deploy_staging.sh

# To enable tests:
RUN_TESTS=true ./apps/chatbot/deploy_staging.sh

# Tests will run after successful deployment
# Deployment will FAIL if tests fail (exit code 1)
```

## Test Output

Successful test run:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Test Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Service deployment: Verified
✓ OAuth configuration: Verified
✓ OAuth flow: Tested and working

✓ Staging integration tests completed successfully!
```

Failed test (example):
```
✗ OAuth authenticated request failed (HTTP 500)
Response: {"error": "Internal server error"}
```

## Troubleshooting

### "GOOGLE_REFRESH_TOKEN not set"
- **Solution**: Run `./tools/get_refresh_token_localhost.sh` and export the token

### "Failed to get ID token"
- **Cause**: Refresh token expired or invalid
- **Solution**: Get a new refresh token using `./tools/get_refresh_token_localhost.sh`

### "Service is not ready"
- **Cause**: Deployment failed or service not responding
- **Solution**: Check Cloud Run logs: `gcloud run services logs read cwe-chatbot-staging`

### "OAuth authenticated request failed (HTTP 401)"
- **Cause**: ID token expired (tokens expire after 1 hour)
- **Solution**: Re-run tests to get a fresh ID token from refresh token

### "redirect_uri_mismatch"
- **Cause**: OAuth app redirect URIs not configured
- **Solution**: Add `http://localhost:8080/` to Google OAuth app redirect URIs

## Related Documentation

- `/tools/get_refresh_token_localhost.sh` - Get OAuth refresh token
- `/tools/pretest_get_id_token.py` - Convert refresh token to ID token
- `/apps/chatbot/deploy_staging.sh` - Staging deployment script
- `/docs/refactor/R14/` - OAuth implementation documentation
