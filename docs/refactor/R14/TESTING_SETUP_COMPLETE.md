# Staging Integration Test Setup - Complete

**Date**: October 16, 2025
**Status**: ✅ Complete and Verified

## Summary

Successfully implemented automated integration testing for the CWE ChatBot staging environment with OAuth-only authentication. Tests can now run automatically after deployment or manually on-demand.

## What Was Implemented

### 1. Test Organization ✅

Reorganized test scripts into proper structure:

```
tests/integration/
├── run_staging_tests.sh        # Main test runner (NEW)
├── test_staging_oauth.sh        # OAuth flow tests (moved from tools/)
└── README.md                    # Complete test documentation (NEW)

tools/
├── get_refresh_token_localhost.sh   # OAuth token acquisition
└── pretest_get_id_token.py          # Token refresh helper (enhanced with debug output)
```

**Key Changes:**
- Moved `tools/test_staging_oauth.sh` → `tests/integration/test_staging_oauth.sh`
- Created comprehensive test runner: `tests/integration/run_staging_tests.sh`
- Made scripts work from any directory (auto-detect project root)
- Fixed Python environment (use `poetry run python` instead of system `python3`)

### 2. Deployment Script Integration ✅

Updated `apps/chatbot/deploy_staging.sh` to support automated testing:

```bash
# Deploy with tests enabled
RUN_TESTS=true ./apps/chatbot/deploy_staging.sh

# Deploy without tests (default)
./apps/chatbot/deploy_staging.sh
```

**Features:**
- Optional test execution via `RUN_TESTS=true` environment variable
- Tests run automatically after successful deployment
- Deployment **fails** if tests fail (exit code 1)
- Graceful handling when `GOOGLE_REFRESH_TOKEN` not set (skips OAuth tests)

### 3. Comprehensive Test Coverage ✅

#### Test 1: Service Deployment Status
- Verifies Cloud Run service is ready
- Checks latest revision and deployment time
- Validates service health

#### Test 2: OAuth Configuration
- Verifies `AUTH_MODE=oauth` (OAuth-only mode)
- Counts OAuth secrets (4+ environment variables)
- Ensures production parity

#### Test 3: Headless OAuth Authentication Flow
- **Step 1**: Refresh token → ID token exchange
- **Step 2**: Health endpoint (no auth required)
- **Step 3**: API rejects unauthenticated requests (401)
- **Step 4**: API accepts OAuth Bearer token (200)
- **Step 5**: Response validation (valid JSON)

**All tests passing in staging environment! ✅**

## Resolved Issues

### Issue 1: Script Hanging During Token Refresh ❌ → ✅
**Problem**: `test_staging_oauth.sh` hung at "Step 1: Getting ID token from refresh token..."

**Root Cause**: Script used `python3` but `google-auth` package only available in Poetry environment

**Solution**:
- Changed to `poetry run python scripts/ops/pretest_get_id_token.py`
- Added debug output to identify hanging points
- Added 30-second timeout with helpful error messages

### Issue 2: Missing google-auth Package ❌ → ✅
**Problem**: `ModuleNotFoundError: No module named 'google.oauth2'`

**Solution**: Use Poetry environment which has `google-auth` already installed

### Issue 3: Path Issues After Moving Script ❌ → ✅
**Problem**: After moving test script to `tests/integration/`, tool paths broke

**Solution**: Auto-detect project root and change to it before running tools:
```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"
```

### Issue 4: AUTH_MODE Check Failing ❌ → ✅
**Problem**: gcloud `--format` query couldn't extract nested environment variables

**Solution**: Use JSON output with jq:
```bash
AUTH_MODE=$(gcloud run services describe "$SERVICE" \
  --format=json | jq -r '.spec.template.spec.containers[0].env[] | select(.name=="AUTH_MODE") | .value')
```

## Usage Examples

### Deploy and Test Automatically

```bash
# Export refresh token (one-time setup)
export GOOGLE_REFRESH_TOKEN='1//09...'

# Deploy with tests
RUN_TESTS=true ./apps/chatbot/deploy_staging.sh

# Output:
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   Running Integration Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ✓ Service deployment: Verified
# ✓ OAuth configuration: Verified
# ✓ OAuth flow: Tested and working
# ✓ Staging integration tests completed successfully!
```

### Run Tests Manually

```bash
# Get refresh token (one-time)
./scripts/ops/get_refresh_token_localhost.sh
# ... follow browser OAuth flow ...
# Copy and export the token

export GOOGLE_REFRESH_TOKEN='1//09...'

# Run all tests
./tests/integration/run_staging_tests.sh
```

### Run Only OAuth Tests

```bash
export GOOGLE_REFRESH_TOKEN='1//09...'
./tests/integration/test_staging_oauth.sh
```

## Test Results (Verified)

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Staging Integration Test Suite
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Environment:
  Project:      cwechatbot
  Region:       us-central1
  Service:      cwe-chatbot-staging
  Staging URL:  https://staging-cwe.crashedmind.com

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Test 1: Service Deployment Status
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Service is ready and running
✓ Latest revision: cwe-chatbot-staging-00030-6g9
✓ Deployed at: 2025-10-16T10:00:31.842865Z

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Test 2: OAuth Configuration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ AUTH_MODE=oauth (OAuth-only mode)
✓ OAuth secrets configured (4 environment variables)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Test 3: Headless OAuth Authentication Flow
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ GOOGLE_REFRESH_TOKEN is set
✓ ID token obtained (1138 chars)
✓ Health check passed (HTTP 200)
✓ Correctly rejected unauthenticated request (HTTP 401)
✓ OAuth authenticated request succeeded (HTTP 200)
✓ Valid JSON response received
✓ Response length: 7072 chars

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Test Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Service deployment: Verified
✓ OAuth configuration: Verified
✓ OAuth flow: Tested and working

✓ Staging integration tests completed successfully!
```

## Next Steps (Future Work)

### CI/CD Integration (Not Implemented Yet)

For automated CI/CD pipelines:

1. **Store refresh token in Secret Manager**:
```bash
echo -n "YOUR_REFRESH_TOKEN" | gcloud secrets create google-refresh-token \
  --data-file=- \
  --project=cwechatbot
```

2. **Create CI/CD service account** with permissions:
   - `roles/run.viewer` - Read Cloud Run services
   - `roles/secretmanager.secretAccessor` - Access secrets

3. **In CI/CD pipeline**:
```yaml
# Example GitHub Actions
- name: Run Staging Tests
  env:
    GOOGLE_REFRESH_TOKEN: ${{ secrets.GOOGLE_REFRESH_TOKEN }}
  run: |
    RUN_TESTS=true ./apps/chatbot/deploy_staging.sh
```

### Additional Test Coverage (Future)

Consider adding:
- Performance testing (response time benchmarks)
- Load testing (concurrent requests)
- Security scanning (OWASP ZAP integration)
- PDF upload E2E tests
- WebSocket connection tests

## Documentation

Complete documentation available:
- **Test README**: `tests/integration/README.md`
- **OAuth Setup**: `docs/refactor/R14/create_tokens.md`
- **Deployment Guide**: `docs/refactor/R14/DEPLOYMENT_COMPLETE.md`
- **This Document**: `docs/refactor/R14/TESTING_SETUP_COMPLETE.md`

## Files Modified/Created

### Created
- `tests/integration/run_staging_tests.sh` - Main test runner
- `tests/integration/README.md` - Test documentation
- `docs/refactor/R14/TESTING_SETUP_COMPLETE.md` - This document

### Modified
- `apps/chatbot/deploy_staging.sh` - Added test execution option
- `tools/pretest_get_id_token.py` - Added debug output and timeout
- `tests/integration/test_staging_oauth.sh` - Moved from tools/, fixed paths

### Moved
- `tools/test_staging_oauth.sh` → `tests/integration/test_staging_oauth.sh`

## Success Criteria ✅

- [x] Tests run automatically after staging deployment
- [x] Tests verify OAuth-only authentication works
- [x] Tests validate service health and configuration
- [x] Tests fail deployment if any check fails
- [x] Tests can run manually on-demand
- [x] Tests work from any directory
- [x] Complete documentation provided
- [x] All tests passing in staging environment

## Conclusion

The staging integration test suite is **production-ready** and provides comprehensive validation of OAuth authentication and service health. Tests can be run automatically after deployment or manually for verification.

**Status**: ✅ Complete and Verified
**Deployment**: Ready for production use
**Documentation**: Complete
