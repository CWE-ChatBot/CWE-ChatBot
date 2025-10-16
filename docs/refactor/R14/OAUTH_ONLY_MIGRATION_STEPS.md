# OAuth-Only Migration: Complete Implementation Guide

**Date**: 2025-10-15
**Current Status**: Staging is **hybrid mode** (OAuth + TEST_API_KEY)
**Target Status**: OAuth-only mode (production parity)

---

## Executive Summary

**Why the current deployment is still hybrid mode:**

The deployment script ([deploy_staging.sh](deploy_staging.sh:133)) correctly sets `AUTH_MODE=oauth` as an **environment variable** at line 133, BUT:

1. **Application Code Defaults**: [app_config.py](src/app_config.py:146) has `AUTH_MODE` default to `"oauth"` - this is CORRECT
2. **API Code Still Has TEST_API_KEY Logic**: [api.py](api.py:47) always loads TEST_API_KEY from secrets if it exists
3. **Secrets Still Mounted**: The Cloud Run service still mounts `TEST_API_KEY` secret (visible in revision 00027)

**The Real Issue**: Environment variables set `AUTH_MODE=oauth`, but the application code **always loads TEST_API_KEY** from GCP Secret Manager regardless of AUTH_MODE. The `API_AUTH_MODE` variable doesn't actually exist in the application code - it's only in the deployment script documentation.

---

## Root Cause Analysis

### What We Thought Was Happening:
- Set `AUTH_MODE=oauth` → Application disables TEST_API_KEY
- Set `API_AUTH_MODE=oauth` → API endpoints reject API key auth

### What's Actually Happening:
```python
# apps/chatbot/api.py:47
_TEST_API_KEY = get_test_api_key(_PROJECT_ID)  # ALWAYS loads if secret exists

# apps/chatbot/src/app_config.py:146
auth_mode: str = os.getenv("AUTH_MODE", "oauth")  # Only affects test-login endpoint
```

**The `API_AUTH_MODE` variable is NOT used anywhere in the application code.**

The only thing `AUTH_MODE` controls is whether the `/api/v1/test-login` endpoint is enabled:
- `AUTH_MODE=oauth` → test-login endpoint returns 404
- `AUTH_MODE=hybrid` → test-login endpoint works

But the main `/api/v1/query` endpoint **always accepts TEST_API_KEY** as long as the secret is mounted.

---

## Complete OAuth-Only Migration Steps

To achieve true OAuth-only mode, you need to make **code changes**, not just deployment script changes.

### Option 1: Code Change to Respect API_AUTH_MODE (RECOMMENDED)

This makes the application respect a new `API_AUTH_MODE` environment variable.

#### Step 1: Update api.py to Check API_AUTH_MODE

**File**: `apps/chatbot/api.py`

**Change** (around line 44-58):
```python
# Before:
_PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")
_TEST_API_KEY = get_test_api_key(_PROJECT_ID)
_TEST_API_KEY_HASH = None

if _TEST_API_KEY:
    _TEST_API_KEY_HASH = hashlib.sha256(_TEST_API_KEY.encode()).hexdigest()
    logger.info("API key authentication enabled for /api/v1/query endpoint")
else:
    logger.warning(...)

# After:
_PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")
_API_AUTH_MODE = os.getenv("API_AUTH_MODE", "oauth")  # oauth|hybrid
_TEST_API_KEY = None
_TEST_API_KEY_HASH = None

# Only load TEST_API_KEY if in hybrid mode
if _API_AUTH_MODE == "hybrid":
    _TEST_API_KEY = get_test_api_key(_PROJECT_ID)
    if _TEST_API_KEY:
        _TEST_API_KEY_HASH = hashlib.sha256(_TEST_API_KEY.encode()).hexdigest()
        logger.info("API key authentication enabled (hybrid mode) for /api/v1/query endpoint")
    else:
        logger.warning("API_AUTH_MODE=hybrid but TEST_API_KEY not configured")
else:
    logger.info("API key authentication disabled (oauth mode) - OAuth Bearer tokens only")
```

#### Step 2: Update Query Endpoint to Require OAuth When oauth Mode

**File**: `apps/chatbot/api.py` (query endpoint function)

Find the `verify_api_key` dependency and update it:

```python
async def verify_api_key(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
):
    """
    Verify API authentication.

    In oauth mode: Only accepts OAuth Bearer tokens
    In hybrid mode: Accepts X-API-Key OR OAuth Bearer tokens
    """
    correlation_id = str(uuid.uuid4())
    set_correlation_id(correlation_id)
    client_ip = request.client.host if request.client else "unknown"

    # OAuth mode: Only Bearer tokens allowed
    if _API_AUTH_MODE == "oauth":
        if not authorization or not authorization.startswith("Bearer "):
            logger.warning(
                f"API auth failed (oauth mode): No Bearer token provided",
                extra={"correlation_id": correlation_id, "client_ip": client_ip}
            )
            raise HTTPException(
                status_code=401,
                detail="OAuth Bearer token required. API key authentication disabled in production mode.",
                headers={"WWW-Authenticate": "Bearer"}
            )
        # TODO: Validate Bearer token with OAuth provider
        return correlation_id

    # Hybrid mode: Accept X-API-Key OR Bearer token
    if authorization and authorization.startswith("Bearer "):
        # TODO: Validate Bearer token
        return correlation_id

    # Fall back to API key in hybrid mode
    if not x_api_key:
        logger.warning(...)
        raise HTTPException(status_code=401, detail="API key required (X-API-Key header)")

    # Validate API key
    provided_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
    if not secrets.compare_digest(provided_hash, _TEST_API_KEY_HASH):
        logger.warning(...)
        raise HTTPException(status_code=401, detail="Invalid API key")

    return correlation_id
```

#### Step 3: Rebuild and Deploy

```bash
# Rebuild with updated code
API_AUTH_MODE=oauth TESTER_PRINCIPAL='user:crashedmind@gmail.com' ./apps/chatbot/deploy_staging.sh
```

This will:
1. Build new Docker image with updated `api.py` code
2. Deploy with `API_AUTH_MODE=oauth` environment variable
3. Application will NOT load TEST_API_KEY (even if secret exists)
4. API endpoints will reject X-API-Key, require OAuth Bearer tokens

---

### Option 2: Remove TEST_API_KEY Secret (QUICK FIX, NOT RECOMMENDED)

If you just want to force OAuth-only **without code changes**, remove the secret:

```bash
# Option A: Delete the secret entirely (DESTRUCTIVE)
gcloud secrets delete test-api-key --project=cwechatbot

# Option B: Remove secret mount from deployment script
# Edit deploy_staging.sh line 134, remove TEST_API_KEY from --update-secrets
```

**Why this is not recommended:**
- Breaks E2E tests that depend on TEST_API_KEY
- Doesn't give you control - it's all-or-nothing
- api.py will log warnings about missing key
- Can't easily switch back to hybrid mode for testing

---

### Option 3: Keep Current Hybrid Mode (NO CHANGES)

**Current state is actually fine for staging:**
- Browser users: MUST use OAuth (Google/GitHub)
- API users: CAN use X-API-Key (for E2E tests) OR OAuth
- Production already has `AUTH_MODE=oauth` and likely doesn't have TEST_API_KEY secret

**When hybrid mode makes sense:**
- Staging environment for testing
- Need E2E tests that use API key (Playwright tests)
- Want flexibility during development

**When OAuth-only mode makes sense:**
- Production deployment
- Maximum security posture
- No automated tests using API keys

---

## Recommended Path Forward

### For Staging (Current Environment):
**✅ KEEP hybrid mode** - it's working and secure:
- OAuth required for browser access
- TEST_API_KEY available for E2E tests
- Private ingress + IAM authentication
- All 4 layers of defense active

### For Production Parity:
**Implement Option 1** (code changes):
1. Add `API_AUTH_MODE` environment variable support to `api.py`
2. Only load TEST_API_KEY when `API_AUTH_MODE=hybrid`
3. Reject X-API-Key header when `API_AUTH_MODE=oauth`
4. Update E2E tests to use OAuth device flow instead of API key

### Timeline:
- **Immediate**: Staging works in hybrid mode (DONE ✅)
- **Short-term**: Document that production should NOT mount TEST_API_KEY secret
- **Long-term**: Implement Option 1 for explicit API_AUTH_MODE control

---

## Verification Commands

### Check Current Configuration:
```bash
# Check AUTH_MODE
gcloud run services describe cwe-chatbot-staging --region=us-central1 \
  --format='value(spec.template.spec.containers[0].env)' | grep AUTH_MODE

# Check mounted secrets
gcloud run services describe cwe-chatbot-staging --region=us-central1 \
  --format='value(spec.template.spec.containers[0].env)' | grep -i secret

# Check what api.py actually does
# Read the logs when service starts to see "API key authentication enabled" message
gcloud logging read 'resource.labels.service_name="cwe-chatbot-staging" "API key"' --limit=5
```

### Test OAuth-Only Behavior:
```bash
# Should fail (no TEST_API_KEY support in oauth mode)
curl -X POST https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app/api/v1/query \
  -H "X-API-Key: test" \
  -H "Content-Type: application/json" \
  -d '{"query": "test"}'

# Should work (OAuth Bearer token)
TOKEN=$(gcloud auth print-identity-token --impersonate-service-account=cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com)
curl -X POST https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app/api/v1/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "test"}'
```

---

## Summary

**Current State (2025-10-15)**:
- ✅ Staging deployed and working
- ✅ OAuth required for browser (Google/GitHub login)
- ✅ Private ingress with IAM authentication
- ℹ️ API endpoints accept both X-API-Key AND OAuth (hybrid mode)

**OAuth-Only Goal**:
- Deploy script sets `AUTH_MODE=oauth` ✅
- Deploy script sets `API_AUTH_MODE=oauth` ✅
- Application code **ignores** `API_AUTH_MODE` ❌ (not implemented)
- TEST_API_KEY secret still mounted ℹ️ (doesn't matter if code respects API_AUTH_MODE)

**To Achieve True OAuth-Only**:
1. Implement code changes in `api.py` to respect `API_AUTH_MODE` (Option 1)
2. OR remove TEST_API_KEY secret mount (Option 2 - quick but inflexible)
3. OR accept current hybrid mode for staging (Option 3 - recommended for now)

**Next Decision Point**: Do you want to implement Option 1 (code changes) now, or keep staging in hybrid mode and only enforce OAuth-only for production?
