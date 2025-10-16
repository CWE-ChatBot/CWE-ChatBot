# OAuth-Only Staging Deployment - COMPLETE

**Date**: 2025-10-16
**Status**: ✅ Production-Ready
**Environment**: Staging (staging-cwe.crashedmind.com)

---

## 🎯 What We Accomplished

### 1. OAuth-Only Application Code ✅
- **Removed all API key authentication** from `apps/chatbot/api.py`
- Implemented `verify_oauth_token()` for OAuth Bearer token validation
- API correctly rejects requests without proper OAuth tokens (HTTP 401)
- Production parity achieved: staging = production authentication

### 2. Docker Build & Deployment ✅
- **Fixed retry decorator bug** in `apps/chatbot/src/llm_provider.py`
  - Issue: Invalid tenacity syntax causing silent LLM response failures
  - Resolution: Simplified retry logic
- **Built OAuth-only image**: `gcr.io/cwechatbot/cwe-chatbot:fix-retry`
- **Deployed to Cloud Run**: Revision `cwe-chatbot-staging-00030-6g9`

### 3. Load Balancer Configuration ✅
- **Created infrastructure**:
  - NEG: `cwe-chatbot-staging-neg` → `cwe-chatbot-staging` service
  - Backend: `cwe-chatbot-staging-be` with Cloud Armor protection
  - SSL Certificate: `cert-staging-cwe-crashedmind-com` (ACTIVE)
- **Host-based routing**: `staging-cwe.crashedmind.com` → staging backend
- **Production unchanged**: `cwe.crashedmind.com` → production backend

### 4. Security Hardening ✅

#### Cloud Armor WAF Rules:
| Priority | Rule | Description |
|----------|------|-------------|
| 100 | Allow | GET/HEAD root & /api/health |
| 110 | Allow | JSON API ≤10MB |
| 995 | Allow | WebSocket from prod origin |
| 996 | Allow | WebSocket from staging origin |
| 1000 | Allow | WebSocket (updated for staging) |
| 1100 | Deny | Cross-origin WebSocket |
| 1200 | Deny | WebSocket without Origin |
| 1300 | Rate limit | 300 req/min per IP |
| 900 | Rate limit | 60 req/min per x-user-id |
| 2147483647 | **Deny** | Default deny all |

#### Cloud Run Security:
- **Ingress**: `internal-and-cloud-load-balancing` (LB-only)
- **IAM**: `allUsers` (security enforced at LB layer by Cloud Armor)
- **OAuth**: Google + GitHub providers configured
- **CSP**: Strict Content Security Policy enabled

### 5. Headless OAuth Testing Infrastructure ✅

#### Created Tools:
- **`tools/pretest_get_id_token.py`**: Refresh token → ID token exchange
- **`tools/get_refresh_token_localhost.sh`**: Interactive OAuth flow for setup
- **`tools/test_staging_oauth.sh`**: Comprehensive OAuth flow validation
- **`tools/expose_staging_via_lb.sh`**: Idempotent LB setup
- **`tools/harden_lb_and_run.sh`**: Security hardening automation

#### OAuth Flow (Headless):
```bash
# One-time setup: Get refresh token
./scripts/ops/get_refresh_token_localhost.sh

# Export refresh token (store in CI secrets)
export GOOGLE_REFRESH_TOKEN='your_token_here'

# Test staging with OAuth
./tools/test_staging_oauth.sh
```

---

## 🏗️ Infrastructure Details

### DNS Configuration
- **A Record**: `staging-cwe.crashedmind.com` → `34.49.0.7`
- **Load Balancer IP**: `34.49.0.7` (shared with production)

### Cloud Run Services
- **Production**: `cwe-chatbot` (unchanged)
- **Staging**: `cwe-chatbot-staging` (OAuth-only)
- **PDF Worker**: `pdf-worker-staging` (service-account access only)

### URLs
- **Staging**: https://staging-cwe.crashedmind.com
- **Production**: https://cwe.crashedmind.com
- **Cloud Run Direct**: https://cwe-chatbot-staging-258315443546.us-central1.run.app

---

## 🔐 Security Architecture

### Defense in Depth (4 Layers):
1. **Cloud Armor WAF**: DDoS protection, rate limiting, request filtering
2. **Load Balancer**: TLS termination, host-based routing
3. **Cloud Run IAM**: LB-only ingress (no public internet access)
4. **Application OAuth**: Google/GitHub OAuth 2.0 Bearer tokens

### OAuth Configuration
- **Providers**: Google OAuth 2.0, GitHub OAuth 2.0
- **Scopes**: `openid`, `email`, `profile`
- **Token Type**: ID tokens (JWT)
- **Redirect URIs**:
  - `https://staging-cwe.crashedmind.com/auth/oauth/google/callback`
  - `https://staging-cwe.crashedmind.com/auth/oauth/github/callback`
  - `http://localhost:8080/` (for headless token generation)

---

## 🧪 Testing & Verification

### Browser Testing ✅
```bash
# Open in browser
open https://staging-cwe.crashedmind.com

# Expected: OAuth login (Google/GitHub)
# After login: Full Chainlit UI with working queries
```

### API Testing ✅
```bash
# Test 1: Without OAuth (should fail with 401)
curl -X POST https://staging-cwe.crashedmind.com/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{"query":"What is CWE-79?","persona":"Developer"}'

# Expected: HTTP 401, "OAuth Bearer token required"

# Test 2: With OAuth token (should succeed)
export GOOGLE_REFRESH_TOKEN='your_refresh_token'
ID_TOKEN=$(python3 tools/pretest_get_id_token.py | awk -F= '/^ID_TOKEN=/{print $2}')

curl -X POST https://staging-cwe.crashedmind.com/api/v1/query \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"What is CWE-79?","persona":"Developer"}'

# Expected: HTTP 200, full CWE response with JSON data
```

### Automated Testing ✅
```bash
# Run comprehensive OAuth flow test
./tools/test_staging_oauth.sh

# Validates:
# - Refresh token → ID token exchange
# - Health endpoint accessibility
# - OAuth rejection without token
# - OAuth authentication with token
# - Valid API response structure
```

---

## 📝 Key Files Modified/Created

### Application Code
- `apps/chatbot/api.py` - OAuth-only authentication
- `apps/chatbot/src/llm_provider.py` - Fixed retry decorator bug
- `apps/chatbot/deploy_staging.sh` - OAuth-only deployment config

### Infrastructure Scripts
- `tools/expose_staging_via_lb.sh` - Load balancer wiring (idempotent)
- `tools/harden_lb_and_run.sh` - Security hardening (idempotent)
- `tools/pretest_get_id_token.py` - Token refresh helper
- `tools/get_refresh_token_localhost.sh` - OAuth setup helper
- `tools/test_staging_oauth.sh` - OAuth flow testing

### Configuration
- `.gcloudignore` - Optimized Cloud Build uploads

---

## 🚀 CI/CD Integration

### GitHub Actions Example
```yaml
name: Test Staging

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup GCloud
        uses: google-github-actions/setup-gcloud@v1

      - name: Test Staging OAuth
        env:
          GOOGLE_REFRESH_TOKEN: ${{ secrets.GOOGLE_REFRESH_TOKEN }}
          GOOGLE_WEB_CLIENT_ID: ${{ secrets.GOOGLE_WEB_CLIENT_ID }}
          GOOGLE_WEB_CLIENT_SECRET: ${{ secrets.GOOGLE_WEB_CLIENT_SECRET }}
        run: |
          ./tools/test_staging_oauth.sh
```

### Required Secrets
- `GOOGLE_REFRESH_TOKEN` - Long-lived refresh token (from setup script)
- `GOOGLE_WEB_CLIENT_ID` - OAuth client ID (from Secret Manager)
- `GOOGLE_WEB_CLIENT_SECRET` - OAuth client secret (from Secret Manager)

---

## 🐛 Issues Fixed

### 1. Retry Decorator Bug (CRITICAL)
**Problem**: LLM response generation failing silently
**Cause**: Invalid tenacity syntax `& (~retry_if_exception_type(...))`
**Fix**: Simplified to `retry=retry_if_exception(_is_transient_llm_error)`
**Impact**: Queries now complete with full responses

### 2. OAuth Redirect URI Mismatch
**Problem**: "redirect_uri_mismatch" errors during OAuth flow
**Cause**: Missing redirect URIs in Google OAuth app
**Fix**: Added staging callback URIs to OAuth app configuration
**Impact**: Browser OAuth login works correctly

### 3. Secret Manager Import Error
**Problem**: Warnings about missing `secretmanager` import
**Cause**: Secrets mounted via Cloud Run env vars (not code-based access)
**Fix**: No fix needed - warnings are informational only
**Impact**: Secrets load correctly from mounted environment

---

## 📊 Performance & Metrics

### Response Times (from staging tests)
- OAuth token refresh: ~200ms
- API query (with OAuth): ~2-5s (includes LLM generation)
- Health endpoint: <100ms

### Resource Usage
- **Memory**: 512Mi allocated
- **CPU**: 1 vCPU
- **Concurrency**: 80 requests per instance
- **Max instances**: 5
- **Min instances**: 0 (scales to zero)

---

## ✅ Acceptance Criteria Met

From Story R14 - OAuth-Only Staging:

- [x] Staging uses OAuth-only authentication (no API keys)
- [x] Production parity achieved (same auth method)
- [x] Headless testing possible via refresh tokens
- [x] Load balancer routes staging traffic correctly
- [x] Cloud Armor protects staging environment
- [x] Browser OAuth login works (Google + GitHub)
- [x] API OAuth Bearer token authentication works
- [x] Automated testing scripts provided
- [x] CI/CD integration documented
- [x] Security hardening complete

---

## 🎓 Lessons Learned

### What Worked Well
1. **Idempotent scripts** - Can re-run without breaking things
2. **Refresh token approach** - Simple, secure, CI-friendly
3. **Load balancer reuse** - One LB for prod + staging saves costs
4. **Docker layer caching** - Speeds up builds significantly

### What Could Be Improved
1. **OAuth client setup** - Manual step to add redirect URIs
2. **DNS propagation delay** - ~5-60 minutes for new domains
3. **Build timeout issues** - Local Docker build was faster than Cloud Build

### Security Best Practices Applied
1. **Default deny** - Cloud Armor blocks everything except allowed patterns
2. **Multiple OAuth providers** - Google + GitHub for redundancy
3. **LB-only ingress** - Cloud Run not directly accessible
4. **Separate staging/prod** - Host-based routing isolates environments

---

## 📚 Related Documentation

- [OAuth Device Flow](docs/refactor/R14/R14.md) - Original OAuth design
- [Token Creation Guide](docs/refactor/R14/create_tokens.md) - Refresh token setup
- [Staging Setup](docs/refactor/R14/staging.md) - Infrastructure notes
- [OAuth Migration](apps/chatbot/OAUTH_ONLY_COMPLETE.md) - Code changes
- [Architecture](docs/architecture/security.md) - Security design

---

## 🎉 Conclusion

**OAuth-only staging environment is fully operational and production-ready!**

The staging environment now perfectly mirrors production authentication, allowing:
- ✅ Real-world OAuth testing before production deployment
- ✅ Headless CI/CD testing with refresh tokens
- ✅ Secure, token-based API access
- ✅ Defense-in-depth security posture
- ✅ Production parity for authentic testing

**No more hybrid mode. No more API keys. OAuth-only everywhere. Simple. Same. Secure.**
