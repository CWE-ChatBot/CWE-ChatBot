# Hybrid Auth Pattern for E2E Testing

## Overview

The CWE ChatBot uses a **hybrid authentication mode** to enable Playwright E2E tests without compromising security.

- **Production (AUTH_MODE=oauth)**: OAuth only, no test endpoints
- **Testing/Staging (AUTH_MODE=hybrid)**: OAuth + test-login endpoint for E2E tests

## Architecture

### Problem with OAuth-Only Testing

1. Playwright tests need to authenticate to access WebSocket/UI
2. OAuth flow requires browser automation (clicking through Google/GitHub login)
3. OAuth tokens expire frequently, making tests brittle
4. Test accounts need real credentials stored in CI

### Solution: Test-Login Endpoint

Instead of puppeting through OAuth, tests:

1. **Call `/api/v1/test-login`** with API key header
2. **Receive short-lived session cookie** (30 minutes)
3. **Use cookie for WebSocket/UI** - no OAuth dance needed

## Security Guarantees

### No Open Access

- ❌ NOT anonymous - requires valid API key
- ✅ API key from GCP Secret Manager (production) or env var (local)
- ✅ Constant-time comparison prevents timing attacks
- ✅ Only available when `AUTH_MODE=hybrid` (disabled in production)
- ✅ Short-lived sessions (30 minutes, configurable)
- ✅ HttpOnly, Secure, SameSite=Lax cookies

### Environment-Gated

```python
# Production (AUTH_MODE=oauth)
response = requests.post("/api/v1/test-login", ...)
# Returns: 404 Not Found (endpoint hidden)

# Testing (AUTH_MODE=hybrid)
response = requests.post("/api/v1/test-login", headers={"X-API-Key": api_key})
# Returns: 200 OK with session cookie
```

### Audit Trail

All test sessions logged:
```
2025-10-11 17:30:42 - test-login: Issued test session test-1728667842-a1b2c3d4 (expires in 1800s)
```

## Usage

### 1. Generate API Key

```bash
# Generate secure API key (32 bytes URL-safe)
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 2. Store API Key

**Local Testing**:
```bash
export TEST_API_KEY="your-generated-key-here"
export AUTH_MODE="hybrid"
```

**Production (GCP Secret Manager)**:
```bash
gcloud secrets create test-api-key --data-file=- <<< "your-generated-key-here"
```

### 3. Test-Login Flow

**REST API Call**:
```bash
# Exchange API key for session cookie
curl -X POST http://localhost:8081/api/v1/test-login \
  -H "X-API-Key: $TEST_API_KEY" \
  --cookie-jar cookies.txt

# Response:
# {
#   "ok": true,
#   "session_id": "test-1728667842-a1b2c3d4",
#   "expires_in": 1800,
#   "message": "Test session created. Cookie set for WebSocket/UI authentication."
# }

# Use cookie for subsequent requests (WebSocket/UI now authenticated)
curl http://localhost:8081/ --cookie cookies.txt
```

**Playwright E2E Tests**:
```typescript
// tests/e2e/setup.ts
import { request, chromium, type BrowserContext } from '@playwright/test';

export async function newTestContext(baseURL: string, apiKey: string): Promise<BrowserContext> {
  // 1) Get session cookie via test-login
  const req = await request.newContext({ baseURL });
  const resp = await req.post('/api/v1/test-login', {
    headers: { 'X-API-Key': apiKey }
  });

  if (resp.status() !== 200) {
    throw new Error(`test-login failed: ${resp.status()}`);
  }

  // 2) Reuse cookies in browser context
  const cookies = await req.storageState();
  const browser = await chromium.launch();
  const context = await browser.newContext({ storageState: cookies });

  return context;
}
```

**Use in Tests**:
```typescript
test('CWE-82 force-injection works E2E', async () => {
  const context = await newTestContext(
    process.env.CHATBOT_URL!,
    process.env.TEST_API_KEY!
  );

  const page = await context.newPage();
  await page.goto(process.env.CHATBOT_URL!);

  // Interact with UI - WebSocket authenticated via cookie
  await page.fill('#chat-input', 'What is CWE-82?');
  await page.click('#send-button');

  // Assertions...
});
```

## API Reference

### POST /api/v1/test-login

**Authentication**: Requires `X-API-Key` header

**Availability**: Only when `AUTH_MODE=hybrid` (returns 404 in oauth mode)

**Request**:
```http
POST /api/v1/test-login HTTP/1.1
X-API-Key: your-api-key-here
```

**Response** (200 OK):
```json
{
  "ok": true,
  "session_id": "test-1728667842-a1b2c3d4",
  "expires_in": 1800,
  "message": "Test session created. Cookie set for WebSocket/UI authentication."
}
```

**Response** (404 Not Found - production):
```json
{
  "detail": "Not found"
}
```

**Response** (401 Unauthorized - invalid API key):
```json
{
  "detail": "Invalid API key"
}
```

**Side Effects**:
- Sets `test_session_id` cookie (HttpOnly, Secure, SameSite=Lax, 30 min expiry)
- Logs session creation with session ID and expiry

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AUTH_MODE` | No | `oauth` | `oauth` (production) or `hybrid` (testing) |
| `TEST_API_KEY` | Yes (hybrid) | - | API key for test authentication |
| `ENABLE_OAUTH` | No | `true` | Enable OAuth for real users |

## Production Deployment

**Never deploy with AUTH_MODE=hybrid to production!**

Production should use:
```yaml
env:
  - name: AUTH_MODE
    value: "oauth"  # test-login endpoint disabled
  - name: ENABLE_OAUTH
    value: "true"
  # TEST_API_KEY not needed in production
```

Staging/CI can use:
```yaml
env:
  - name: AUTH_MODE
    value: "hybrid"  # test-login endpoint enabled
  - name: TEST_API_KEY
    valueFrom:
      secretKeyRef:
        name: test-api-key
        key: value
```

## Alternatives Considered

### ❌ Storage State Reuse
- **Approach**: Do one manual OAuth login, save cookies, reuse in tests
- **Problem**: Tokens expire, brittle, requires manual login

### ❌ Reverse Proxy API Key Injection
- **Approach**: NGINX/Envoy injects API key for CI IP addresses
- **Problem**: More infrastructure, doesn't solve WebSocket auth

### ❌ Open Anonymous Access
- **Approach**: Disable auth completely for testing
- **Problem**: Insecure, can't test auth-required features

### ✅ Hybrid Auth (Chosen)
- **Pros**: Secure, clean, works with WebSocket, environment-gated
- **Cons**: Requires TEST_API_KEY management

## Security Checklist

- ✅ API key required (not anonymous)
- ✅ Environment-gated (hybrid mode only)
- ✅ Short-lived sessions (30 minutes)
- ✅ Secure cookies (HttpOnly, Secure, SameSite)
- ✅ Constant-time key comparison
- ✅ Audit logging
- ✅ Hidden in production (404)
- ✅ API key in Secret Manager
- ✅ Rate limiting (10 req/min per IP)

## References

- **API Implementation**: `apps/chatbot/api.py` (test_login function)
- **Config**: `apps/chatbot/src/app_config.py` (auth_mode setting)
- **E2E Tests**: `apps/chatbot/tests/e2e/test_cwe_queries_puppeteer.py`
- **Security**: Uses same API key verification as `/api/v1/query`
