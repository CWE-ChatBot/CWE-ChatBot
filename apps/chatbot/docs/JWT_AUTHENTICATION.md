# JWT Authentication for REST API

**Status**: Implemented in R16 (October 2025)
**Applies To**: REST API endpoints (`/api/v1/*`)
**Authentication Method**: OIDC JWT Bearer tokens

## Overview

The CWE ChatBot REST API uses **OpenID Connect (OIDC) JWT verification** to authenticate API requests. This provides secure, stateless authentication using industry-standard JSON Web Tokens.

### Key Features

- ✅ **Real JWT Verification** - No authentication bypass, proper signature validation
- ✅ **OIDC Standard** - Works with Google, Azure AD, Okta, Auth0, etc.
- ✅ **Email Allowlist** - Enforces user allowlist from `app_config`
- ✅ **Email Verification** - Optional `email_verified` claim check
- ✅ **JWKS Caching** - 1-hour TTL cache for performance
- ✅ **Structured Logging** - No token leakage, correlation IDs for tracing

## Quick Start (Google OAuth)

### 1. Get Google OAuth Client ID

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create OAuth 2.0 Client ID (Web application)
3. Copy the Client ID (format: `*.apps.googleusercontent.com`)

### 2. Configure Environment

```bash
# Required for Google ID tokens
OAUTH_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com

# Optional overrides (defaults work for Google)
# OIDC_ISSUER=https://accounts.google.com
# OIDC_JWKS_URL=https://www.googleapis.com/oauth2/v3/certs
# OIDC_REQUIRE_EMAIL_VERIFIED=true
```

### 3. Make Authenticated API Request

```bash
# Get Google ID token (example using gcloud)
TOKEN=$(gcloud auth print-identity-token)

# Query the API
curl -X POST https://your-api.example.com/api/v1/query \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What is CWE-79?",
    "persona": "developer"
  }'
```

## Configuration Reference

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OAUTH_GOOGLE_CLIENT_ID` | Yes* | None | Google OAuth Client ID - used as default audience |
| `OIDC_ISSUER` | No | `https://accounts.google.com` | Expected JWT issuer (`iss` claim) |
| `OIDC_JWKS_URL` | No | `https://www.googleapis.com/oauth2/v3/certs` | JWKS endpoint for public keys |
| `OIDC_AUDIENCE` | No | Uses `OAUTH_GOOGLE_CLIENT_ID` | Expected JWT audience (`aud` claim), comma-separated for multiple |
| `OIDC_REQUIRE_EMAIL_VERIFIED` | No | `true` | Require `email_verified: true` in JWT claims |

*Required unless `OIDC_AUDIENCE` is explicitly set.

### Configuration Precedence

1. **Explicit OIDC settings** - `OIDC_*` env vars override defaults
2. **Google OAuth fallback** - `OAUTH_GOOGLE_CLIENT_ID` used as audience
3. **Fail closed** - Missing audience raises `RuntimeError` at startup

## JWT Verification Flow

### 1. Request Processing

```
Client Request
  ↓
Extract Bearer Token from Authorization header
  ↓
Unverified check: issuer matches config
  ↓
Fetch JWKS (cached with 1h TTL)
  ↓
Verify signature using RS256 public key
  ↓
Validate claims: iss, aud, exp, iat
  ↓
Check email_verified (if required)
  ↓
Enforce email allowlist
  ↓
Attach user info to request.state
  ↓
Generate correlation_id
  ↓
Allow request
```

### 2. JWT Claims Validation

**Required Claims:**
- `iss` - Must match `OIDC_ISSUER`
- `aud` - Must match one of `OIDC_AUDIENCE` values
- `exp` - Token must not be expired
- `kid` - Must match a key in JWKS

**Optional Claims:**
- `email` - Used for allowlist enforcement (if present)
- `email_verified` - Checked if `OIDC_REQUIRE_EMAIL_VERIFIED=true`
- `sub` - Logged for audit trail
- `upn`, `preferred_username` - Fallback email sources

### 3. Error Responses

| Status | Scenario | Detail |
|--------|----------|--------|
| `401 Unauthorized` | Missing Authorization header | "OAuth Bearer token required" |
| `401 Unauthorized` | Malformed token | "Malformed token" |
| `401 Unauthorized` | Wrong issuer | "Invalid token issuer" |
| `401 Unauthorized` | Missing `kid` | "Missing token key id (kid)" |
| `401 Unauthorized` | Signature invalid | "Invalid token" |
| `401 Unauthorized` | Token expired | "Invalid token" |
| `401 Unauthorized` | Email not verified | "Email not verified for account" |
| `403 Forbidden` | User not in allowlist | "User not authorized" |
| `500 Internal Server Error` | OIDC config error | "Server auth configuration error" |
| `503 Service Unavailable` | JWKS fetch failure | "Unable to fetch/parse JWKS" |

## Other OIDC Providers

The implementation supports any OIDC-compliant provider. Below are examples for common providers.

### Azure AD (Microsoft Entra ID)

```bash
# Azure AD configuration
OIDC_ISSUER=https://login.microsoftonline.com/{tenant-id}/v2.0
OIDC_JWKS_URL=https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys
OIDC_AUDIENCE=api://your-api-client-id
OIDC_REQUIRE_EMAIL_VERIFIED=false  # Azure AD doesn't always include this claim
```

### Okta

```bash
# Okta configuration
OIDC_ISSUER=https://your-domain.okta.com/oauth2/default
OIDC_JWKS_URL=https://your-domain.okta.com/oauth2/default/v1/keys
OIDC_AUDIENCE=api://your-api-identifier
```

### Auth0

```bash
# Auth0 configuration
OIDC_ISSUER=https://your-tenant.auth0.com/
OIDC_JWKS_URL=https://your-tenant.auth0.com/.well-known/jwks.json
OIDC_AUDIENCE=https://your-api-identifier
```

### Self-Hosted (Keycloak, Authentik, etc.)

```bash
# Generic OIDC provider
OIDC_ISSUER=https://auth.example.com/realms/your-realm
OIDC_JWKS_URL=https://auth.example.com/realms/your-realm/protocol/openid-connect/certs
OIDC_AUDIENCE=your-client-id
```

## Security Considerations

### What's Protected

✅ **Signature Verification** - RS256 signature validated against JWKS
✅ **Expiration Checks** - Expired tokens rejected
✅ **Issuer Validation** - Only configured issuer accepted
✅ **Audience Validation** - Only configured audience(s) accepted
✅ **Email Allowlist** - User must be in configured allowlist
✅ **No Token Logging** - Tokens never logged, only claim metadata

### What's NOT Protected

⚠️ **Replay Attacks** - Tokens can be reused until expiration (use short TTL)
⚠️ **Token Theft** - Stolen tokens work until expiration (use HTTPS only)
⚠️ **Rate Limiting** - Currently IP-based only (not per-user)

### Best Practices

1. **Always use HTTPS** - Never send tokens over unencrypted connections
2. **Short token TTL** - Recommend ≤ 1 hour token lifetime
3. **Rotate signing keys** - Regular key rotation at provider
4. **Monitor failed auth** - Alert on unusual 401/403 patterns
5. **Restrict allowlist** - Only authorized users in email allowlist

## Testing

### Unit Tests

```bash
# Run JWT verification tests
poetry run pytest apps/chatbot/tests/test_jwt_verification.py -v

# Test coverage:
# - JWKS caching (cache hits, misses, TTL expiration)
# - OIDC settings resolution
# - RSA key construction from JWK
# - Valid/invalid token verification
# - Expiration, issuer, audience validation
# - Email verification and allowlist enforcement
# - Error responses (401/403)
```

### Manual Testing with Google

```bash
# 1. Get a real Google ID token
gcloud auth print-identity-token

# 2. Test with curl
curl -X POST http://localhost:8000/api/v1/query \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  -H "Content-Type: application/json" \
  -d '{"query": "What is CWE-79?", "persona": "developer"}'

# 3. Check logs for authentication success
# Look for: "API request authenticated with Bearer token"
```

### Testing with Custom Tokens

See `apps/chatbot/tests/test_jwt_verification.py` for examples of creating test tokens with RSA keys.

## Troubleshooting

### "Server auth configuration error" (500)

**Cause**: Missing or invalid OIDC configuration
**Fix**: Ensure `OAUTH_GOOGLE_CLIENT_ID` or `OIDC_AUDIENCE` is set

```bash
# Check configuration
echo $OAUTH_GOOGLE_CLIENT_ID
# Should output: your-client-id.apps.googleusercontent.com
```

### "Invalid token issuer" (401)

**Cause**: Token `iss` claim doesn't match `OIDC_ISSUER`
**Fix**: Verify token issuer matches configuration

```bash
# Decode token to check issuer (unverified - for debugging only)
echo $TOKEN | cut -d. -f2 | base64 -d | jq .iss

# Should match OIDC_ISSUER (default: https://accounts.google.com)
```

### "Missing token key id (kid)" (401)

**Cause**: JWT header missing `kid` claim
**Fix**: Ensure your OIDC provider includes `kid` in JWT header

### "Unable to fetch/parse JWKS" (503)

**Cause**: Network error or invalid JWKS URL
**Fix**: Verify JWKS URL is reachable and returns valid JSON

```bash
# Test JWKS endpoint
curl https://www.googleapis.com/oauth2/v3/certs
# Should return: {"keys": [...]}
```

### "Email not verified" (401)

**Cause**: `email_verified` claim is `false` and verification required
**Fix**: Either verify email at provider, or disable check (not recommended)

```bash
# Disable email verification check (development only)
OIDC_REQUIRE_EMAIL_VERIFIED=false
```

### "User not authorized" (403)

**Cause**: Email not in allowlist
**Fix**: Add user email to allowlist in `app_config.py`

```python
# src/app_config.py
allowed_users: Set[str] = {"user@example.com"}
```

## Production Deployment

### Cloud Run Configuration

```bash
# Deploy with OIDC settings
gcloud run deploy cwe-chatbot \
  --image gcr.io/cwechatbot/cwe-chatbot:latest \
  --region us-central1 \
  --set-env-vars OAUTH_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com \
  --set-env-vars OIDC_REQUIRE_EMAIL_VERIFIED=true
```

### Secret Manager

Store sensitive OAuth secrets in GCP Secret Manager:

```bash
# Store Google OAuth client ID (if not using env vars)
echo -n "your-client-id.apps.googleusercontent.com" | \
  gcloud secrets create oauth-google-client-id --data-file=-
```

### Monitoring

Key metrics to monitor:

- **401 rate** - Spike indicates invalid tokens or attacks
- **403 rate** - Users hitting allowlist restrictions
- **503 rate** - JWKS fetch failures (upstream provider issues)
- **JWT verification latency** - Should be <50ms with caching

Example Cloud Monitoring query:

```
resource.type="cloud_run_revision"
AND resource.labels.service_name="cwe-chatbot"
AND httpRequest.status>=401
AND httpRequest.status<=403
```

## Implementation Details

### JWKS Cache

- **TTL**: 1 hour (configurable via `_JWKSCache.__init__`)
- **Storage**: In-memory dictionary (single instance)
- **Eviction**: Time-based only (no LRU)
- **Thread Safety**: AsyncIO-safe (not thread-safe)

### Performance

- **First request**: ~200-500ms (JWKS fetch + verification)
- **Cached requests**: ~10-50ms (verification only)
- **JWKS cache hit rate**: ~99.9% (with 1h TTL)

### Dependencies

```toml
[tool.poetry.dependencies]
python-jose = {extras = ["cryptography"], version = "^3.3.0"}
httpx = {extras = ["http2"], version = "^0.28.1"}
cryptography = "^46.0.0"
```

## Migration from Previous Implementation

### Before (R15 and earlier)

```python
# TODO: Validate Bearer token with OAuth provider (Google/GitHub)
# For now, accept any Bearer token (Chainlit handles OAuth validation for WebSocket)
# Future: Verify JWT signature and claims
```

**Security Issue**: Authentication bypass - any Bearer token accepted.

### After (R16)

```python
# Full OIDC JWT verification
claims = await _verify_bearer_token(token)
# Validates: signature, issuer, audience, expiration, email allowlist
```

**Breaking Change**: Existing API clients must use valid OIDC JWT tokens.

## References

- [R16 Refactor Specification](../../docs/refactor/R16/R16_jwt.md)
- [OIDC Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [Google Identity Platform](https://developers.google.com/identity/protocols/oauth2/openid-connect)
- [python-jose Documentation](https://python-jose.readthedocs.io/)
