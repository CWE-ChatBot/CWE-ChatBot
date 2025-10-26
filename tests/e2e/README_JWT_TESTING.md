# End-to-End JWT Authentication Testing

This directory contains comprehensive E2E security tests for JWT/OAuth authentication following OWASP guidelines.

## Overview

The test suite validates JWT authentication security against the live staging environment, following the **OWASP Web Security Testing Guide (WSTG-SESS-10)**:
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens

## Test Coverage

### ✅ Covered Security Tests

1. **Unauthenticated Access Control**
   - Requests without Authorization header are rejected
   - Empty bearer tokens are rejected
   - Invalid auth schemes (Basic, etc.) are rejected

2. **Malformed Token Handling**
   - Invalid JWT format rejected (wrong segments, invalid base64)
   - Invalid JSON in payload rejected
   - No sensitive error details leaked

3. **Algorithm Confusion Prevention (Critical)**
   - `none` algorithm tokens rejected (CVE-2015-9235)
   - Symmetric algorithms (HS256) rejected when expecting asymmetric (RS256)
   - Prevents using public key as HMAC secret

4. **Token Expiration Validation**
   - Expired tokens (`exp` claim) are rejected
   - Tokens without `exp` claim are rejected

5. **Signature Validation**
   - Tokens with invalid signatures are rejected
   - Modified payload detection (breaks signature)
   - Only tokens signed by trusted issuers accepted

6. **Claims Validation**
   - Issuer (`iss`) validation
   - Audience (`aud`) validation
   - Email verification (`email_verified`) enforcement

7. **Email Allowlist Enforcement**
   - Only allowlisted emails can access the API
   - Non-allowlisted emails rejected even with valid token structure

8. **Real Token Testing**
   - Tests with actual Google OAuth ID tokens
   - Tests with actual GitHub OAuth tokens
   - Validates end-to-end OAuth flow

## Running the Tests

### Prerequisites

```bash
# Install dependencies
poetry install

# Set staging URL (default: https://staging-cwe.crashedmind.com)
export STAGING_URL="https://staging-cwe.crashedmind.com"
```

### Run All Tests (Without Real Tokens)

This runs all security tests with crafted/invalid tokens:

```bash
poetry run pytest tests/e2e/test_jwt_auth_staging.py -v
```

Expected output: Most tests should **PASS** (rejecting invalid tokens). Tests requiring real tokens will be **SKIPPED**.

### Run Tests with Real Google OAuth Token

To test with a real Google ID token:

#### Step 1: Obtain Google ID Token

Use the [Google OAuth 2.0 Playground](https://developers.google.com/oauthplayground/):

1. Go to https://developers.google.com/oauthplayground/
2. Click the gear icon ⚙️ (OAuth 2.0 Configuration)
3. Check "Use your own OAuth credentials"
4. Enter your OAuth Client ID and Secret (from GCP Console)
5. In Step 1: Select "Google OAuth2 API v2" → `https://www.googleapis.com/auth/userinfo.email`
6. Click "Authorize APIs"
7. Sign in with an **allowed email address** (in the allowlist)
8. In Step 2: Exchange authorization code for tokens
9. Copy the `id_token` value (not the access_token!)

#### Step 2: Run Tests with Token

```bash
export GOOGLE_ID_TOKEN="<paste-your-id-token-here>"
poetry run pytest tests/e2e/test_jwt_auth_staging.py::TestRealGoogleToken -v
```

Expected: All tests **PASS** with valid allowlisted Google token.

### Run Tests with Real GitHub Token

```bash
export GITHUB_TOKEN="<your-github-oauth-token>"
poetry run pytest tests/e2e/test_jwt_auth_staging.py::TestRealGitHubToken -v
```

### Run Specific Test Classes

```bash
# Test only algorithm confusion attacks
poetry run pytest tests/e2e/test_jwt_auth_staging.py::TestAlgorithmConfusion -v

# Test only signature validation
poetry run pytest tests/e2e/test_jwt_auth_staging.py::TestSignatureValidation -v

# Test only claims validation
poetry run pytest tests/e2e/test_jwt_auth_staging.py::TestClaimValidation -v
```

### Run with Verbose Output

```bash
poetry run pytest tests/e2e/test_jwt_auth_staging.py -v -s
```

## Test Results Interpretation

### ✅ Expected Results (Security Working Correctly)

All tests in these classes should **PASS** (meaning attacks are **blocked**):
- `TestUnauthenticatedAccess` - All requests without auth rejected (401/403)
- `TestMalformedTokens` - All malformed tokens rejected (401/403)
- `TestAlgorithmConfusion` - All algorithm attacks rejected (401/403)
- `TestExpiredTokens` - All expired tokens rejected (401/403)
- `TestSignatureValidation` - All invalid signatures rejected (401/403)
- `TestClaimValidation` - All invalid claims rejected (401/403)
- `TestEmailAllowlist` - Non-allowlisted emails rejected (401/403)

### ✅ With Real Tokens (Functionality Working)

These tests should **PASS** (meaning valid tokens are **accepted**):
- `TestRealGoogleToken` - Valid Google tokens work (200 OK)
- `TestRealGitHubToken` - Valid GitHub tokens work (200 OK)

### ❌ Security Issues to Investigate

If any of these tests **FAIL**, it indicates a **security vulnerability**:

| Test Failure | Security Issue | Severity | OWASP Reference |
|--------------|----------------|----------|-----------------|
| `test_none_algorithm_rejected` | CVE-2015-9235: Unsigned tokens accepted | **CRITICAL** | WSTG-SESS-10 |
| `test_symmetric_algorithm_rejected` | Algorithm confusion vulnerability | **HIGH** | WSTG-SESS-10 |
| `test_expired_token_rejected` | Expired tokens still valid | **HIGH** | WSTG-SESS-10 |
| `test_invalid_signature_rejected` | Signature not validated | **CRITICAL** | WSTG-SESS-10 |
| `test_wrong_issuer_rejected` | Issuer validation missing | **HIGH** | WSTG-SESS-10 |
| `test_wrong_audience_rejected` | Audience validation missing | **MEDIUM** | WSTG-SESS-10 |
| `test_unverified_email_rejected` | Email verification bypass | **MEDIUM** | Application Logic |
| `test_non_allowlisted_email_rejected` | Authorization bypass | **HIGH** | Application Logic |

## CI/CD Integration

### GitHub Actions Example

```yaml
name: E2E JWT Security Tests

on: [push, pull_request]

jobs:
  jwt-security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install Poetry
        run: pip install poetry

      - name: Install dependencies
        run: poetry install

      - name: Run JWT Security Tests
        env:
          STAGING_URL: https://staging-cwe.crashedmind.com
        run: |
          poetry run pytest tests/e2e/test_jwt_auth_staging.py -v

      - name: Run with Real Token (if available)
        if: ${{ secrets.GOOGLE_ID_TOKEN }}
        env:
          STAGING_URL: https://staging-cwe.crashedmind.com
          GOOGLE_ID_TOKEN: ${{ secrets.GOOGLE_ID_TOKEN }}
        run: |
          poetry run pytest tests/e2e/test_jwt_auth_staging.py::TestRealGoogleToken -v
```

## Manual Testing with curl

### Test Unauthenticated Request (Should Fail)

```bash
curl -i https://staging-cwe.crashedmind.com/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is CWE-79?"}'

# Expected: 401 Unauthorized or 403 Forbidden
```

### Test with Valid Google Token (Should Succeed)

```bash
# First, get token from OAuth playground (see above)
export TOKEN="<your-google-id-token>"

curl -i https://staging-cwe.crashedmind.com/api/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "What is CWE-79?"}'

# Expected: 200 OK with chat response
```

### Test Algorithm Confusion Attack (Should Fail)

```bash
# Token with 'none' algorithm (unsigned)
TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJoYWNrZXJAZXZpbC5jb20iLCJlbWFpbCI6ImhhY2tlckBldmlsLmNvbSJ9."

curl -i https://staging-cwe.crashedmind.com/api/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "hack attempt"}'

# Expected: 401 Unauthorized (CRITICAL if this succeeds!)
```

## Troubleshooting

### All Tests Return 200 OK (Security Issue!)

If unauthorized requests return 200 instead of 401/403:
- Check if `AUTH_MODE=oauth` is set in Cloud Run environment
- Verify `ENABLE_OAUTH=true` is configured
- Check that `@require_oauth_token` decorator is applied to endpoints

### Real Token Tests Fail with 401

If your real Google token is rejected:
1. **Check token expiration**: ID tokens expire after 1 hour
2. **Verify email is in allowlist**: Check `allowed-users` secret in GCP
3. **Check audience**: Token `aud` must match `OAUTH_GOOGLE_CLIENT_ID`
4. **Verify email_verified=true**: Some accounts may not have verified emails

To debug token claims:
```bash
# Decode JWT (first get token from OAuth playground)
echo "<your-token>" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Check for:
- `"email_verified": true`
- `"aud": "your-client-id.apps.googleusercontent.com"`
- `"iss": "https://accounts.google.com"`
- `"exp"` timestamp is in the future

### Tests Timeout

If tests timeout:
- Check staging URL is accessible: `curl -i https://staging-cwe.crashedmind.com/api/health`
- Verify Cloud Run service is running
- Check firewall/network connectivity
- Increase timeout: `TIMEOUT=30 poetry run pytest ...`

## Security Best Practices Validated

This test suite validates these JWT security best practices:

✅ **Never accept `alg: none`** (CVE-2015-9235)
✅ **Always validate signature** with proper public keys
✅ **Validate all critical claims**: `iss`, `aud`, `exp`, `email_verified`
✅ **Enforce token expiration** (`exp` claim)
✅ **Use asymmetric algorithms** (RS256, not HS256) for OAuth
✅ **Validate issuer** (prevent token from untrusted sources)
✅ **Validate audience** (prevent token reuse across services)
✅ **Enforce email verification** (prevent unverified account access)
✅ **Implement allowlist** (authorization layer beyond authentication)
✅ **Reject malformed tokens** without leaking implementation details

## References

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP WSTG-SESS-10: Testing JWT](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens)
- [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [Google Identity: Authenticate with a backend server](https://developers.google.com/identity/sign-in/web/backend-auth)
- [CVE-2015-9235: JWT None Algorithm Vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)

## Contributing

When adding new authentication features, ensure you:
1. Add corresponding E2E security tests
2. Follow OWASP JWT security guidelines
3. Test both positive (valid token) and negative (attack) cases
4. Document any new test requirements in this README
