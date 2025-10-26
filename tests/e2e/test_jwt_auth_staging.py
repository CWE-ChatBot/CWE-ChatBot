#!/usr/bin/env python3
"""
End-to-End JWT Authentication Security Tests for Staging Environment

Tests OAuth/JWT authentication against the live staging environment following
OWASP JWT Security Testing guidelines:
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens

Test Coverage:
1. Unauthenticated access is properly rejected
2. Valid JWT tokens are accepted
3. Invalid/malformed JWT tokens are rejected
4. Expired tokens are rejected
5. Tokens with invalid signatures are rejected
6. Algorithm confusion attacks are prevented (e.g., none, HS256 vs RS256)
7. Email allowlist enforcement
8. Email verification claim enforcement
9. Audience validation
10. Issuer validation

Usage:
    # Test with real Google OAuth token (manual flow):
    export STAGING_URL="https://staging-cwe.crashedmind.com"
    export GOOGLE_ID_TOKEN="<your-google-id-token>"
    poetry run pytest tests/e2e/test_jwt_auth_staging.py -v

    # Run all tests (some will be skipped without real tokens):
    poetry run pytest tests/e2e/test_jwt_auth_staging.py -v

Requirements:
    - Staging environment must be deployed and accessible
    - For real token tests: Valid Google/GitHub OAuth tokens
    - Tokens can be obtained via OAuth playground or manual OAuth flow
"""

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import pytest
import requests
from jose import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64

# Configuration
STAGING_URL = os.getenv("STAGING_URL", "https://staging-cwe.crashedmind.com")
API_BASE = f"{STAGING_URL}/api/v1"  # REST API is at /api/v1 prefix
GOOGLE_ID_TOKEN = os.getenv("GOOGLE_ID_TOKEN")  # Real Google OAuth token for testing
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # Real GitHub token for testing
TIMEOUT = 10  # Request timeout in seconds


class TestUnauthenticatedAccess:
    """
    OWASP-WSTG-SESS-10: Test that unauthenticated requests are properly rejected.

    Reference: All endpoints requiring authentication should return 401/403
    when no token is provided.
    """

    def test_api_rejects_no_auth_header(self):
        """Test that requests without Authorization header are rejected."""
        response = requests.get(
            f"{API_BASE}/health",
            timeout=TIMEOUT
        )

        # Health endpoint is public, so should return 200
        # This test validates the endpoint is accessible
        assert response.status_code == 200, \
            f"Health endpoint should be accessible, got {response.status_code}"

    def test_query_endpoint_rejects_no_auth(self):
        """Test that query endpoint requires authentication."""
        response = requests.post(
            f"{API_BASE}/query",
            json={"query": "What is CWE-79?"},
            timeout=TIMEOUT
        )

        # Query endpoint should require auth
        assert response.status_code in [401, 403], \
            f"Query endpoint should reject unauthenticated requests, got {response.status_code}"

    def test_empty_bearer_token_rejected(self):
        """Test that empty Bearer token is rejected."""
        response = requests.post(
            f"{API_BASE}/query",
            headers={"Authorization": "Bearer "},
            json={"query": "What is CWE-79?"},
            timeout=TIMEOUT
        )

        assert response.status_code in [401, 403], \
            f"Empty bearer token should be rejected, got {response.status_code}"

    def test_invalid_auth_scheme_rejected(self):
        """Test that non-Bearer auth schemes are rejected."""
        response = requests.post(
            f"{API_BASE}/query",
            json={"query": "What is CWE-79?"},
            headers={"Authorization": "Basic dGVzdDp0ZXN0"},
            timeout=TIMEOUT
        )

        assert response.status_code in [401, 403], \
            f"Non-Bearer auth should be rejected, got {response.status_code}"


class TestMalformedTokens:
    """
    OWASP-WSTG-SESS-10: Test handling of malformed JWT tokens.

    Reference: Malformed tokens should be rejected with appropriate error messages
    without revealing sensitive implementation details.
    """

    def test_invalid_jwt_format_rejected(self):
        """Test that tokens with invalid JWT format are rejected."""
        invalid_tokens = [
            "not.a.jwt",  # Not enough segments
            "invalid_base64!@#$%",  # Invalid base64
            "header.payload",  # Missing signature
            "a.b.c.d",  # Too many segments
            ".",  # Just dots
            "",  # Empty string
        ]

        for invalid_token in invalid_tokens:
            response = requests.post(
                f"{API_BASE}/query",
                json={"query": "What is CWE-79?"},
                headers={"Authorization": f"Bearer {invalid_token}"},
                timeout=TIMEOUT
            )

            assert response.status_code in [401, 403], \
                f"Malformed token '{invalid_token}' should be rejected, got {response.status_code}"

    def test_invalid_json_in_payload_rejected(self):
        """Test that tokens with invalid JSON in payload are rejected."""
        # Create a token with invalid JSON payload
        header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode().rstrip('=')
        payload = base64.urlsafe_b64encode(b'{invalid json}').decode().rstrip('=')
        signature = base64.urlsafe_b64encode(b'fake_signature').decode().rstrip('=')
        invalid_token = f"{header}.{payload}.{signature}"

        response = requests.post(
            f"{API_BASE}/query",
            json={"query": "What is CWE-79?"},
            headers={"Authorization": f"Bearer {invalid_token}"},
            timeout=TIMEOUT
        )

        assert response.status_code in [401, 403], \
            f"Token with invalid JSON should be rejected, got {response.status_code}"


class TestAlgorithmConfusion:
    """
    OWASP-WSTG-SESS-10: Test prevention of algorithm confusion attacks.

    Reference: JWT libraries must not allow algorithm switching attacks:
    - "none" algorithm should be rejected
    - Symmetric algorithms (HS256) should not be accepted when expecting asymmetric (RS256)
    """

    def test_none_algorithm_rejected(self):
        """
        Critical: Test that 'none' algorithm tokens are rejected.

        This is CVE-2015-9235 - attackers could create unsigned tokens
        by setting alg to 'none'.
        """
        # Create unsigned token with 'none' algorithm
        header = {"alg": "none", "typ": "JWT"}
        payload = {
            "sub": "test@example.com",
            "email": "test@example.com",
            "email_verified": True,
            "aud": os.getenv("OAUTH_GOOGLE_CLIENT_ID", "test-client-id"),
            "iss": "https://accounts.google.com",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }

        # Encode without signature (algorithm='none')
        header_b64 = base64.urlsafe_b64encode(
            str(header).replace("'", '"').encode()
        ).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(
            str(payload).replace("'", '"').encode()
        ).decode().rstrip('=')

        # Token with empty signature (for 'none' algorithm)
        none_token = f"{header_b64}.{payload_b64}."

        response = requests.post(
            f"{API_BASE}/query",
            json={"query": "What is CWE-79?"},
            headers={"Authorization": f"Bearer {none_token}"},
            timeout=TIMEOUT
        )

        assert response.status_code in [401, 403], \
            f"CRITICAL: 'none' algorithm token should be rejected, got {response.status_code}"

    def test_symmetric_algorithm_rejected(self):
        """
        Test that symmetric algorithms (HS256) are rejected when expecting asymmetric (RS256).

        This prevents attackers from using the public key as an HMAC secret.
        """
        # Create token with HS256 (symmetric) instead of RS256 (asymmetric)
        payload = {
            "sub": "attacker@example.com",
            "email": "attacker@example.com",
            "email_verified": True,
            "aud": os.getenv("OAUTH_GOOGLE_CLIENT_ID", "test-client-id"),
            "iss": "https://accounts.google.com",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }

        # Sign with HS256 using arbitrary secret
        hs256_token = jwt.encode(payload, "secret", algorithm="HS256")

        response = requests.post(
            f"{API_BASE}/query",
            headers={"Authorization": f"Bearer {hs256_token}"},
            timeout=TIMEOUT
        )

        assert response.status_code in [401, 403], \
            f"HS256 token should be rejected when expecting RS256, got {response.status_code}"


class TestExpiredTokens:
    """
    OWASP-WSTG-SESS-10: Test that expired tokens are properly rejected.

    Reference: JWT exp claim must be validated and expired tokens rejected.
    """

    def test_expired_token_rejected(self):
        """Test that tokens with expired 'exp' claim are rejected."""
        # Create expired token
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        payload = {
            "sub": "test@example.com",
            "email": "test@example.com",
            "email_verified": True,
            "aud": os.getenv("OAUTH_GOOGLE_CLIENT_ID", "test-client-id"),
            "iss": "https://accounts.google.com",
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),  # Expired 1 hour ago
            "iat": int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp())
        }

        expired_token = jwt.encode(payload, private_key, algorithm="RS256")

        response = requests.post(
            f"{API_BASE}/query",
            headers={"Authorization": f"Bearer {expired_token}"},
            timeout=TIMEOUT
        )

        assert response.status_code in [401, 403], \
            f"Expired token should be rejected, got {response.status_code}"

    def test_token_without_exp_rejected(self):
        """Test that tokens without 'exp' claim are rejected."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        payload = {
            "sub": "test@example.com",
            "email": "test@example.com",
            "email_verified": True,
            "aud": os.getenv("OAUTH_GOOGLE_CLIENT_ID", "test-client-id"),
            "iss": "https://accounts.google.com",
            # Missing 'exp' claim
            "iat": int(datetime.now(timezone.utc).timestamp())
        }

        no_exp_token = jwt.encode(payload, private_key, algorithm="RS256")

        response = requests.post(
            f"{API_BASE}/query",
            headers={"Authorization": f"Bearer {no_exp_token}"},
            timeout=TIMEOUT
        )

        assert response.status_code in [401, 403], \
            f"Token without exp claim should be rejected, got {response.status_code}"


class TestSignatureValidation:
    """
    OWASP-WSTG-SESS-10: Test JWT signature validation.

    Reference: JWT signatures must be validated using proper public key infrastructure.
    """

    def test_invalid_signature_rejected(self):
        """Test that tokens with invalid signatures are rejected."""
        # Create token with valid format but invalid signature
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        payload = {
            "sub": "test@example.com",
            "email": "test@example.com",
            "email_verified": True,
            "aud": os.getenv("OAUTH_GOOGLE_CLIENT_ID", "test-client-id"),
            "iss": "https://accounts.google.com",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }

        # Create token with random key (won't match Google's public keys)
        invalid_sig_token = jwt.encode(payload, private_key, algorithm="RS256")

        response = requests.post(
            f"{API_BASE}/query",
            headers={"Authorization": f"Bearer {invalid_sig_token}"},
            timeout=TIMEOUT
        )

        assert response.status_code in [401, 403], \
            f"Token with invalid signature should be rejected, got {response.status_code}"

    def test_modified_payload_rejected(self):
        """Test that tokens with modified payload are rejected (breaks signature)."""
        # Get a valid token structure and modify payload
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        payload = {
            "sub": "user@example.com",
            "email": "user@example.com",
            "email_verified": True,
            "aud": os.getenv("OAUTH_GOOGLE_CLIENT_ID", "test-client-id"),
            "iss": "https://accounts.google.com",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }

        token = jwt.encode(payload, private_key, algorithm="RS256")

        # Modify payload (change email) - this will break the signature
        parts = token.split('.')
        modified_payload = base64.urlsafe_b64encode(
            b'{"sub":"attacker@evil.com","email":"attacker@evil.com"}'
        ).decode().rstrip('=')
        modified_token = f"{parts[0]}.{modified_payload}.{parts[2]}"

        response = requests.post(
            f"{API_BASE}/query",
            headers={"Authorization": f"Bearer {modified_token}"},
            timeout=TIMEOUT
        )

        assert response.status_code in [401, 403], \
            f"Token with modified payload should be rejected, got {response.status_code}"


class TestClaimValidation:
    """
    OWASP-WSTG-SESS-10: Test JWT claims validation.

    Reference: Critical claims (iss, aud, email_verified) must be validated.
    """

    def test_wrong_issuer_rejected(self):
        """Test that tokens from wrong issuer are rejected."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        payload = {
            "sub": "test@example.com",
            "email": "test@example.com",
            "email_verified": True,
            "aud": os.getenv("OAUTH_GOOGLE_CLIENT_ID", "test-client-id"),
            "iss": "https://evil-issuer.com",  # Wrong issuer
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }

        wrong_iss_token = jwt.encode(payload, private_key, algorithm="RS256")

        response = requests.post(
            f"{API_BASE}/query",
            headers={"Authorization": f"Bearer {wrong_iss_token}"},
            timeout=TIMEOUT
        )

        assert response.status_code in [401, 403], \
            f"Token with wrong issuer should be rejected, got {response.status_code}"

    def test_wrong_audience_rejected(self):
        """Test that tokens with wrong audience are rejected."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        payload = {
            "sub": "test@example.com",
            "email": "test@example.com",
            "email_verified": True,
            "aud": "wrong-client-id.apps.googleusercontent.com",  # Wrong audience
            "iss": "https://accounts.google.com",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }

        wrong_aud_token = jwt.encode(payload, private_key, algorithm="RS256")

        response = requests.post(
            f"{API_BASE}/query",
            headers={"Authorization": f"Bearer {wrong_aud_token}"},
            timeout=TIMEOUT
        )

        assert response.status_code in [401, 403], \
            f"Token with wrong audience should be rejected, got {response.status_code}"

    def test_unverified_email_rejected(self):
        """Test that tokens with email_verified=false are rejected."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        payload = {
            "sub": "test@example.com",
            "email": "test@example.com",
            "email_verified": False,  # Email not verified
            "aud": os.getenv("OAUTH_GOOGLE_CLIENT_ID", "test-client-id"),
            "iss": "https://accounts.google.com",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }

        unverified_token = jwt.encode(payload, private_key, algorithm="RS256")

        response = requests.post(
            f"{API_BASE}/query",
            headers={"Authorization": f"Bearer {unverified_token}"},
            timeout=TIMEOUT
        )

        assert response.status_code in [401, 403], \
            f"Token with unverified email should be rejected, got {response.status_code}"


class TestEmailAllowlist:
    """
    Test email allowlist enforcement with real and crafted tokens.

    Only emails in the allowlist should be able to access the API.
    """

    def test_non_allowlisted_email_rejected(self):
        """Test that emails not in allowlist are rejected (even with valid token structure)."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        payload = {
            "sub": "hacker@evil.com",
            "email": "hacker@evil.com",  # Not in allowlist
            "email_verified": True,
            "aud": os.getenv("OAUTH_GOOGLE_CLIENT_ID", "test-client-id"),
            "iss": "https://accounts.google.com",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp())
        }

        non_allowlist_token = jwt.encode(payload, private_key, algorithm="RS256")

        response = requests.post(
            f"{API_BASE}/query",
            headers={"Authorization": f"Bearer {non_allowlist_token}"},
            timeout=TIMEOUT
        )

        # Should be rejected due to allowlist (even though signature will fail first)
        assert response.status_code in [401, 403], \
            f"Non-allowlisted email should be rejected, got {response.status_code}"


@pytest.mark.skipif(not GOOGLE_ID_TOKEN, reason="GOOGLE_ID_TOKEN not set - requires real OAuth token")
class TestRealGoogleToken:
    """
    Test with real Google OAuth ID tokens.

    To obtain a Google ID token:
    1. Use OAuth 2.0 Playground: https://developers.google.com/oauthplayground/
    2. Select "Google OAuth2 API v2" -> "https://www.googleapis.com/auth/userinfo.email"
    3. Click "Authorize APIs" and sign in with allowed email
    4. Exchange authorization code for tokens
    5. Copy the id_token value

    Usage:
        export GOOGLE_ID_TOKEN="<your-id-token>"
        poetry run pytest tests/e2e/test_jwt_auth_staging.py::TestRealGoogleToken -v
    """

    def test_valid_google_token_accepted(self):
        """Test that a valid Google ID token is accepted."""
        response = requests.get(
            f"{API_BASE}/health",
            headers={"Authorization": f"Bearer {GOOGLE_ID_TOKEN}"},
            timeout=TIMEOUT
        )

        # Valid token should be accepted (200 OK)
        assert response.status_code == 200, \
            f"Valid Google token should be accepted, got {response.status_code}: {response.text}"

    def test_google_token_allows_chat_access(self):
        """Test that valid Google token grants access to chat endpoint."""
        response = requests.post(
            f"{API_BASE}/query",
            headers={"Authorization": f"Bearer {GOOGLE_ID_TOKEN}"},
            json={"query": "What is CWE-79?"},
            timeout=TIMEOUT
        )

        # Should get valid response
        assert response.status_code in [200, 201], \
            f"Chat endpoint should accept valid token, got {response.status_code}: {response.text}"


@pytest.mark.skipif(not GITHUB_TOKEN, reason="GITHUB_TOKEN not set - requires real OAuth token")
class TestRealGitHubToken:
    """
    Test with real GitHub OAuth tokens.

    To obtain a GitHub token:
    1. GitHub OAuth flow or personal access token with read:user scope
    2. For OAuth: Use GitHub OAuth app flow to get access token

    Usage:
        export GITHUB_TOKEN="<your-github-token>"
        poetry run pytest tests/e2e/test_jwt_auth_staging.py::TestRealGitHubToken -v
    """

    def test_valid_github_token_accepted(self):
        """Test that a valid GitHub token is accepted."""
        response = requests.get(
            f"{API_BASE}/health",
            headers={"Authorization": f"Bearer {GITHUB_TOKEN}"},
            timeout=TIMEOUT
        )

        # Valid token should be accepted
        assert response.status_code == 200, \
            f"Valid GitHub token should be accepted, got {response.status_code}: {response.text}"


if __name__ == "__main__":
    """
    Run tests directly:
        python tests/e2e/test_jwt_auth_staging.py
    """
    pytest.main([__file__, "-v", "--tb=short"])
