#!/usr/bin/env python3
"""
Integration tests for JWT/OIDC authentication in REST API.

This test suite validates the complete JWT authentication flow including:
- OIDC configuration loading
- JWT token verification with RSA signatures
- Email allowlist enforcement
- Error handling and status codes
- Integration with FastAPI dependencies

Can be run with real Google tokens or mocked tokens for CI/CD.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException, Request
from jose import jwt
import base64

# Import the functions under test
from apps.chatbot.api import (
    _oidc_settings,
    _verify_bearer_token,
    verify_oauth_token,
)


class TestOIDCConfiguration:
    """Test OIDC configuration with various providers."""

    def test_google_default_configuration(self):
        """Verify Google OIDC defaults are correctly configured."""
        with patch.dict(os.environ, {"OAUTH_GOOGLE_CLIENT_ID": "test-client.apps.googleusercontent.com"}, clear=False):
            with patch("apps.chatbot.api.app_config") as mock_config:
                mock_config.oauth_google_client_id = "test-client.apps.googleusercontent.com"

                settings = _oidc_settings()

                assert settings["issuer"] == "https://accounts.google.com"
                assert settings["jwks_url"] == "https://www.googleapis.com/oauth2/v3/certs"
                assert "test-client.apps.googleusercontent.com" in settings["audiences"]
                assert settings["require_email_verified"] is True

    def test_custom_oidc_provider_configuration(self):
        """Test configuration with custom OIDC provider."""
        custom_env = {
            "OIDC_ISSUER": "https://login.microsoftonline.com/tenant-id/v2.0",
            "OIDC_JWKS_URL": "https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys",
            "OIDC_AUDIENCE": "api://my-api",
            "OIDC_REQUIRE_EMAIL_VERIFIED": "false",
        }

        with patch.dict(os.environ, custom_env, clear=False):
            settings = _oidc_settings()

            assert settings["issuer"] == "https://login.microsoftonline.com/tenant-id/v2.0"
            assert settings["jwks_url"] == "https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys"
            assert "api://my-api" in settings["audiences"]
            assert settings["require_email_verified"] is False

    def test_multiple_audiences_configuration(self):
        """Test configuration with multiple audiences."""
        with patch.dict(os.environ, {"OIDC_AUDIENCE": "aud1,aud2,aud3"}, clear=False):
            settings = _oidc_settings()

            assert len(settings["audiences"]) == 3
            assert all(aud in settings["audiences"] for aud in ["aud1", "aud2", "aud3"])

    def test_missing_audience_fails_safely(self):
        """Test that missing audience configuration raises error at startup."""
        with patch.dict(os.environ, {}, clear=True):
            with patch("apps.chatbot.api.app_config") as mock_config:
                mock_config.oauth_google_client_id = None

                with pytest.raises(RuntimeError, match="OIDC_AUDIENCE or OAUTH_GOOGLE_CLIENT_ID"):
                    _oidc_settings()


class JWTTestHelper:
    """Helper class for creating test JWT tokens."""

    @staticmethod
    def create_rsa_keypair():
        """Generate RSA keypair for testing."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def create_token(private_key, claims: Dict[str, Any], kid: str = "test-kid") -> str:
        """Create a JWT token with given claims."""
        headers = {"kid": kid}
        return jwt.encode(claims, private_key, algorithm="RS256", headers=headers)

    @staticmethod
    def create_jwks(public_key, kid: str = "test-kid") -> Dict[str, Any]:
        """Create JWKS dictionary from public key."""
        public_numbers = public_key.public_numbers()
        n_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
        e_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")

        return {
            "keys": [
                {
                    "kid": kid,
                    "kty": "RSA",
                    "use": "sig",
                    "n": base64.urlsafe_b64encode(n_bytes).decode().rstrip("="),
                    "e": base64.urlsafe_b64encode(e_bytes).decode().rstrip("="),
                }
            ]
        }


class TestJWTVerificationSuccess:
    """Test successful JWT verification scenarios."""

    @pytest.fixture
    def test_setup(self):
        """Setup test fixtures."""
        helper = JWTTestHelper()
        private_key, public_key = helper.create_rsa_keypair()

        settings = {
            "issuer": "https://accounts.google.com",
            "jwks_url": "https://www.googleapis.com/oauth2/v3/certs",
            "audiences": ["test-client.apps.googleusercontent.com"],
            "require_email_verified": True,
        }

        return {
            "helper": helper,
            "private_key": private_key,
            "public_key": public_key,
            "settings": settings,
        }

    @pytest.mark.asyncio
    async def test_valid_token_with_verified_email(self, test_setup):
        """Test that valid token with verified email passes all checks."""
        helper = test_setup["helper"]
        private_key = test_setup["private_key"]
        public_key = test_setup["public_key"]
        settings = test_setup["settings"]

        claims = {
            "iss": "https://accounts.google.com",
            "aud": "test-client.apps.googleusercontent.com",
            "sub": "google-user-123456",
            "email": "allowed.user@example.com",
            "email_verified": True,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        token = helper.create_token(private_key, claims)
        mock_jwks = helper.create_jwks(public_key)

        with patch("apps.chatbot.api._validated_oidc_settings", return_value=settings):
            with patch("apps.chatbot.api._jwks_cache.get", new_callable=AsyncMock, return_value=mock_jwks):
                with patch("apps.chatbot.api.app_config.is_user_allowed", return_value=True):
                    result = await _verify_bearer_token(token)

                    assert result["email"] == "allowed.user@example.com"
                    assert result["sub"] == "google-user-123456"
                    assert result["iss"] == "https://accounts.google.com"
                    assert result["email_verified"] is True

    @pytest.mark.asyncio
    async def test_valid_token_multiple_audiences(self, test_setup):
        """Test token validation with multiple configured audiences."""
        helper = test_setup["helper"]
        private_key = test_setup["private_key"]
        public_key = test_setup["public_key"]

        settings = {
            "issuer": "https://accounts.google.com",
            "jwks_url": "https://www.googleapis.com/oauth2/v3/certs",
            "audiences": ["aud1", "aud2", "aud3"],  # Multiple audiences
            "require_email_verified": True,
        }

        claims = {
            "iss": "https://accounts.google.com",
            "aud": "aud2",  # Matches one of the audiences
            "sub": "user-123",
            "email": "test@example.com",
            "email_verified": True,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        token = helper.create_token(private_key, claims)
        mock_jwks = helper.create_jwks(public_key)

        with patch("apps.chatbot.api._validated_oidc_settings", return_value=settings):
            with patch("apps.chatbot.api._jwks_cache.get", new_callable=AsyncMock, return_value=mock_jwks):
                with patch("apps.chatbot.api.app_config.is_user_allowed", return_value=True):
                    result = await _verify_bearer_token(token)
                    assert result["aud"] == "aud2"


class TestJWTVerificationFailures:
    """Test JWT verification failure scenarios."""

    @pytest.fixture
    def test_setup(self):
        """Setup test fixtures."""
        helper = JWTTestHelper()
        private_key, public_key = helper.create_rsa_keypair()

        settings = {
            "issuer": "https://accounts.google.com",
            "jwks_url": "https://www.googleapis.com/oauth2/v3/certs",
            "audiences": ["test-client.apps.googleusercontent.com"],
            "require_email_verified": True,
        }

        return {
            "helper": helper,
            "private_key": private_key,
            "public_key": public_key,
            "settings": settings,
        }

    @pytest.mark.asyncio
    async def test_expired_token_rejected(self, test_setup):
        """Test that expired tokens are rejected with 401."""
        helper = test_setup["helper"]
        private_key = test_setup["private_key"]
        public_key = test_setup["public_key"]
        settings = test_setup["settings"]

        claims = {
            "iss": "https://accounts.google.com",
            "aud": "test-client.apps.googleusercontent.com",
            "sub": "user-123",
            "email": "test@example.com",
            "email_verified": True,
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),  # Expired
            "iat": int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()),
        }

        token = helper.create_token(private_key, claims)
        mock_jwks = helper.create_jwks(public_key)

        with patch("apps.chatbot.api._validated_oidc_settings", return_value=settings):
            with patch("apps.chatbot.api._jwks_cache.get", new_callable=AsyncMock, return_value=mock_jwks):
                with pytest.raises(HTTPException) as exc_info:
                    await _verify_bearer_token(token)

                assert exc_info.value.status_code == 401
                assert "Invalid token" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_wrong_issuer_rejected(self, test_setup):
        """Test that tokens from wrong issuer are rejected."""
        helper = test_setup["helper"]
        private_key = test_setup["private_key"]
        settings = test_setup["settings"]

        claims = {
            "iss": "https://evil.com",  # Wrong issuer
            "aud": "test-client.apps.googleusercontent.com",
            "sub": "user-123",
            "email": "test@example.com",
            "email_verified": True,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        token = helper.create_token(private_key, claims)

        with patch("apps.chatbot.api._validated_oidc_settings", return_value=settings):
            with pytest.raises(HTTPException) as exc_info:
                await _verify_bearer_token(token)

            assert exc_info.value.status_code == 401
            assert "Invalid token issuer" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_wrong_audience_rejected(self, test_setup):
        """Test that tokens with wrong audience are rejected."""
        helper = test_setup["helper"]
        private_key = test_setup["private_key"]
        public_key = test_setup["public_key"]
        settings = test_setup["settings"]

        claims = {
            "iss": "https://accounts.google.com",
            "aud": "wrong-audience",  # Wrong audience
            "sub": "user-123",
            "email": "test@example.com",
            "email_verified": True,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        token = helper.create_token(private_key, claims)
        mock_jwks = helper.create_jwks(public_key)

        with patch("apps.chatbot.api._validated_oidc_settings", return_value=settings):
            with patch("apps.chatbot.api._jwks_cache.get", new_callable=AsyncMock, return_value=mock_jwks):
                with pytest.raises(HTTPException) as exc_info:
                    await _verify_bearer_token(token)

                assert exc_info.value.status_code == 401
                assert "Invalid token" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_missing_kid_rejected(self, test_setup):
        """Test that tokens without kid header are rejected."""
        private_key = test_setup["private_key"]
        settings = test_setup["settings"]

        claims = {
            "iss": "https://accounts.google.com",
            "aud": "test-client.apps.googleusercontent.com",
            "sub": "user-123",
            "email": "test@example.com",
            "email_verified": True,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        # Create token without kid
        token = jwt.encode(claims, private_key, algorithm="RS256")

        with patch("apps.chatbot.api._validated_oidc_settings", return_value=settings):
            with pytest.raises(HTTPException) as exc_info:
                await _verify_bearer_token(token)

            assert exc_info.value.status_code == 401
            assert "Missing token key id" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_unverified_email_rejected(self, test_setup):
        """Test that unverified emails are rejected when required."""
        helper = test_setup["helper"]
        private_key = test_setup["private_key"]
        public_key = test_setup["public_key"]
        settings = test_setup["settings"]

        claims = {
            "iss": "https://accounts.google.com",
            "aud": "test-client.apps.googleusercontent.com",
            "sub": "user-123",
            "email": "test@example.com",
            "email_verified": False,  # Not verified
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        token = helper.create_token(private_key, claims)
        mock_jwks = helper.create_jwks(public_key)

        with patch("apps.chatbot.api._validated_oidc_settings", return_value=settings):
            with patch("apps.chatbot.api._jwks_cache.get", new_callable=AsyncMock, return_value=mock_jwks):
                with pytest.raises(HTTPException) as exc_info:
                    await _verify_bearer_token(token)

                assert exc_info.value.status_code == 401
                assert "Email not verified" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_user_not_in_allowlist_rejected(self, test_setup):
        """Test that users not in allowlist receive 403."""
        helper = test_setup["helper"]
        private_key = test_setup["private_key"]
        public_key = test_setup["public_key"]
        settings = test_setup["settings"]

        claims = {
            "iss": "https://accounts.google.com",
            "aud": "test-client.apps.googleusercontent.com",
            "sub": "user-123",
            "email": "blocked@example.com",
            "email_verified": True,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        token = helper.create_token(private_key, claims)
        mock_jwks = helper.create_jwks(public_key)

        with patch("apps.chatbot.api._validated_oidc_settings", return_value=settings):
            with patch("apps.chatbot.api._jwks_cache.get", new_callable=AsyncMock, return_value=mock_jwks):
                with patch("apps.chatbot.api.app_config.is_user_allowed", return_value=False):
                    with pytest.raises(HTTPException) as exc_info:
                        await _verify_bearer_token(token)

                    assert exc_info.value.status_code == 403
                    assert "User not authorized" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_fail_closed_when_no_allowlist_configured(self, test_setup):
        """Test that authentication fails when no allowlist is configured (fail-closed security)."""
        helper = test_setup["helper"]
        private_key = test_setup["private_key"]
        public_key = test_setup["public_key"]
        settings = test_setup["settings"]

        claims = {
            "iss": "https://accounts.google.com",
            "aud": "test-client.apps.googleusercontent.com",
            "sub": "user-123",
            "email": "legitimate@example.com",
            "email_verified": True,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }

        token = helper.create_token(private_key, claims)
        mock_jwks = helper.create_jwks(public_key)

        # Simulate empty allowlist (no users configured)
        with patch("apps.chatbot.api._validated_oidc_settings", return_value=settings):
            with patch("apps.chatbot.api._jwks_cache.get", new_callable=AsyncMock, return_value=mock_jwks):
                with patch("apps.chatbot.api.app_config.get_allowed_users", return_value=[]):
                    with pytest.raises(HTTPException) as exc_info:
                        await _verify_bearer_token(token)

                    assert exc_info.value.status_code == 403
                    assert "User not authorized" in exc_info.value.detail


class TestFastAPIDependency:
    """Test the FastAPI verify_oauth_token dependency."""

    @pytest.mark.asyncio
    async def test_missing_authorization_header(self):
        """Test 401 when Authorization header missing."""
        mock_request = MagicMock(spec=Request)
        mock_request.client.host = "127.0.0.1"

        with pytest.raises(HTTPException) as exc_info:
            await verify_oauth_token(mock_request, authorization=None)

        assert exc_info.value.status_code == 401
        assert "OAuth Bearer token required" in exc_info.value.detail
        assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}

    @pytest.mark.asyncio
    async def test_malformed_authorization_header(self):
        """Test 401 when Authorization header malformed."""
        mock_request = MagicMock(spec=Request)
        mock_request.client.host = "127.0.0.1"

        with pytest.raises(HTTPException) as exc_info:
            await verify_oauth_token(mock_request, authorization="Basic notbearer")

        assert exc_info.value.status_code == 401
        assert "OAuth Bearer token required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_valid_token_sets_correlation_id(self):
        """Test that valid token sets correlation ID and user context."""
        mock_request = MagicMock(spec=Request)
        mock_request.client.host = "127.0.0.1"
        mock_request.state = MagicMock()

        mock_claims = {
            "sub": "user-123",
            "email": "test@example.com",
            "iss": "https://accounts.google.com",
        }

        with patch("apps.chatbot.api._verify_bearer_token", new_callable=AsyncMock, return_value=mock_claims):
            correlation_id = await verify_oauth_token(mock_request, authorization="Bearer valid.jwt.token")

            # Verify correlation ID is UUID format
            assert correlation_id is not None
            assert len(correlation_id) == 36
            assert correlation_id.count("-") == 4

            # Verify user context attached to request
            assert mock_request.state.user["email"] == "test@example.com"
            assert mock_request.state.user["sub"] == "user-123"
            assert mock_request.state.user["iss"] == "https://accounts.google.com"


if __name__ == "__main__":
    """Allow running tests directly."""
    pytest.main([__file__, "-v", "--tb=short"])
