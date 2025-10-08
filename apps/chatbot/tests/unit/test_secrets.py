"""
Tests for Secret Manager integration.

Tests both Secret Manager retrieval and environment variable fallback.
"""
import os
import pytest
from unittest.mock import patch, MagicMock
from apps.chatbot.src.secrets import (
    get_secret,
    get_database_password,
    get_gemini_api_key,
    get_chainlit_auth_secret,
    get_oauth_google_client_id,
    get_oauth_google_client_secret,
    get_oauth_github_client_id,
    get_oauth_github_client_secret,
    initialize_secrets,
)


class TestGetSecret:
    """Tests for generic get_secret function."""

    def test_get_secret_from_env_var_when_not_in_gcp(self):
        """Should fall back to environment variable when not in GCP."""
        with patch.dict(os.environ, {
            'K_SERVICE': '',  # Not in Cloud Run
            'GOOGLE_CLOUD_PROJECT': '',  # No project set
            'MY_SECRET': 'env_value'
        }, clear=False):
            # Clear cache to ensure fresh lookup
            get_secret.cache_clear()
            result = get_secret('my-secret')
            assert result == 'env_value'

    def test_get_secret_returns_none_when_not_found(self):
        """Should return None when secret not in Secret Manager or env."""
        with patch.dict(os.environ, {
            'K_SERVICE': '',
            'GOOGLE_CLOUD_PROJECT': '',
        }, clear=True):
            get_secret.cache_clear()
            result = get_secret('nonexistent-secret')
            assert result is None

    def test_get_secret_converts_hyphen_to_underscore_for_env_var(self):
        """Should convert secret-id-format to SECRET_ID_FORMAT for env lookup."""
        with patch.dict(os.environ, {
            'K_SERVICE': '',
            'GOOGLE_CLOUD_PROJECT': '',
            'MY_SECRET_ID': 'converted_value'
        }, clear=False):
            get_secret.cache_clear()
            result = get_secret('my-secret-id')
            assert result == 'converted_value'

    @pytest.mark.skipif(True, reason="Requires google-cloud-secret-manager package")
    @patch('google.cloud.secretmanager.SecretManagerServiceClient')
    def test_get_secret_from_secret_manager_when_in_gcp(self, mock_sm_client):
        """Should retrieve from Secret Manager when in GCP."""
        # Mock Secret Manager response
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.payload.data = b'secret_value'
        mock_client.access_secret_version.return_value = mock_response
        mock_sm_client.return_value = mock_client

        with patch.dict(os.environ, {
            'K_SERVICE': 'cwe-chatbot',  # In Cloud Run
            'GOOGLE_CLOUD_PROJECT': 'test-project'
        }, clear=False):
            get_secret.cache_clear()
            result = get_secret('my-secret', project_id='test-project')

            assert result == 'secret_value'
            mock_client.access_secret_version.assert_called_once()

    @pytest.mark.skipif(True, reason="Requires google-cloud-secret-manager package")
    @patch('google.cloud.secretmanager.SecretManagerServiceClient')
    def test_get_secret_falls_back_to_env_when_secret_manager_fails(self, mock_sm_client):
        """Should fall back to env var if Secret Manager fails."""
        # Mock Secret Manager to raise exception
        mock_client = MagicMock()
        mock_client.access_secret_version.side_effect = Exception("Secret Manager error")
        mock_sm_client.return_value = mock_client

        with patch.dict(os.environ, {
            'K_SERVICE': 'cwe-chatbot',
            'GOOGLE_CLOUD_PROJECT': 'test-project',
            'MY_SECRET': 'fallback_value'
        }, clear=False):
            get_secret.cache_clear()
            result = get_secret('my-secret', project_id='test-project')

            assert result == 'fallback_value'


class TestDatabasePassword:
    """Tests for get_database_password function."""

    def test_get_database_password_from_standardized_secret(self):
        """Should retrieve from db-password-app-user secret."""
        with patch('apps.chatbot.src.secrets.get_secret', return_value='secret_password'):
            result = get_database_password()
            assert result == 'secret_password'

    def test_get_database_password_fallback_to_db_password(self):
        """Should fall back to DB_PASSWORD env var."""
        with patch('apps.chatbot.src.secrets.get_secret', return_value=None):
            with patch.dict(os.environ, {'DB_PASSWORD': 'env_password'}, clear=False):
                result = get_database_password()
                assert result == 'env_password'

    def test_get_database_password_fallback_to_postgres_password(self):
        """Should fall back to POSTGRES_PASSWORD for backwards compatibility."""
        with patch('apps.chatbot.src.secrets.get_secret', return_value=None):
            with patch.dict(os.environ, {
                'DB_PASSWORD': '',
                'POSTGRES_PASSWORD': 'legacy_password'
            }, clear=False):
                result = get_database_password()
                assert result == 'legacy_password'

    def test_get_database_password_strips_whitespace(self):
        """Should strip whitespace from password."""
        with patch('apps.chatbot.src.secrets.get_secret', return_value=None):
            with patch.dict(os.environ, {'DB_PASSWORD': '  password_with_spaces  '}, clear=False):
                result = get_database_password()
                assert result == 'password_with_spaces'


class TestGeminiApiKey:
    """Tests for get_gemini_api_key function."""

    def test_get_gemini_api_key_from_secret_manager(self):
        """Should retrieve from gemini-api-key secret."""
        with patch('apps.chatbot.src.secrets.get_secret', return_value='secret_key'):
            result = get_gemini_api_key()
            assert result == 'secret_key'

    def test_get_gemini_api_key_fallback_to_env(self):
        """Should fall back to GEMINI_API_KEY env var."""
        with patch('apps.chatbot.src.secrets.get_secret', return_value=None):
            with patch.dict(os.environ, {'GEMINI_API_KEY': 'env_key'}, clear=False):
                result = get_gemini_api_key()
                assert result == 'env_key'


class TestChainlitAuthSecret:
    """Tests for get_chainlit_auth_secret function."""

    def test_get_chainlit_auth_secret_from_secret_manager(self):
        """Should retrieve from chainlit-auth-secret."""
        with patch('apps.chatbot.src.secrets.get_secret', return_value='secret_auth'):
            result = get_chainlit_auth_secret()
            assert result == 'secret_auth'

    def test_get_chainlit_auth_secret_fallback_to_env(self):
        """Should fall back to CHAINLIT_AUTH_SECRET env var."""
        with patch('apps.chatbot.src.secrets.get_secret', return_value=None):
            with patch.dict(os.environ, {'CHAINLIT_AUTH_SECRET': 'env_auth'}, clear=False):
                result = get_chainlit_auth_secret()
                assert result == 'env_auth'


class TestOAuthSecrets:
    """Tests for OAuth credential retrieval functions."""

    def test_get_oauth_google_client_id(self):
        """Should retrieve Google OAuth client ID."""
        with patch('apps.chatbot.src.secrets.get_secret', return_value='google_id'):
            result = get_oauth_google_client_id()
            assert result == 'google_id'

    def test_get_oauth_google_client_secret(self):
        """Should retrieve Google OAuth client secret."""
        with patch('apps.chatbot.src.secrets.get_secret', return_value='google_secret'):
            result = get_oauth_google_client_secret()
            assert result == 'google_secret'

    def test_get_oauth_github_client_id(self):
        """Should retrieve GitHub OAuth client ID."""
        with patch('apps.chatbot.src.secrets.get_secret', return_value='github_id'):
            result = get_oauth_github_client_id()
            assert result == 'github_id'

    def test_get_oauth_github_client_secret(self):
        """Should retrieve GitHub OAuth client secret."""
        with patch('apps.chatbot.src.secrets.get_secret', return_value='github_secret'):
            result = get_oauth_github_client_secret()
            assert result == 'github_secret'


class TestInitializeSecrets:
    """Tests for initialize_secrets function."""

    def test_initialize_secrets_returns_status_dict(self, capsys):
        """Should return dict with secret status and print summary."""
        with patch('apps.chatbot.src.secrets.get_database_password', return_value='password'):
            with patch('apps.chatbot.src.secrets.get_gemini_api_key', return_value='key'):
                with patch('apps.chatbot.src.secrets.get_chainlit_auth_secret', return_value=None):
                    with patch('apps.chatbot.src.secrets.get_oauth_google_client_id', return_value='id'):
                        with patch('apps.chatbot.src.secrets.get_oauth_google_client_secret', return_value='secret'):
                            with patch('apps.chatbot.src.secrets.get_oauth_github_client_id', return_value=None):
                                with patch('apps.chatbot.src.secrets.get_oauth_github_client_secret', return_value=None):
                                    result = initialize_secrets()

        assert result['db_password'] is True
        assert result['gemini_api_key'] is True
        assert result['chainlit_auth_secret'] is False
        assert result['oauth_google_client_id'] is True
        assert result['oauth_google_client_secret'] is True
        assert result['oauth_github_client_id'] is False
        assert result['oauth_github_client_secret'] is False

        # Check printed output
        captured = capsys.readouterr()
        assert 'Secret initialization status:' in captured.out
        assert 'db_password: ✓ Found' in captured.out
        assert 'chainlit_auth_secret: ✗ Missing' in captured.out


class TestSecretManagerIntegration:
    """Integration tests with actual Secret Manager (requires GCP auth)."""

    @pytest.mark.integration
    @pytest.mark.skipif(not os.getenv('RUN_GCP_TESTS'), reason="Requires GCP authentication")
    def test_real_secret_manager_retrieval(self):
        """Test actual Secret Manager retrieval (requires real GCP setup)."""
        # This test only runs if RUN_GCP_TESTS=1 is set
        # Assumes db-password-app-user exists in cwechatbot project
        get_secret.cache_clear()
        result = get_secret('db-password-app-user', project_id='cwechatbot')
        assert result is not None
        assert len(result) > 0
