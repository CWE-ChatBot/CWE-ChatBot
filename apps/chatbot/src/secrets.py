"""
Secret Manager integration for CWE ChatBot.

Retrieves secrets from Google Cloud Secret Manager at runtime.
Falls back to environment variables for local development.
"""

import os
from functools import lru_cache
from typing import Optional


@lru_cache(maxsize=128)
def get_secret(
    secret_id: str, project_id: Optional[str] = None, version: str = "latest"
) -> Optional[str]:
    """
    Get secret from GCP Secret Manager or environment variable fallback.

    Args:
        secret_id: Secret name in Secret Manager (e.g., "db-password-app-user")
        project_id: GCP project ID (defaults to GOOGLE_CLOUD_PROJECT env var)
        version: Secret version (default: "latest")

    Returns:
        Secret value or None if not found

    Priority:
        1. GCP Secret Manager (if in Cloud Run or explicit project_id)
        2. Environment variable with same name (uppercased with hyphens to underscores)
        3. None
    """
    # Check if running in GCP (Cloud Run sets these)
    in_gcp = bool(os.getenv("K_SERVICE")) or bool(os.getenv("GOOGLE_CLOUD_PROJECT"))
    project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")

    # Try Secret Manager first if in GCP
    if in_gcp and project_id:
        try:
            from google.cloud import secretmanager

            client = secretmanager.SecretManagerServiceClient()
            name = f"projects/{project_id}/secrets/{secret_id}/versions/{version}"
            response = client.access_secret_version(request={"name": name})
            return str(response.payload.data.decode("UTF-8").strip())
        except Exception as e:
            # Log but don't fail - fall through to env var
            print(
                f"Warning: Failed to get secret '{secret_id}' from Secret Manager: {e}"
            )

    # Fallback to environment variable
    # Convert secret-id-format to SECRET_ID_FORMAT
    env_var_name = secret_id.upper().replace("-", "_")
    return os.getenv(env_var_name)


def get_database_password(project_id: Optional[str] = None) -> str:
    """Get database password from Secret Manager or DB_PASSWORD env var."""
    # Try new standardized secret name first
    password = get_secret("db-password-app-user", project_id)
    if password:
        return password

    # Fallback to direct env var
    password = os.getenv("DB_PASSWORD", "")
    if password:
        return password.strip()

    # Legacy POSTGRES_PASSWORD for backwards compatibility
    return os.getenv("POSTGRES_PASSWORD", "").strip()


def get_gemini_api_key(project_id: Optional[str] = None) -> str:
    """Get Gemini API key from Secret Manager or GEMINI_API_KEY env var."""
    key = get_secret("gemini-api-key", project_id)
    if key:
        return key
    return os.getenv("GEMINI_API_KEY", "")


def get_test_api_key(project_id: Optional[str] = None) -> str:
    """Get TEST API key from Secret Manager or TEST_API_KEY env var."""
    key = get_secret("test-api-key", project_id)
    if key:
        return key
    return os.getenv("TEST_API_KEY", "")


def get_chainlit_auth_secret(project_id: Optional[str] = None) -> Optional[str]:
    """Get Chainlit auth secret from Secret Manager or CHAINLIT_AUTH_SECRET env var."""
    secret = get_secret("chainlit-auth-secret", project_id)
    if secret:
        return secret
    return os.getenv("CHAINLIT_AUTH_SECRET")


def get_oauth_google_client_id(project_id: Optional[str] = None) -> Optional[str]:
    """Get Google OAuth client ID from Secret Manager or OAUTH_GOOGLE_CLIENT_ID env var."""
    client_id = get_secret("oauth-google-client-id", project_id)
    if client_id:
        return client_id
    return os.getenv("OAUTH_GOOGLE_CLIENT_ID")


def get_oauth_google_client_secret(project_id: Optional[str] = None) -> Optional[str]:
    """Get Google OAuth client secret from Secret Manager or OAUTH_GOOGLE_CLIENT_SECRET env var."""
    secret = get_secret("oauth-google-client-secret", project_id)
    if secret:
        return secret
    return os.getenv("OAUTH_GOOGLE_CLIENT_SECRET")


def get_oauth_github_client_id(project_id: Optional[str] = None) -> Optional[str]:
    """Get GitHub OAuth client ID from Secret Manager or OAUTH_GITHUB_CLIENT_ID env var."""
    client_id = get_secret("oauth-github-client-id", project_id)
    if client_id:
        return client_id
    return os.getenv("OAUTH_GITHUB_CLIENT_ID")


def get_oauth_github_client_secret(project_id: Optional[str] = None) -> Optional[str]:
    """Get GitHub OAuth client secret from Secret Manager or OAUTH_GITHUB_CLIENT_SECRET env var."""
    secret = get_secret("oauth-github-client-secret", project_id)
    if secret:
        return secret
    return os.getenv("OAUTH_GITHUB_CLIENT_SECRET")


def initialize_secrets(project_id: Optional[str] = None) -> dict:
    """
    Initialize and validate all secrets at startup.

    Returns:
        Dictionary of secret names to boolean indicating if they were found
    """
    secrets_status = {
        "db_password": bool(get_database_password(project_id)),
        "gemini_api_key": bool(get_gemini_api_key(project_id)),
        "chainlit_auth_secret": bool(get_chainlit_auth_secret(project_id)),
        "oauth_google_client_id": bool(get_oauth_google_client_id(project_id)),
        "oauth_google_client_secret": bool(get_oauth_google_client_secret(project_id)),
        "oauth_github_client_id": bool(get_oauth_github_client_id(project_id)),
        "oauth_github_client_secret": bool(get_oauth_github_client_secret(project_id)),
    }

    # Log status (without values!)
    print("Secret initialization status:")
    for name, found in secrets_status.items():
        status = "✓ Found" if found else "✗ Missing"
        print(f"  {name}: {status}")

    return secrets_status
