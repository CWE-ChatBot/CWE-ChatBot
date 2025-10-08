#!/usr/bin/env python3
"""
Test script to verify OAuth configuration helpers in app_config.py
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import config (which will automatically load environment)
from src.app_config import config


def test_oauth_config_helpers():
    print("🔍 Testing OAuth Configuration Helpers")
    print("=" * 60)

    # Test 1: Check OAuth fields are loaded
    print("\n📋 OAuth Configuration Fields:")
    print("-" * 40)
    print(f"enable_oauth: {config.enable_oauth}")
    print(f"chainlit_url: {config.chainlit_url}")
    print(
        f"chainlit_auth_secret: {'SET' if config.chainlit_auth_secret else 'NOT SET'}"
    )
    print(
        f"oauth_google_client_id: {'SET' if config.oauth_google_client_id else 'NOT SET'}"
    )
    print(
        f"oauth_google_client_secret: {'SET' if config.oauth_google_client_secret else 'NOT SET'}"
    )
    print(
        f"oauth_github_client_id: {'SET' if config.oauth_github_client_id else 'NOT SET'}"
    )
    print(
        f"oauth_github_client_secret: {'SET' if config.oauth_github_client_secret else 'NOT SET'}"
    )
    print(f"allowed_users_raw: {config.allowed_users_raw}")

    # Test 2: Check provider configuration helpers
    print("\n🔌 Provider Configuration Helpers:")
    print("-" * 40)
    print(f"google_oauth_configured: {config.google_oauth_configured}")
    print(f"github_oauth_configured: {config.github_oauth_configured}")
    print(f"oauth_providers_configured: {config.oauth_providers_configured}")
    print(f"oauth_ready: {config.oauth_ready}")

    # Test 3: Check whitelist helpers
    print("\n👥 User Whitelist Helpers:")
    print("-" * 40)
    allowed_users = config.get_allowed_users()
    print(
        f"Allowed users: {allowed_users if allowed_users else 'None (all authenticated users allowed)'}"
    )

    # Test whitelist matching
    test_emails = ["test@example.com", "user@company.com", "admin@otherdomain.com"]

    print("\n🔍 Whitelist Matching Tests:")
    print("-" * 40)
    for email in test_emails:
        is_allowed = config.is_user_allowed(email)
        status = "✅ ALLOWED" if is_allowed else "❌ BLOCKED"
        print(f"{email}: {status}")

    # Test 4: Validate OAuth configuration
    print("\n✅ OAuth Validation:")
    print("-" * 40)
    try:
        config.validate_oauth()
        print("✅ OAuth validation passed")
    except ValueError as e:
        print(f"⚠️  OAuth validation warning: {e}")

    # Test 5: Check redirect URIs
    print("\n🔗 OAuth Redirect URIs:")
    print("-" * 40)
    if config.google_oauth_configured:
        print(f"Google: {config.chainlit_url}/auth/oauth/google/callback")
    if config.github_oauth_configured:
        print(f"GitHub: {config.chainlit_url}/auth/oauth/github/callback")
    if not config.oauth_providers_configured:
        print("No providers configured")

    # Summary
    print("\n📊 Configuration Summary:")
    print("=" * 60)

    if config.oauth_ready:
        print("✅ OAuth is fully configured and ready")
        providers = []
        if config.google_oauth_configured:
            providers.append("Google")
        if config.github_oauth_configured:
            providers.append("GitHub")
        print(f"✅ Configured providers: {', '.join(providers)}")
    elif (
        config.enable_oauth
        and config.oauth_providers_configured
        and not config.chainlit_auth_secret
    ):
        print(
            "⚠️  OAuth enabled and providers configured, but CHAINLIT_AUTH_SECRET is missing"
        )
        print("   Set CHAINLIT_AUTH_SECRET=$(chainlit create-secret)")
    elif config.enable_oauth and not config.oauth_providers_configured:
        print("⚠️  OAuth enabled but no providers configured")
        print("   Set OAUTH_GOOGLE_CLIENT_ID/SECRET or OAUTH_GITHUB_CLIENT_ID/SECRET")
    else:
        print("ℹ️  OAuth is disabled (enable_oauth=false)")

    return config.oauth_ready


if __name__ == "__main__":
    result = test_oauth_config_helpers()
    sys.exit(0 if result else 1)
