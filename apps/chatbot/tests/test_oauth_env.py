#!/usr/bin/env python3
"""
Test script to verify OAuth environment variables are loaded properly
"""

import os
import sys
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Load environment manually
from src.config.env_loader import load_env_auto

load_env_auto()


def test_oauth_env():
    print("🔍 Testing OAuth Environment Variable Loading")
    print("=" * 50)

    # Check if environment is loaded
    print("✅ Environment loaded via app_config_extended")

    # Check OAuth environment variables
    oauth_vars = {
        "OAUTH_GOOGLE_CLIENT_ID": os.getenv("OAUTH_GOOGLE_CLIENT_ID"),
        "OAUTH_GOOGLE_CLIENT_SECRET": os.getenv("OAUTH_GOOGLE_CLIENT_SECRET"),
        "OAUTH_GITHUB_CLIENT_ID": os.getenv("OAUTH_GITHUB_CLIENT_ID"),
        "OAUTH_GITHUB_CLIENT_SECRET": os.getenv("OAUTH_GITHUB_CLIENT_SECRET"),
        "ALLOWED_USERS": os.getenv("ALLOWED_USERS"),
        "CHAINLIT_URL": os.getenv("CHAINLIT_URL", "http://localhost:8081"),
    }

    print("\n📋 OAuth Environment Variables:")
    print("-" * 30)

    all_set = True
    for var_name, var_value in oauth_vars.items():
        if (
            var_value
            and var_value != "your_google_client_id_here"
            and var_value != "your_github_client_id_here"
            and var_value != "your_google_client_secret_here"
            and var_value != "your_github_client_secret_here"
        ):
            print(
                f"✅ {var_name}: {var_value[:20]}..."
                if len(var_value) > 20
                else f"✅ {var_name}: {var_value}"
            )
        else:
            print(f"❌ {var_name}: Not set or placeholder value")
            if var_name.startswith("OAUTH_"):
                all_set = False

    print("\n🎯 Testing Recommendations:")
    print("-" * 30)

    if not all_set:
        print("⚠️  OAuth providers not configured with real credentials")
        print("📝 To test OAuth functionality:")
        print("   1. Get Google OAuth credentials from Google Cloud Console")
        print("   2. Get GitHub OAuth credentials from GitHub Developer Settings")
        print("   3. Update the placeholders in ~/work/env/.env_cwe_chatbot")
        print(
            "   4. Set callback URLs to http://localhost:8081/auth/oauth/{provider}/callback"
        )
        print("\n🔧 For development testing without real OAuth:")
        print("   - The app will show authentication required messages")
        print("   - You can test the authentication enforcement logic")
        print("   - The OAuth callback code is ready when credentials are added")
    else:
        print("✅ OAuth environment variables are configured!")
        print("🚀 Ready to test OAuth authentication")

    print(f"\n🌐 Chainlit URL: {oauth_vars['CHAINLIT_URL']}")

    return all_set


if __name__ == "__main__":
    test_oauth_env()
