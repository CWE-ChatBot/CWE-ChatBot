#!/usr/bin/env python3
"""
Get a Google OAuth refresh token for headless API testing.

This script opens a browser for you to authenticate, then saves your refresh token.
Run once to get the token, then use it with pretest_get_id_token.py for automated testing.
"""

import sys
import subprocess

def get_secret(secret_name, project="cwechatbot"):
    """Get secret from Google Secret Manager."""
    cmd = f"gcloud secrets versions access latest --secret={secret_name} --project={project}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error getting secret {secret_name}: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip()

def main():
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  Google OAuth Refresh Token Generator")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()
    print("This will open your browser for Google authentication.")
    print("After you approve, you'll get a refresh token to use for headless testing.")
    print()

    # Check if google-auth-oauthlib is installed
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:
        print("ERROR: google-auth-oauthlib not installed")
        print()
        print("Install it with:")
        print("  pip install google-auth-oauthlib")
        print()
        sys.exit(1)

    # Get OAuth credentials from Secret Manager
    print("Step 1: Fetching OAuth credentials from Secret Manager...")
    try:
        CLIENT_ID = get_secret("oauth-google-client-id")
        CLIENT_SECRET = get_secret("oauth-google-client-secret")
        print(f"✓ Got client ID: {CLIENT_ID[:20]}...")
        print(f"✓ Got client secret: {CLIENT_SECRET[:10]}...")
    except Exception as e:
        print(f"✗ Failed to get credentials: {e}")
        sys.exit(1)

    print()
    print("Step 2: Starting OAuth flow...")
    print("Your browser will open in a moment...")
    print()

    # Create OAuth flow
    flow = InstalledAppFlow.from_client_config(
        {
            "installed": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://localhost"]
            }
        },
        scopes=["openid", "email", "profile"]
    )

    # Run the flow
    try:
        creds = flow.run_local_server(port=0, open_browser=True)
    except Exception as e:
        print(f"✗ OAuth flow failed: {e}")
        sys.exit(1)

    # Success!
    print()
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  ✓ Success! Your refresh token:")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()
    print(creds.refresh_token)
    print()
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()
    print("Save this token securely and export it:")
    print()
    print(f"  export GOOGLE_REFRESH_TOKEN='{creds.refresh_token}'")
    print()
    print("Then test with:")
    print("  ./tools/test_staging_oauth.sh")
    print()
    print("For CI/CD, store as a secret and export before running tests.")
    print()

if __name__ == "__main__":
    main()
