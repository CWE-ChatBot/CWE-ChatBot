#!/bin/bash
set -euo pipefail

# Manual OAuth refresh token setup
# Run this script and follow the instructions

CLIENT_ID=$(gcloud secrets versions access latest --secret=oauth-google-client-id --project=cwechatbot)
CLIENT_SECRET=$(gcloud secrets versions access latest --secret=oauth-google-client-secret --project=cwechatbot)

cat << EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Get Google OAuth Refresh Token - Manual Method
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

STEP 1: Open this URL in your browser:

https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=$CLIENT_ID&redirect_uri=urn:ietf:wg:oauth:2.0:oob&scope=openid%20email%20profile&access_type=offline&prompt=consent

STEP 2: After approving, Google will show you an authorization code.
        Copy that code.

STEP 3: Paste the authorization code here and press Enter:

EOF

read -r AUTH_CODE

echo ""
echo "Exchanging authorization code for refresh token..."

RESPONSE=$(curl -s -X POST https://oauth2.googleapis.com/token \
  -d "code=$AUTH_CODE" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "redirect_uri=urn:ietf:wg:oauth:2.0:oob" \
  -d "grant_type=authorization_code")

REFRESH_TOKEN=$(echo "$RESPONSE" | jq -r .refresh_token)

if [ "$REFRESH_TOKEN" != "null" ] && [ -n "$REFRESH_TOKEN" ]; then
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ✓ SUCCESS! Your Refresh Token:"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo "$REFRESH_TOKEN"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo "To use it, run:"
  echo ""
  echo "  export GOOGLE_REFRESH_TOKEN='$REFRESH_TOKEN'"
  echo "  ./tools/test_staging_oauth.sh"
  echo ""
  echo "For CI/CD, store this token securely in your secrets manager."
  echo ""
else
  echo ""
  echo "✗ Error getting refresh token:"
  echo "$RESPONSE" | jq .
  echo ""
  echo "Common issues:"
  echo "  - Authorization code already used (they expire after 1 use)"
  echo "  - Code expired (get a new one from step 1)"
  echo ""
fi
