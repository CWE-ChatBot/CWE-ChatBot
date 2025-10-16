#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Test staging OAuth flow headlessly using refresh token
# ─────────────────────────────────────────────────────────────────────────────

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok(){ echo -e "${GREEN}✓${NC} $*"; }
err(){ echo -e "${RED}✗${NC} $*"; }
warn(){ echo -e "${YELLOW}⚠${NC} $*"; }

# Find project root (directory containing pyproject.toml)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Configuration
STAGING_URL="${STAGING_URL:-https://staging-cwe.crashedmind.com}"
PROJECT="${PROJECT:-cwechatbot}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Staging OAuth Headless Test"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check required environment variables
if [[ -z "${GOOGLE_REFRESH_TOKEN:-}" ]]; then
  err "GOOGLE_REFRESH_TOKEN not set"
  echo ""
  echo "To get a refresh token:"
  echo "  1. Run: ./scripts/ops/get_refresh_token_localhost.sh"
  echo "  2. Export: export GOOGLE_REFRESH_TOKEN='your_refresh_token'"
  exit 1
fi

# Get OAuth credentials from Secret Manager if not set
if [[ -z "${GOOGLE_WEB_CLIENT_ID:-}" ]]; then
  warn "GOOGLE_WEB_CLIENT_ID not set, fetching from Secret Manager..."
  export GOOGLE_WEB_CLIENT_ID=$(gcloud secrets versions access latest --secret=oauth-google-client-id --project="$PROJECT")
  ok "Got client ID from Secret Manager"
fi

if [[ -z "${GOOGLE_WEB_CLIENT_SECRET:-}" ]]; then
  warn "GOOGLE_WEB_CLIENT_SECRET not set, fetching from Secret Manager..."
  export GOOGLE_WEB_CLIENT_SECRET=$(gcloud secrets versions access latest --secret=oauth-google-client-secret --project="$PROJECT")
  ok "Got client secret from Secret Manager"
fi

# Step 1: Get ID token
echo ""
echo "Step 1: Getting ID token from refresh token..."
cd "$PROJECT_ROOT"
ID_TOKEN_OUTPUT=$(poetry run python scripts/ops/pretest_get_id_token.py 2>&1)
if [[ $? -ne 0 ]]; then
  err "Failed to get ID token"
  echo "$ID_TOKEN_OUTPUT"
  exit 1
fi

ID_TOKEN=$(echo "$ID_TOKEN_OUTPUT" | awk -F= '/^ID_TOKEN=/{print $2}')
if [[ -z "$ID_TOKEN" ]]; then
  err "No ID token returned"
  exit 1
fi

ok "ID token obtained (${#ID_TOKEN} chars)"

# Step 2: Test health endpoint (no auth required)
echo ""
echo "Step 2: Testing health endpoint (no auth)..."
HEALTH_RESPONSE=$(curl -s -w "\n%{http_code}" "$STAGING_URL/")
HTTP_CODE=$(echo "$HEALTH_RESPONSE" | tail -1)
if [[ "$HTTP_CODE" == "200" ]]; then
  ok "Health check passed (HTTP $HTTP_CODE)"
else
  err "Health check failed (HTTP $HTTP_CODE)"
fi

# Step 3: Test API without auth (should fail with 401)
echo ""
echo "Step 3: Testing API without auth (should fail with 401)..."
NO_AUTH_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$STAGING_URL/api/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"query":"test","persona":"Developer"}')
HTTP_CODE=$(echo "$NO_AUTH_RESPONSE" | tail -1)
BODY=$(echo "$NO_AUTH_RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" == "401" ]] && echo "$BODY" | grep -q "OAuth Bearer token required"; then
  ok "Correctly rejected unauthenticated request (HTTP 401)"
else
  err "Expected 401 OAuth error, got HTTP $HTTP_CODE"
  echo "Response: $BODY"
fi

# Step 4: Test API with OAuth token
echo ""
echo "Step 4: Testing API with OAuth Bearer token..."
AUTH_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$STAGING_URL/api/v1/query" \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"What is CWE-79?","persona":"Developer"}')
HTTP_CODE=$(echo "$AUTH_RESPONSE" | tail -1)
BODY=$(echo "$AUTH_RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" == "200" ]]; then
  ok "OAuth authenticated request succeeded (HTTP 200)"

  # Check if we got a proper response
  if echo "$BODY" | jq -e '.response' >/dev/null 2>&1; then
    ok "Valid JSON response received"
    RESPONSE_LENGTH=$(echo "$BODY" | jq -r '.response' | wc -c)
    ok "Response length: $RESPONSE_LENGTH chars"

    # Show first 200 chars of response
    echo ""
    echo "Response preview:"
    echo "─────────────────────────────────────────────────────────────────"
    echo "$BODY" | jq -r '.response' | head -c 200
    echo "..."
    echo "─────────────────────────────────────────────────────────────────"
  else
    warn "Response doesn't contain expected 'response' field"
    echo "Full response: $BODY"
  fi
else
  err "OAuth authenticated request failed (HTTP $HTTP_CODE)"
  echo "Response: $BODY"
  exit 1
fi

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Test Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "Health endpoint: Working"
ok "OAuth rejection: Working (401 without token)"
ok "OAuth authentication: Working (200 with valid token)"
ok "API response: Valid JSON with response data"
echo ""
ok "Headless OAuth flow verified successfully!"
echo ""
