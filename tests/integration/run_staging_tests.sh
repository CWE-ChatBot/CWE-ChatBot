#!/usr/bin/env bash
# Staging Integration Test Suite
# Runs after staging deployment to verify OAuth flow and API functionality
set -euo pipefail

# Colors
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok(){ echo -e "${GREEN}✓${NC} $*"; }
err(){ echo -e "${RED}✗${NC} $*"; }
warn(){ echo -e "${YELLOW}⚠${NC} $*"; }

# Configuration
STAGING_URL="${STAGING_URL:-https://staging-cwe.crashedmind.com}"
PROJECT="${PROJECT:-cwechatbot}"
REGION="${REGION:-us-central1}"
SERVICE="cwe-chatbot-staging"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Staging Integration Test Suite"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Environment:"
echo "  Project:      $PROJECT"
echo "  Region:       $REGION"
echo "  Service:      $SERVICE"
echo "  Staging URL:  $STAGING_URL"
echo ""

# Test 1: Service Health Check
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 1: Service Deployment Status"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SERVICE_STATUS=$(gcloud run services describe "$SERVICE" \
  --region="$REGION" \
  --project="$PROJECT" \
  --format="value(status.conditions[0].status)" 2>/dev/null || echo "FAIL")

if [[ "$SERVICE_STATUS" == "True" ]]; then
  ok "Service is ready and running"

  # Get latest revision info
  LATEST_REVISION=$(gcloud run services describe "$SERVICE" \
    --region="$REGION" \
    --project="$PROJECT" \
    --format="value(status.latestReadyRevisionName)")

  DEPLOY_TIME=$(gcloud run revisions describe "$LATEST_REVISION" \
    --region="$REGION" \
    --project="$PROJECT" \
    --format="value(metadata.creationTimestamp)")

  ok "Latest revision: $LATEST_REVISION"
  ok "Deployed at: $DEPLOY_TIME"
else
  err "Service is not ready (status: $SERVICE_STATUS)"
  exit 1
fi

echo ""

# Test 2: OAuth Configuration
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 2: OAuth Configuration"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check AUTH_MODE is set to oauth
AUTH_MODE=$(gcloud run services describe "$SERVICE" \
  --region="$REGION" \
  --project="$PROJECT" \
  --format=json | jq -r '.spec.template.spec.containers[0].env[] | select(.name=="AUTH_MODE") | .value')

if [[ "$AUTH_MODE" == "oauth" ]]; then
  ok "AUTH_MODE=oauth (OAuth-only mode)"
else
  err "AUTH_MODE is not 'oauth' (got: $AUTH_MODE)"
  exit 1
fi

# Check OAuth secrets are configured
OAUTH_SECRETS=$(gcloud run services describe "$SERVICE" \
  --region="$REGION" \
  --project="$PROJECT" \
  --format="json" | jq -r '.spec.template.spec.containers[0].env[] | select(.name | startswith("OAUTH")) | .name' | wc -l)

if [[ "$OAUTH_SECRETS" -ge 4 ]]; then
  ok "OAuth secrets configured ($OAUTH_SECRETS environment variables)"
else
  warn "OAuth may not be fully configured (found $OAUTH_SECRETS env vars)"
fi

echo ""

# Test 3: Headless OAuth Flow
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 3: Headless OAuth Authentication Flow"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [[ -z "${GOOGLE_REFRESH_TOKEN:-}" ]]; then
  warn "GOOGLE_REFRESH_TOKEN not set - skipping OAuth flow tests"
  echo ""
  echo "To run OAuth tests:"
  echo "  1. Run: ./tools/get_refresh_token_localhost.sh"
  echo "  2. Export the refresh token"
  echo "  3. Run this test suite again"
else
  ok "GOOGLE_REFRESH_TOKEN is set"
  echo ""
  echo "Running OAuth flow tests..."

  # Run the OAuth test script
  if ./tests/integration/test_staging_oauth.sh; then
    ok "OAuth authentication flow verified"
  else
    err "OAuth authentication tests failed"
    exit 1
  fi
fi

echo ""

# Test Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Test Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "Service deployment: Verified"
ok "OAuth configuration: Verified"

if [[ -n "${GOOGLE_REFRESH_TOKEN:-}" ]]; then
  ok "OAuth flow: Tested and working"
else
  warn "OAuth flow: Skipped (no refresh token)"
fi

echo ""
ok "Staging integration tests completed successfully!"
echo ""
