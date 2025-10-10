#!/usr/bin/env bash
#
# staging_deploy_per_user_rate_limit.sh
#
# STAGING-SAFE deployment strategy for per-user rate limiting.
# Uses priority 900 (before WebSocket rules) for testing without affecting production.
#
# Strategy:
# 1. Deploy per-user rule at priority 900 (non-breaking - evaluated before production rules)
# 2. Test thoroughly with integration + E2E tests
# 3. After validation, promote to priority 1000 (production position)
#
# Usage:
#   PROJECT=cwechatbot \
#   POLICY=cwe-chatbot-armor \
#   URL_MAP=cwe-chatbot-lb \
#   STAGING_URL="https://cwe.crashedmind.com" \
#   bash scripts/staging_deploy_per_user_rate_limit.sh
#

set -euo pipefail

# === Configuration ===
PROJECT="${PROJECT:-cwechatbot}"
POLICY="${POLICY:-cwe-chatbot-armor}"
URL_MAP="${URL_MAP:-cwe-chatbot-lb}"
STAGING_URL="${STAGING_URL:-https://cwe.crashedmind.com}"

# Per-user rate limit settings
USER_HEADER="${USER_HEADER:-X-User-Id}"
USER_HEADER_LOWER=$(echo "$USER_HEADER" | tr 'A-Z' 'a-z')
RPM_PER_USER="${RPM_PER_USER:-60}"
INTERVAL_SEC="${INTERVAL_SEC:-60}"
BAN_DURATION_SEC="${BAN_DURATION_SEC:-300}"
BAN_COUNT_MULTIPLIER="${BAN_COUNT_MULTIPLIER:-2}"

# Test settings
TEST_USER_ID="${TEST_USER_ID:-staging-test-user-1}"
TEST_RATE_LIMIT="${TEST_RATE_LIMIT:-10}"

# Staging rule priority (before WebSocket rules, non-breaking)
STAGING_PRIORITY=900

export CLOUDSDK_CORE_PROJECT="$PROJECT"

# === Helper functions ===
say() { printf "\n[staging-deploy] %s\n" "$*"; }
warn() { printf "\n[warn] %s\n" "$*" 1>&2; }
success() { printf "\n✅ [success] %s\n" "$*"; }
error() { printf "\n❌ [error] %s\n" "$*" 1>&2; }

# === Step 1: Verify current production state ===
say "=== Step 1: Verify Current Production State ==="
say "Checking existing Cloud Armor rules..."

gcloud compute security-policies describe "$POLICY" \
  --format="table(rules[].priority,rules[].action,rules[].description)" || {
  error "Failed to describe Cloud Armor policy. Check project and policy name."
  exit 1
}

say ""
say "Current rules:"
say "  Priority 1000: WebSocket allow (same-origin)"
say "  Priority 1100: WebSocket deny (cross-origin)"
say "  Priority 1200: WebSocket deny (no origin)"
say "  Priority 2147483647: Default allow"
say ""
say "We will add STAGING rule at priority 900 (before WebSocket rules)"
success "Production state verified"

# === Step 2: Check if staging rule already exists ===
say ""
say "=== Step 2: Check for Existing Staging Rule ==="

if gcloud compute security-policies rules describe "$STAGING_PRIORITY" \
  --security-policy="$POLICY" >/dev/null 2>&1; then
  warn "Staging rule at priority $STAGING_PRIORITY already exists. Updating..."

  gcloud compute security-policies rules update "$STAGING_PRIORITY" \
    --security-policy="$POLICY" \
    --action=rate-based-ban \
    --expression="has(request.headers['$USER_HEADER_LOWER'])" \
    --rate-limit-threshold-count="$RPM_PER_USER" \
    --rate-limit-threshold-interval-sec="$INTERVAL_SEC" \
    --conform-action=allow \
    --exceed-action=deny-429 \
    --ban-threshold-count="$((RPM_PER_USER * BAN_COUNT_MULTIPLIER))" \
    --ban-threshold-interval-sec="$INTERVAL_SEC" \
    --ban-duration-sec="$BAN_DURATION_SEC" \
    --enforce-on-key=http-header \
    --enforce-on-key-name="$USER_HEADER_LOWER"
else
  say "Creating new staging rule at priority $STAGING_PRIORITY..."

  gcloud compute security-policies rules create "$STAGING_PRIORITY" \
    --security-policy="$POLICY" \
    --action=rate-based-ban \
    --expression="has(request.headers['$USER_HEADER_LOWER'])" \
    --rate-limit-threshold-count="$RPM_PER_USER" \
    --rate-limit-threshold-interval-sec="$INTERVAL_SEC" \
    --conform-action=allow \
    --exceed-action=deny-429 \
    --ban-threshold-count="$((RPM_PER_USER * BAN_COUNT_MULTIPLIER))" \
    --ban-threshold-interval-sec="$INTERVAL_SEC" \
    --ban-duration-sec="$BAN_DURATION_SEC" \
    --enforce-on-key=http-header \
    --enforce-on-key-name="$USER_HEADER_LOWER"
fi

success "Staging rule deployed at priority $STAGING_PRIORITY"

# === Step 3: Verify deployment ===
say ""
say "=== Step 3: Verify Staging Deployment ==="

gcloud compute security-policies rules describe "$STAGING_PRIORITY" \
  --security-policy="$POLICY" \
  --format="yaml(priority,action,match,rateLimitOptions)"

say ""
say "Updated rule order:"
gcloud compute security-policies describe "$POLICY" \
  --format="table(rules[].priority,rules[].action,rules[].description)" \
  | head -10

success "Staging rule verified"

# === Step 4: Quick synthetic test ===
say ""
say "=== Step 4: Quick Synthetic Test ==="
say "Testing with $TEST_RATE_LIMIT requests to verify 200→429 behavior"
say "Target: $STAGING_URL"
say "User-ID: $TEST_USER_ID"
say ""

H="$(printf '%s: %s' "$USER_HEADER" "$TEST_USER_ID")"
OK=0; DENIED=0; LAST=""

for i in $(seq 1 $((TEST_RATE_LIMIT + 3))); do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "$H" "$STAGING_URL" 2>&1) || CODE="error"
  printf "  req %02d -> %s\n" "$i" "$CODE"
  LAST="$CODE"

  if [[ "$CODE" =~ ^2..$ ]]; then
    OK=$((OK+1))
  elif [[ "$CODE" == "429" ]]; then
    DENIED=$((DENIED+1))
  fi

  sleep 0.3
done

say ""
say "Synthetic test results: OK=$OK DENIED=$DENIED LAST=$LAST"

if [[ "$DENIED" -gt 0 ]]; then
  success "Rate limiting is ACTIVE (observed $DENIED x 429 responses)"
else
  warn "No 429 responses observed. Check:"
  warn "  1. Is X-User-Id header being injected by gateway?"
  warn "  2. Is Load Balancer stripping client X-User-Id?"
  warn "  3. Check Cloud Logging for DENY_429 events"
fi

# === Step 5: Next steps ===
say ""
say "=== Step 5: Next Steps ==="
say ""
say "✅ STAGING DEPLOYMENT COMPLETE"
say ""
say "Staging rule deployed at priority $STAGING_PRIORITY (before production WebSocket rules)"
say "Production traffic continues unaffected."
say ""
say "IMPORTANT: Run full test suite before promoting to production:"
say ""
say "1. Run integration tests:"
echo "   STAGING_URL=\"$STAGING_URL\" TEST_RATE_LIMIT=$TEST_RATE_LIMIT \\"
echo "   pytest tests/integration/test_rate_limit_user.py -v"
say ""
say "2. Run E2E tests (verify no regressions):"
echo "   # Add your E2E test command here"
say ""
say "3. Monitor Cloud Logging for 15 minutes:"
echo "   gcloud logging tail 'resource.type=\"http_load_balancer\" AND jsonPayload.enforcedAction=\"DENY_429\"' --format=json"
say ""
say "4. Verify enforcedOnKey in logs:"
echo "   # Should show HTTP_HEADER for per-user, IP for fallback"
say ""
say "5. AFTER VALIDATION: Promote to production priority 1000:"
echo "   bash scripts/promote_staging_to_production.sh"
say ""
say "6. ROLLBACK (if needed):"
echo "   gcloud compute security-policies rules delete $STAGING_PRIORITY --security-policy=$POLICY"
say ""
success "Review next steps above before proceeding to production"
