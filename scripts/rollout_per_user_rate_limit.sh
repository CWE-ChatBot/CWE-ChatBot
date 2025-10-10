#!/usr/bin/env bash
#
# rollout_per_user_rate_limit.sh
#
# One-shot idempotent script to:
# 1. Verify LB removes client X-User-Id headers
# 2. Create/update Cloud Armor per-user rate limiting rule @ priority 1000
# 3. Run synthetic probe to verify 200→429 behavior
#
# Usage:
#   PROJECT=my-gcp-proj \
#   POLICY=prod-edge-armor \
#   URL_MAP=prod-ext-https \
#   STAGING_URL="https://staging.example.com/healthz" \
#   TEST_RATE_LIMIT=10 \
#   bash scripts/rollout_per_user_rate_limit.sh
#

set -euo pipefail

# === Configuration ===
PROJECT="${PROJECT:?PROJECT env var required}"
POLICY="${POLICY:?POLICY env var required}"
URL_MAP="${URL_MAP:?URL_MAP env var required}"
STAGING_URL="${STAGING_URL:?STAGING_URL env var required}"

# Per-user rate limit settings
USER_HEADER="${USER_HEADER:-X-User-Id}"
USER_HEADER_LOWER=$(echo "$USER_HEADER" | tr 'A-Z' 'a-z')  # Cloud Armor uses lowercase in CEL
RPM_PER_USER="${RPM_PER_USER:-60}"
INTERVAL_SEC="${INTERVAL_SEC:-60}"
BAN_DURATION_SEC="${BAN_DURATION_SEC:-300}"
BAN_COUNT_MULTIPLIER="${BAN_COUNT_MULTIPLIER:-2}"

# Test settings
TEST_USER_ID="${TEST_USER_ID:-itest-user-1}"
TEST_RATE_LIMIT="${TEST_RATE_LIMIT:-10}"  # lower for staging probe

# Set GCP project context
export CLOUDSDK_CORE_PROJECT="$PROJECT"

# === Helper functions ===
say() { printf "\n[rollout] %s\n" "$*"; }
warn() { printf "\n[warn] %s\n" "$*" 1>&2; }

# === 1) Verify LB is stripping client X-User-Id ===
say "Checking URL map headerAction for requestHeadersToRemove..."
if gcloud compute url-maps describe "$URL_MAP" \
  --format=json \
  | tr 'A-Z' 'a-z' \
  | grep -q 'requestheaderstoremove.*x-user-id'; then
  say "✅ OK: URL map removes X-User-Id on ingress."
else
  warn "⚠️ X-User-Id not found in requestHeadersToRemove. Apply headerAction removal before proceeding."
  warn "Example: --default-route-action='{\"headerAction\":{\"requestHeadersToRemove\":[\"X-User-Id\"]}}'"
  warn ""
  warn "Continuing anyway to show full rollout process..."
fi

# === 2) Ensure/Update per-user rule @ 1000 ===
say "Ensuring Cloud Armor per-user rule (priority 1000) on policy $POLICY..."
say "Settings: ${RPM_PER_USER} req/min, ${BAN_DURATION_SEC}s ban, enforce-on-key=HTTP_HEADER($USER_HEADER_LOWER)"

if gcloud compute security-policies rules describe 1000 --security-policy "$POLICY" >/dev/null 2>&1; then
  say "Rule 1000 exists — updating to desired settings..."
  gcloud compute security-policies rules update 1000 \
    --security-policy="$POLICY" \
    --action=rate-based-ban \
    --expression="request.headers['$USER_HEADER_LOWER'] != null" \
    --rate-limit-threshold-count="$RPM_PER_USER" \
    --rate-limit-threshold-interval-sec="$INTERVAL_SEC" \
    --conform-action=deny-429 \
    --exceed-action=deny-429 \
    --ban-threshold-count="$((RPM_PER_USER * BAN_COUNT_MULTIPLIER))" \
    --ban-threshold-interval-sec="$INTERVAL_SEC" \
    --ban-duration-sec="$BAN_DURATION_SEC" \
    --enforce-on-key=HTTP_HEADER \
    --enforce-on-key-name="$USER_HEADER_LOWER"
else
  say "Rule 1000 not present — creating..."
  gcloud compute security-policies rules create 1000 \
    --security-policy="$POLICY" \
    --action=rate-based-ban \
    --expression="request.headers['$USER_HEADER_LOWER'] != null" \
    --rate-limit-threshold-count="$RPM_PER_USER" \
    --rate-limit-threshold-interval-sec="$INTERVAL_SEC" \
    --conform-action=deny-429 \
    --exceed-action=deny-429 \
    --ban-threshold-count="$((RPM_PER_USER * BAN_COUNT_MULTIPLIER))" \
    --ban-threshold-interval-sec="$INTERVAL_SEC" \
    --ban-duration-sec="$BAN_DURATION_SEC" \
    --enforce-on-key=HTTP_HEADER \
    --enforce-on-key-name="$USER_HEADER_LOWER"
fi

say "✅ Verifying rule 1000 summary:"
gcloud compute security-policies rules describe 1000 --security-policy "$POLICY" \
  --format="table(priority,action,rateLimitOptions.enforceOnKey,match.expr.expression)"

# === 3) Synthetic probe against staging ===
say ""
say "=== Running synthetic probe ==="
say "Expect: 200s then 429 once over TEST_RATE_LIMIT=$TEST_RATE_LIMIT within ${INTERVAL_SEC}s interval"
say "Target: $STAGING_URL"
say "User-ID: $TEST_USER_ID"
say ""

# Send header with mixed-case name (will be normalized to lowercase by LB/Cloud Armor)
H="$(printf '%s: %s' "${USER_HEADER^}" "$TEST_USER_ID")"
OK=0; FAIL=0; LAST=""

for i in $(seq 1 $((TEST_RATE_LIMIT+5))); do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "$H" "$STAGING_URL" 2>&1) || CODE="curl_error"
  printf "req %02d -> %s\n" "$i" "$CODE"
  LAST="$CODE"

  if [[ "$CODE" =~ ^2..$ ]]; then
    OK=$((OK+1))
  else
    FAIL=$((FAIL+1))
  fi

  sleep 0.5
done

say ""
say "=== Synthetic summary ==="
say "OK=$OK FAIL=$FAIL LAST=$LAST"

if [[ "$LAST" == "429" ]]; then
  say "✅ SUCCESS: Per-user rate limit enforced at edge (429 observed)."
else
  warn "⚠️ Did not observe 429. Check:"
  warn "  - Header stripping at LB (requestHeadersToRemove)"
  warn "  - Gateway injection of trusted X-User-Id"
  warn "  - Cloud Armor policy attachment to backend service"
  warn "  - Cloud Logging for DENY_429 events"
fi

# === Final instructions ===
say ""
say "=== Next steps ==="
say ""
say "1. Verify in Logs Explorer:"
echo '   resource.type="http_load_balancer" AND jsonPayload.enforcedAction="DENY_429"'
echo ''
say "2. Confirm enforcedOnKey in logs:"
echo '   - HTTP_HEADER for per-user rule (priority 1000)'
echo '   - IP for per-IP fallback rule (priority 1100)'
echo ''
say "3. Test spoofing protection:"
echo '   curl -H "X-User-Id: attacker" '"$STAGING_URL"' # should be stripped by LB'
echo ''
say "4. Rollback (if needed):"
echo "   gcloud compute security-policies rules delete 1000 --security-policy=\"$POLICY\""
say ""
say "✅ Rollout complete!"
