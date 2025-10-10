#!/usr/bin/env bash
#
# promote_staging_to_production.sh
#
# Promotes staging per-user rate limiting rule (priority 900) to production (priority 1000).
# Only run this AFTER full validation in staging (integration + E2E tests passed).
#
# Usage:
#   bash scripts/promote_staging_to_production.sh
#

set -euo pipefail

PROJECT="${PROJECT:-cwechatbot}"
POLICY="${POLICY:-cwe-chatbot-armor}"
STAGING_PRIORITY=900
PRODUCTION_PRIORITY=1000

export CLOUDSDK_CORE_PROJECT="$PROJECT"

say() { printf "\n[promote] %s\n" "$*"; }
warn() { printf "\n[warn] %s\n" "$*" 1>&2; }
success() { printf "\n✅ [success] %s\n" "$*"; }
error() { printf "\n❌ [error] %s\n" "$*" 1>&2; }

# === Confirmation ===
say "=== PROMOTE STAGING TO PRODUCTION ==="
say ""
say "This will:"
say "  1. Get staging rule config from priority $STAGING_PRIORITY"
say "  2. Create/update production rule at priority $PRODUCTION_PRIORITY"
say "  3. Delete staging rule at priority $STAGING_PRIORITY"
say ""
warn "Have you completed ALL validation steps?"
warn "  - Integration tests passed?"
warn "  - E2E tests passed (no regressions)?"
warn "  - Cloud Logging shows correct enforcedOnKey=HTTP_HEADER?"
warn "  - Monitored for 15+ minutes without issues?"
say ""
read -p "Proceed with promotion to production? (yes/no): " CONFIRM

if [[ "$CONFIRM" != "yes" ]]; then
  error "Promotion cancelled by user"
  exit 1
fi

# === Step 1: Verify staging rule exists ===
say ""
say "=== Step 1: Verify Staging Rule ==="

if ! gcloud compute security-policies rules describe "$STAGING_PRIORITY" \
  --security-policy="$POLICY" >/dev/null 2>&1; then
  error "Staging rule at priority $STAGING_PRIORITY not found"
  error "Run staging deployment first: bash scripts/staging_deploy_per_user_rate_limit.sh"
  exit 1
fi

say "Getting staging rule configuration..."
STAGING_CONFIG=$(gcloud compute security-policies rules describe "$STAGING_PRIORITY" \
  --security-policy="$POLICY" \
  --format=json)

success "Staging rule found at priority $STAGING_PRIORITY"

# === Step 2: Check if production rule exists ===
say ""
say "=== Step 2: Check Production Rule Status ==="

if gcloud compute security-policies rules describe "$PRODUCTION_PRIORITY" \
  --security-policy="$POLICY" >/dev/null 2>&1; then
  warn "Production rule at priority $PRODUCTION_PRIORITY already exists"
  warn "This will UPDATE the existing production rule"
  read -p "Continue? (yes/no): " CONTINUE
  if [[ "$CONTINUE" != "yes" ]]; then
    error "Promotion cancelled"
    exit 1
  fi
  PROD_EXISTS=true
else
  say "Production priority $PRODUCTION_PRIORITY is available (will create new rule)"
  PROD_EXISTS=false
fi

# === Step 3: Extract configuration from staging ===
say ""
say "=== Step 3: Extract Configuration ==="

# Extract key values from staging config
EXPRESSION=$(echo "$STAGING_CONFIG" | grep -Po '"expression":\s*"\K[^"]+' || echo "")
RPM=$(echo "$STAGING_CONFIG" | grep -Po '"rateLimitThresholdCount":\s*\K\d+' || echo "60")
INTERVAL=$(echo "$STAGING_CONFIG" | grep -Po '"rateLimitThresholdIntervalSec":\s*\K\d+' || echo "60")
BAN_COUNT=$(echo "$STAGING_CONFIG" | grep -Po '"banThresholdCount":\s*\K\d+' || echo "120")
BAN_INTERVAL=$(echo "$STAGING_CONFIG" | grep -Po '"banThresholdIntervalSec":\s*\K\d+' || echo "60")
BAN_DURATION=$(echo "$STAGING_CONFIG" | grep -Po '"banDurationSec":\s*\K\d+' || echo "300")
ENFORCE_KEY=$(echo "$STAGING_CONFIG" | grep -Po '"enforceOnKey":\s*"\K[^"]+' || echo "HTTP_HEADER")
ENFORCE_KEY_NAME=$(echo "$STAGING_CONFIG" | grep -Po '"enforceOnKeyName":\s*"\K[^"]+' || echo "x-user-id")

say "Staging configuration:"
say "  Expression: $EXPRESSION"
say "  Rate limit: $RPM requests / $INTERVAL seconds"
say "  Ban: $BAN_COUNT requests / $BAN_INTERVAL seconds → $BAN_DURATION seconds ban"
say "  Enforce on: $ENFORCE_KEY ($ENFORCE_KEY_NAME)"

# === Step 4: Create/Update production rule ===
say ""
say "=== Step 4: Deploy to Production Priority $PRODUCTION_PRIORITY ==="

if [[ "$PROD_EXISTS" == "true" ]]; then
  say "Updating existing production rule..."
  gcloud compute security-policies rules update "$PRODUCTION_PRIORITY" \
    --security-policy="$POLICY" \
    --action=rate-based-ban \
    --expression="$EXPRESSION" \
    --rate-limit-threshold-count="$RPM" \
    --rate-limit-threshold-interval-sec="$INTERVAL" \
    --conform-action=allow \
    --exceed-action=deny-429 \
    --ban-threshold-count="$BAN_COUNT" \
    --ban-threshold-interval-sec="$BAN_INTERVAL" \
    --ban-duration-sec="$BAN_DURATION" \
    --enforce-on-key="$ENFORCE_KEY" \
    --enforce-on-key-name="$ENFORCE_KEY_NAME"
else
  say "Creating new production rule..."
  gcloud compute security-policies rules create "$PRODUCTION_PRIORITY" \
    --security-policy="$POLICY" \
    --action=rate-based-ban \
    --expression="$EXPRESSION" \
    --rate-limit-threshold-count="$RPM" \
    --rate-limit-threshold-interval-sec="$INTERVAL" \
    --conform-action=allow \
    --exceed-action=deny-429 \
    --ban-threshold-count="$BAN_COUNT" \
    --ban-threshold-interval-sec="$BAN_INTERVAL" \
    --ban-duration-sec="$BAN_DURATION" \
    --enforce-on-key="$ENFORCE_KEY" \
    --enforce-on-key-name="$ENFORCE_KEY_NAME"
fi

success "Production rule deployed at priority $PRODUCTION_PRIORITY"

# === Step 5: Delete staging rule ===
say ""
say "=== Step 5: Clean Up Staging Rule ==="
say "Deleting staging rule at priority $STAGING_PRIORITY..."

gcloud compute security-policies rules delete "$STAGING_PRIORITY" \
  --security-policy="$POLICY" \
  --quiet

success "Staging rule removed"

# === Step 6: Verify final state ===
say ""
say "=== Step 6: Verify Final Production State ==="

gcloud compute security-policies describe "$POLICY" \
  --format="table(rules[].priority,rules[].action,rules[].description)"

say ""
say "Production rule order:"
say "  Priority 1000: Per-user rate limiting (x-user-id) → 60 rpm/user, 300s ban"
say "  Priority 1100: Per-IP fallback → WebSocket deny (cross-origin)"
say "  Priority 1200: WebSocket deny (no origin)"
say "  Priority 2147483647: Default allow"

success "Promotion complete!"

# === Step 7: Post-deployment monitoring ===
say ""
say "=== Step 7: Post-Deployment Monitoring ==="
say ""
say "Monitor production for the next 30 minutes:"
say ""
say "1. Watch Cloud Logging for DENY_429:"
echo "   gcloud logging tail 'resource.type=\"http_load_balancer\" AND jsonPayload.enforcedAction=\"DENY_429\"'"
say ""
say "2. Check error rates:"
echo "   # Monitor 5xx errors, should remain low"
say ""
say "3. Verify user experience:"
echo "   # Test actual user flows, ensure no false positives"
say ""
say "4. ROLLBACK (if issues detected):"
echo "   gcloud compute security-policies rules delete $PRODUCTION_PRIORITY --security-policy=$POLICY"
say ""
success "Per-user rate limiting now ACTIVE in production at priority $PRODUCTION_PRIORITY"
