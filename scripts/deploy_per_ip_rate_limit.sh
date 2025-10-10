#!/bin/bash
# deploy_per_ip_rate_limit.sh
# Deploy per-IP rate limiting to Cloud Armor (Story S-1 baseline DDoS protection)
#
# Purpose: Add per-IP rate limiting as fallback protection for ALL traffic
# Priority: 1300 (after WebSocket rules at 1000-1200, before per-user at 900)
# Note: Per-user limits (priority 900) are more permissive, so they're checked first

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

PROJECT="${PROJECT:-cwechatbot}"
POLICY="${POLICY:-cwe-chatbot-armor}"
PRIORITY="${PRIORITY:-1300}"

# Per-IP Rate Limiting (Baseline DDoS Protection)
# More restrictive than per-user (60 RPM) - acts as safety net
RPM_PER_IP="${RPM_PER_IP:-300}"          # 300 requests/minute per IP
INTERVAL_SEC="${INTERVAL_SEC:-60}"       # 60-second window

# Ban settings - double the rate limit for ban threshold
BAN_COUNT_MULTIPLIER="${BAN_COUNT_MULTIPLIER:-2}"
BAN_DURATION_SEC="${BAN_DURATION_SEC:-600}"  # 10-minute ban

# ============================================================================
# Validation
# ============================================================================

echo "=================================="
echo "Per-IP Rate Limiting Deployment"
echo "=================================="
echo "Project:         $PROJECT"
echo "Policy:          $POLICY"
echo "Priority:        $PRIORITY"
echo "Rate Limit:      $RPM_PER_IP requests per $INTERVAL_SEC seconds"
echo "Ban Threshold:   $((RPM_PER_IP * BAN_COUNT_MULTIPLIER)) requests per $INTERVAL_SEC seconds"
echo "Ban Duration:    $BAN_DURATION_SEC seconds"
echo "=================================="
echo ""

# Check if rule already exists
if gcloud compute security-policies rules describe "$PRIORITY" \
    --security-policy="$POLICY" \
    --project="$PROJECT" &>/dev/null; then
    echo "❌ Rule at priority $PRIORITY already exists"
    echo ""
    echo "Current rule configuration:"
    gcloud compute security-policies rules describe "$PRIORITY" \
        --security-policy="$POLICY" \
        --project="$PROJECT" \
        --format=yaml
    echo ""
    echo "To update, first delete: gcloud compute security-policies rules delete $PRIORITY --security-policy=$POLICY"
    exit 1
fi

# ============================================================================
# Deploy Per-IP Rate Limiting Rule
# ============================================================================

echo "Creating per-IP rate limiting rule at priority $PRIORITY..."
echo ""

gcloud compute security-policies rules create "$PRIORITY" \
  --security-policy="$POLICY" \
  --project="$PROJECT" \
  --action=rate-based-ban \
  --expression="true" \
  --rate-limit-threshold-count="$RPM_PER_IP" \
  --rate-limit-threshold-interval-sec="$INTERVAL_SEC" \
  --conform-action=allow \
  --exceed-action=deny-429 \
  --ban-threshold-count="$((RPM_PER_IP * BAN_COUNT_MULTIPLIER))" \
  --ban-threshold-interval-sec="$INTERVAL_SEC" \
  --ban-duration-sec="$BAN_DURATION_SEC" \
  --enforce-on-key=ip \
  --description="S-1: Per-IP rate limiting (baseline DDoS protection)"

echo ""
echo "✅ Per-IP rate limiting rule deployed successfully"
echo ""

# ============================================================================
# Verification
# ============================================================================

echo "Verifying deployment..."
echo ""

gcloud compute security-policies rules describe "$PRIORITY" \
  --security-policy="$POLICY" \
  --project="$PROJECT" \
  --format=yaml

echo ""
echo "=================================="
echo "Current Cloud Armor Rule Priorities"
echo "=================================="
gcloud compute security-policies describe "$POLICY" \
  --project="$PROJECT" \
  --format="table(
    rules[].priority:label=PRIORITY,
    rules[].action:label=ACTION,
    rules[].description:label=DESCRIPTION
  )" | sort -n

echo ""
echo "✅ Deployment complete!"
echo ""
echo "Next steps:"
echo "1. Run integration tests: poetry run pytest tests/integration/test_rate_limit_ip.py"
echo "2. Monitor Cloud Logging for rate limit events"
echo "3. Verify rule evaluation order in production traffic"
