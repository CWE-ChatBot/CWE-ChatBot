#!/usr/bin/env bash
# scripts/setup_rate_limits.sh
#
# Purpose: Create Cloud Armor per-IP rate limiting policy and attach to Load Balancer
# Usage: PROJECT_ID=cwechatbot REGION=us-central1 ./scripts/setup_rate_limits.sh
#
# Environment variables:
#   PROJECT_ID        - GCP project ID (required)
#   REGION            - GCP region (default: us-central1)
#   POLICY            - Security policy name (default: edge-rate-limits)
#   RPM_PER_IP        - Requests per minute per IP (default: 60)
#   INTERVAL_SEC      - Rate limit window in seconds (default: 60)
#   BAN_DURATION_SEC  - Ban duration in seconds (default: 300)
#   BAN_COUNT_MULTIPLIER - Ban threshold multiplier (default: 2)
#   BACKEND           - Backend service name (auto-discovered if not set)

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:?ERROR: PROJECT_ID must be set}"
REGION="${REGION:-us-central1}"
POLICY="${POLICY:-edge-rate-limits}"
RPM_PER_IP="${RPM_PER_IP:-60}"
INTERVAL_SEC="${INTERVAL_SEC:-60}"
BAN_DURATION_SEC="${BAN_DURATION_SEC:-300}"
BAN_COUNT_MULTIPLIER="${BAN_COUNT_MULTIPLIER:-2}"

echo "=== Cloud Armor Rate Limiting Setup ==="
echo "Project: ${PROJECT_ID}"
echo "Region: ${REGION}"
echo "Policy: ${POLICY}"
echo "Rate: ${RPM_PER_IP} req/min per IP"
echo "Ban duration: ${BAN_DURATION_SEC}s"
echo ""

# Set project
gcloud config set project "${PROJECT_ID}"

# Discover backend service if not explicitly provided
if [[ -z "${BACKEND:-}" ]]; then
  echo "[1/5] Discovering backend service..."

  BACKENDS=$(gcloud compute backend-services list \
    --global \
    --format="value(name)" \
    --filter="backends.group:cloudrun" 2>/dev/null || true)

  if [[ -z "${BACKENDS}" ]]; then
    echo "✗ ERROR: No Cloud Run backend services found"
    echo ""
    echo "This script requires an HTTPS Load Balancer with Cloud Run backend."
    echo "Create one first or set BACKEND=<name> explicitly."
    echo ""
    echo "To list all backend services:"
    echo "  gcloud compute backend-services list --global"
    exit 1
  fi

  BACKEND_COUNT=$(echo "${BACKENDS}" | wc -l)

  if [[ ${BACKEND_COUNT} -gt 1 ]]; then
    echo "✗ ERROR: Multiple Cloud Run backend services found:"
    echo ""
    echo "${BACKENDS}" | sed 's/^/  - /'
    echo ""
    echo "Set BACKEND=<name> explicitly to choose one:"
    echo "  BACKEND=<name> ./scripts/setup_rate_limits.sh"
    exit 1
  fi

  BACKEND="${BACKENDS}"
  echo "✓ Auto-discovered backend: ${BACKEND}"
else
  echo "[1/5] Using provided backend: ${BACKEND}"

  # Verify backend exists
  if ! gcloud compute backend-services describe "${BACKEND}" \
      --global --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "✗ ERROR: Backend service '${BACKEND}' not found"
    exit 1
  fi
  echo "✓ Backend verified"
fi
echo ""

# Create or update security policy
echo "[2/5] Creating/updating security policy..."

if gcloud compute security-policies describe "${POLICY}" \
    --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "Policy '${POLICY}' already exists (will update rules)"
else
  gcloud compute security-policies create "${POLICY}" \
    --project="${PROJECT_ID}" \
    --description="Per-IP rate limiting at edge (${RPM_PER_IP} rpm)"
  echo "✓ Created policy '${POLICY}'"
fi
echo ""

# Create per-IP rate limiting rule (priority 1100)
echo "[3/5] Creating per-IP rate limiting rule (priority 1100)..."

BAN_THRESHOLD_COUNT=$(( RPM_PER_IP * BAN_COUNT_MULTIPLIER ))

# Delete existing rule if present (allows re-running script with new values)
gcloud compute security-policies rules delete 1100 \
  --security-policy="${POLICY}" \
  --project="${PROJECT_ID}" \
  --quiet 2>/dev/null || true

gcloud compute security-policies rules create 1100 \
  --security-policy="${POLICY}" \
  --project="${PROJECT_ID}" \
  --action=rate-based-ban \
  --src-ip-ranges="*" \
  --rate-limit-threshold-count="${RPM_PER_IP}" \
  --rate-limit-threshold-interval-sec="${INTERVAL_SEC}" \
  --conform-action=allow \
  --exceed-action=deny-429 \
  --enforce-on-key=IP \
  --ban-threshold-count="${BAN_THRESHOLD_COUNT}" \
  --ban-threshold-interval-sec="${INTERVAL_SEC}" \
  --ban-duration-sec="${BAN_DURATION_SEC}"

echo "✓ Rate limit rule created:"
echo "  - Limit: ${RPM_PER_IP} requests per ${INTERVAL_SEC}s per IP"
echo "  - Action: deny-429 (HTTP 429 Too Many Requests)"
echo "  - Ban: ${BAN_THRESHOLD_COUNT} requests triggers ${BAN_DURATION_SEC}s ban"
echo ""

# Create explicit final allow rule (priority 2147483647 - max int32)
echo "[4/5] Creating explicit final allow rule (priority 2147483647)..."

# Delete existing rule if present
gcloud compute security-policies rules delete 2147483647 \
  --security-policy="${POLICY}" \
  --project="${PROJECT_ID}" \
  --quiet 2>/dev/null || true

gcloud compute security-policies rules create 2147483647 \
  --security-policy="${POLICY}" \
  --project="${PROJECT_ID}" \
  --action=allow \
  --src-ip-ranges="*" \
  --description="Default allow (explicit)"

echo "✓ Final allow rule created (catches all non-rate-limited traffic)"
echo ""

# Attach policy to backend service
echo "[5/5] Attaching policy to backend service..."

gcloud compute backend-services update "${BACKEND}" \
  --global \
  --project="${PROJECT_ID}" \
  --security-policy="${POLICY}"

echo "✓ Policy '${POLICY}' attached to backend '${BACKEND}'"
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ Setup complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Policy: ${POLICY}"
echo "Backend: ${BACKEND}"
echo "Rate limit: ${RPM_PER_IP} req/min per IP"
echo "Ban duration: ${BAN_DURATION_SEC}s after ${BAN_THRESHOLD_COUNT} requests"
echo ""
echo "Next steps:"
echo "  1. Test: ./scripts/hit_until_429.sh https://<your-endpoint>"
echo "  2. Monitor: gcloud logging read 'jsonPayload.enforcedAction=\"DENY_429\"' --limit=10"
echo "  3. Observability: ./scripts/setup_rate_limit_observability.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
