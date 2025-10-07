#!/usr/bin/env bash
# scripts/setup_budgets.sh
#
# Purpose: Create monthly GCP billing budget with email alerts
# Usage: PROJECT_ID=cwechatbot BILLING_ACCOUNT_ID=012345-ABCDEF-678901 ./scripts/setup_budgets.sh
#
# Environment variables:
#   PROJECT_ID          - GCP project ID (required)
#   BILLING_ACCOUNT_ID  - Billing account ID (required, format: 012345-ABCDEF-678901)
#   ALERT_EMAIL         - Email for budget alerts (required)
#   MONTHLY_BUDGET_USD  - Monthly budget in USD (default: 1000)
#   ALERT_THRESHOLDS    - Comma-separated % thresholds (default: 50,75,90,100)
#
# Note: Budgets API only supports MONTH/QUARTER/YEAR periods (not DAILY).
#       For daily cost alerts, use Cloud Monitoring on billing metrics.

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:?ERROR: PROJECT_ID must be set}"
BILLING_ACCOUNT_ID="${BILLING_ACCOUNT_ID:?ERROR: BILLING_ACCOUNT_ID must be set (format: 012345-ABCDEF-678901)}"
ALERT_EMAIL="${ALERT_EMAIL:?ERROR: ALERT_EMAIL must be set}"
MONTHLY_BUDGET_USD="${MONTHLY_BUDGET_USD:-1000}"
ALERT_THRESHOLDS="${ALERT_THRESHOLDS:-50,75,90,100}"

echo "=== GCP Billing Budgets Setup ==="
echo "Project: ${PROJECT_ID}"
echo "Billing Account: ${BILLING_ACCOUNT_ID}"
echo "Alert Email: ${ALERT_EMAIL}"
echo "Monthly Budget: \$${MONTHLY_BUDGET_USD} USD"
echo "Alert Thresholds: ${ALERT_THRESHOLDS}%"
echo ""

# Verify gcloud auth
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
  echo "✗ ERROR: No active gcloud authentication"
  echo "  Run: gcloud auth login"
  exit 1
fi

# Verify billing account access
echo "[1/2] Verifying billing account access..."
if ! gcloud billing accounts describe "${BILLING_ACCOUNT_ID}" >/dev/null 2>&1; then
  echo "✗ ERROR: Cannot access billing account '${BILLING_ACCOUNT_ID}'"
  echo ""
  echo "List your billing accounts:"
  echo "  gcloud billing accounts list"
  echo ""
  echo "Grant yourself billing permissions:"
  echo "  gcloud billing accounts add-iam-policy-binding ${BILLING_ACCOUNT_ID} \\"
  echo "    --member='user:$(gcloud config get-value account)' \\"
  echo "    --role='roles/billing.admin'"
  exit 1
fi
echo "✓ Billing account verified"
echo ""

# Build thresholdRules array with correct key: thresholdPercent (0..1)
IFS=',' read -ra THRESHOLDS <<< "${ALERT_THRESHOLDS}"
RULES=()
for t in "${THRESHOLDS[@]}"; do
  # Convert percentage to decimal (50 -> 0.5)
  dec=$(python3 -c "print(round(float(${t})/100.0, 4))")
  RULES+=("{\"thresholdPercent\": ${dec}}")
done
# Join array elements with commas
THRESHOLD_JSON="["
for i in "${!RULES[@]}"; do
  if [[ $i -gt 0 ]]; then
    THRESHOLD_JSON+=","
  fi
  THRESHOLD_JSON+="${RULES[$i]}"
done
THRESHOLD_JSON+="]"

echo "[2/2] Creating monthly budget (\$${MONTHLY_BUDGET_USD})..."
echo "      (Note: Budgets API does not support DAILY period - use Cloud Monitoring for daily alerts)"
echo ""

# Create monthly budget JSON
MONTHLY_BUDGET_JSON=$(cat <<EOF
{
  "displayName": "Monthly Budget - ${PROJECT_ID}",
  "budgetFilter": {
    "projects": ["projects/${PROJECT_ID}"],
    "calendarPeriod": "MONTH"
  },
  "amount": {
    "specifiedAmount": {
      "currencyCode": "USD",
      "units": "${MONTHLY_BUDGET_USD}"
    }
  },
  "thresholdRules": ${THRESHOLD_JSON},
  "notificationsRule": {
    "pubsubTopic": "",
    "schemaVersion": "1.0",
    "monitoringNotificationChannels": [],
    "disableDefaultIamRecipients": false,
    "enableProjectLevelRecipients": true
  },
  "allUpdatesRule": {
    "pubsubTopic": "",
    "schemaVersion": "1.0",
    "monitoringNotificationChannels": [],
    "disableDefaultIamRecipients": false,
    "enableProjectLevelRecipients": true
  }
}
EOF
)

MONTHLY_BUDGET_FILE="/tmp/monthly-budget-${PROJECT_ID}.json"
echo "${MONTHLY_BUDGET_JSON}" > "${MONTHLY_BUDGET_FILE}"

# Check if budget already exists
EXISTING_MONTHLY=$(curl -s -X GET \
  "https://billingbudgets.googleapis.com/v1/billingAccounts/${BILLING_ACCOUNT_ID}/budgets" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  | grep -o "\"displayName\":\"Monthly Budget - ${PROJECT_ID}\"" || true)

if [[ -n "${EXISTING_MONTHLY}" ]]; then
  echo "⚠ Monthly budget already exists (skipping creation)"
else
  MONTHLY_RESPONSE=$(curl -s -X POST \
    "https://billingbudgets.googleapis.com/v1/billingAccounts/${BILLING_ACCOUNT_ID}/budgets" \
    -H "Authorization: Bearer $(gcloud auth print-access-token)" \
    -H "Content-Type: application/json" \
    -d @"${MONTHLY_BUDGET_FILE}")

  if echo "${MONTHLY_RESPONSE}" | grep -q '"name"'; then
    MONTHLY_BUDGET_NAME=$(echo "${MONTHLY_RESPONSE}" | grep -o '"name":"[^"]*"' | cut -d'"' -f4)
    echo "✓ Monthly budget created: ${MONTHLY_BUDGET_NAME}"
  else
    echo "✗ ERROR creating monthly budget:"
    echo "${MONTHLY_RESPONSE}"
    exit 1
  fi
fi
rm -f "${MONTHLY_BUDGET_FILE}"
echo ""

echo "⚠ MANUAL STEP REQUIRED:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Budget alerts are sent to Billing Account Admins by default."
echo ""
echo "To add '${ALERT_EMAIL}' to budget notifications:"
echo ""
echo "1. Go to: https://console.cloud.google.com/billing/${BILLING_ACCOUNT_ID}/budgets"
echo "2. Click the Monthly budget"
echo "3. Under 'Manage notifications' → 'Email alerts to'"
echo "4. Add: ${ALERT_EMAIL}"
echo "5. Save"
echo ""
echo "OR grant billing admin role:"
echo "  gcloud billing accounts add-iam-policy-binding ${BILLING_ACCOUNT_ID} \\"
echo "    --member='user:${ALERT_EMAIL}' \\"
echo "    --role='roles/billing.admin'"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ Budget setup complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Monthly Budget: \$${MONTHLY_BUDGET_USD} USD"
echo "Alert Thresholds: ${ALERT_THRESHOLDS}%"
echo ""
echo "For DAILY cost alerts, use Cloud Monitoring:"
echo "  https://console.cloud.google.com/monitoring/dashboards"
echo ""
echo "View budgets:"
echo "  https://console.cloud.google.com/billing/${BILLING_ACCOUNT_ID}/budgets"
echo ""
echo "List budgets via API:"
echo "  curl -X GET \\"
echo "    'https://billingbudgets.googleapis.com/v1/billingAccounts/${BILLING_ACCOUNT_ID}/budgets' \\"
echo "    -H 'Authorization: Bearer \$(gcloud auth print-access-token)'"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
