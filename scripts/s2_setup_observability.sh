#!/usr/bin/env bash
# S-2: Observability and Alerting Setup Script
# Creates log-based metrics and alert policies for LLM guardrail blocks
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-cwechatbot}"
ALERT_EMAIL="${ALERT_EMAIL:?Error: ALERT_EMAIL must be set (e.g., secops@example.com)}"

echo "=== Observability Setup for LLM Guardrails ==="
echo "Project: ${PROJECT_ID}"
echo "Alert Email: ${ALERT_EMAIL}"
echo ""

gcloud config set project "${PROJECT_ID}"

# Ensure required APIs are enabled
echo "Enabling required APIs..."
gcloud services enable \
  logging.googleapis.com \
  monitoring.googleapis.com \
  --project="${PROJECT_ID}"

echo ""
echo "Creating log-based metric for CRITICAL guardrail blocks..."

# Create metric for CRITICAL guardrail blocks (Model Armor / Safety)
# Note: Using simple counter metric (no value extractor) for compatibility
gcloud logging metrics create llm_guardrail_blocks \
  --description="CRITICAL blocks from Model Armor / Safety filters" \
  --log-filter='severity=CRITICAL AND (jsonPayload.enforcedSecurityPolicy.name:* OR resource.type="aiplatform.googleapis.com/Endpoint")' 2>/dev/null || {
    echo "Metric already exists or creation failed."
    echo "To update, delete first: gcloud logging metrics delete llm_guardrail_blocks"
  }

echo ""
echo "Creating email notification channel..."

# Create email notification channel
cat > /tmp/s2_email_channel.json <<JSON
{
  "type": "email",
  "displayName": "Security Operations Email",
  "enabled": true,
  "labels": {
    "email_address": "${ALERT_EMAIL}"
  }
}
JSON

CHANNEL=$(gcloud beta monitoring channels create \
  --channel-content-from-file=/tmp/s2_email_channel.json \
  --format="value(name)" 2>/dev/null || echo "")

if [ -z "$CHANNEL" ]; then
  echo "Email channel creation failed or already exists."
  echo "Listing existing email channels..."
  gcloud beta monitoring channels list --filter="type=email AND labels.email_address=${ALERT_EMAIL}" --format="value(name)"
  echo ""
  echo "Using existing channel or specify manually in alert policy."
  # Try to get existing channel
  CHANNEL=$(gcloud beta monitoring channels list \
    --filter="type=email AND labels.email_address=${ALERT_EMAIL}" \
    --format="value(name)" --limit=1)
fi

echo "Notification channel: ${CHANNEL}"
echo ""

echo "Creating alert policy for guardrail blocks..."

# Create alert policy for any blocks in 5-minute window
cat > /tmp/s2_alert_policy.json <<JSON
{
  "displayName": "CRITICAL: LLM guardrail blocks > 0 (5m)",
  "combiner": "OR",
  "conditions": [
    {
      "displayName": "Guardrail blocks detected in 5m window",
      "conditionThreshold": {
        "filter": "metric.type=\"logging.googleapis.com/user/llm_guardrail_blocks\" AND resource.type=\"global\"",
        "comparison": "COMPARISON_GT",
        "thresholdValue": 0,
        "duration": "300s",
        "aggregations": [
          {
            "alignmentPeriod": "300s",
            "perSeriesAligner": "ALIGN_RATE"
          }
        ],
        "trigger": {
          "count": 1
        }
      }
    }
  ],
  "notificationChannels": ["${CHANNEL}"],
  "documentation": {
    "content": "LLM guardrail block detected. Model Armor or Safety filters prevented potentially unsafe content.\n\nInvestigate in Logs Explorer:\n1. Filter: severity=CRITICAL\n2. Review policy name and blocked content hash\n3. Follow S-2 runbook for triage and tuning\n\nRunbook: docs/runbooks/S-2-guardrails-runbook.md",
    "mimeType": "text/markdown"
  },
  "alertStrategy": {
    "autoClose": "1800s"
  }
}
JSON

gcloud alpha monitoring policies create \
  --policy-from-file=/tmp/s2_alert_policy.json || {
    echo "Alert policy creation failed or already exists."
    echo "To update, delete first and recreate."
  }

# Cleanup temp files
rm -f /tmp/s2_email_channel.json /tmp/s2_alert_policy.json

echo ""
echo "✅ Observability setup complete!"
echo ""
echo "Summary:"
echo "- Log-based metric: llm_guardrail_blocks"
echo "- Notification channel: ${CHANNEL}"
echo "- Alert policy: CRITICAL: LLM guardrail blocks > 0 (5m)"
echo ""
echo "Next steps:"
echo "1. Test with smoke test script: poetry run python scripts/s2_smoke_test.py"
echo "2. Review runbook: docs/runbooks/S-2-guardrails-runbook.md"
echo "3. Monitor alerts at: https://console.cloud.google.com/monitoring/alerting"
echo ""
