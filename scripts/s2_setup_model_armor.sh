#!/usr/bin/env bash
# S-2: Model Armor Setup Script
# Creates Model Armor template with guardrail shields for CWE ChatBot
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-cwechatbot}"
LOCATION="${LOCATION:-us-central1}"
TEMPLATE_ID="${TEMPLATE_ID:-llm-guardrails-default}"

echo "=== Model Armor Setup for CWE ChatBot ==="
echo "Project: ${PROJECT_ID}"
echo "Location: ${LOCATION}"
echo "Template: ${TEMPLATE_ID}"
echo ""

# Ensure APIs are enabled
echo "Enabling required APIs..."
gcloud services enable \
  aiplatform.googleapis.com \
  modelarmor.googleapis.com \
  --project="${PROJECT_ID}"

echo ""
echo "Creating Model Armor template with guardrail shields..."
echo "Note: DANGEROUS_CONTENT is set to HIGH confidence to avoid blocking"
echo "      legitimate vulnerability information in CWE ChatBot responses."
echo ""

# Create Model Armor template with shields
# DANGEROUS_CONTENT: HIGH confidence to avoid blocking vulnerability info
# Other categories: HIGH confidence for fail-closed security
gcloud model-armor templates create "${TEMPLATE_ID}" \
  --project="${PROJECT_ID}" \
  --location="${LOCATION}" \
  --basic-config-filter-enforcement=enabled \
  --pi-and-jailbreak-filter-settings-enforcement=enabled \
  --rai-settings-filters='[
    {"filterType":"hate-speech","confidenceLevel":"HIGH"},
    {"filterType":"harassment","confidenceLevel":"HIGH"},
    {"filterType":"sexually-explicit","confidenceLevel":"HIGH"},
    {"filterType":"dangerous","confidenceLevel":"HIGH"}
  ]' || {
    echo ""
    echo "Template creation failed or already exists."
    echo "To update existing template, delete it first:"
    echo "  gcloud model-armor templates delete ${TEMPLATE_ID} --location=${LOCATION} --project=${PROJECT_ID}"
    exit 1
  }

echo ""
echo "✅ Model Armor template created successfully: ${TEMPLATE_ID}"
echo ""
echo "Next steps:"
echo "1. Bind this template to your Vertex AI serving path:"
echo "   - Console: Security → Model Armor → Integrations → Vertex AI"
echo "   - Select project: ${PROJECT_ID}, location: ${LOCATION}"
echo "   - Bind template: ${TEMPLATE_ID} to your endpoint/gateway"
echo ""
echo "2. Update app endpoint (ENV or DNS) to route through guarded path"
echo ""
echo "3. Run observability setup: ./scripts/s2_setup_observability.sh"
echo ""
