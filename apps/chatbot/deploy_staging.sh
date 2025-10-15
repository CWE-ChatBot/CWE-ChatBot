#!/usr/bin/env bash
# Staging deployment script for CWE ChatBot with Chainlit data layer
# Tests new features without affecting production
#
# Secure-by-default: private ingress, IAM-gated, optional test bypass in hybrid mode
# Deploys:
# 1. PDF Worker (secure, service-account-only access)
# 2. CWE ChatBot Staging (OAuth + hybrid auth for testing)

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
PROJECT="${PROJECT:-cwechatbot}"
REGION="${REGION:-us-central1}"
SERVICE="cwe-chatbot-staging"
PDF_WORKER_SERVICE="pdf-worker-staging"
CHATBOT_SA="cwe-chatbot-run-sa@${PROJECT}.iam.gserviceaccount.com"

# Exposure and access control
EXPOSURE_MODE="${EXPOSURE_MODE:-private}"  # private|public
# Optional: grant a specific principal access to staging when private
# e.g. TESTER_PRINCIPAL='user:alice@example.com' or 'group:devs@example.com'
TESTER_PRINCIPAL="${TESTER_PRINCIPAL:-}"
# Use VPC connector if needed
VPC_CONNECTOR="${VPC_CONNECTOR:-run-us-central1}"

# Print functions
print_info() { echo -e "${GREEN}✓${NC} $1"; }
print_warn() { echo -e "${YELLOW}⚠${NC}  $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }

# Deploy staging
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CWE ChatBot STAGING Deployment (ChatBot + PDF Worker)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print_warn "Deploying to STAGING - production unaffected"

gcloud config set project "$PROJECT" --quiet

# Ingress/auth flags — keep private unless you have an HTTPS LB + Cloud Armor
ALLOW_FLAG="--no-allow-unauthenticated"
INGRESS_FLAG="--ingress=internal-and-cloud-load-balancing"
if [[ "$EXPOSURE_MODE" == "public" ]]; then
  print_warn "Public mode requested. Strongly recommend HTTPS LB + Cloud Armor."
  ALLOW_FLAG="--allow-unauthenticated"
  INGRESS_FLAG="--ingress=all"
fi

# ============================================================================
# STEP 1: Deploy PDF Worker (Secure, Service Account Only)
# ============================================================================
echo ""
print_info "Step 1/2: Deploying PDF Worker (secure mode)"

# Build PDF worker image
print_info "Building PDF worker image..."
gcloud builds submit apps/pdf_worker \
    --tag="gcr.io/${PROJECT}/pdf-worker:latest" \
    --quiet

# Deploy PDF worker with NO public access (service account only)
print_info "Deploying PDF worker service (service-account-only access)..."
gcloud run deploy "$PDF_WORKER_SERVICE" \
    --region="$REGION" \
    --image="gcr.io/${PROJECT}/pdf-worker:latest" \
    --service-account="$CHATBOT_SA" \
    --ingress=internal-and-cloud-load-balancing \
    --memory=1Gi \
    --cpu=1 \
    --min-instances=0 \
    --max-instances=10 \
    --concurrency=10 \
    --timeout=60 \
    --no-allow-unauthenticated \
    --execution-environment=gen2 \
    --set-env-vars="ISOLATE_SANITIZER=true,MODEL_ARMOR_ENABLED=true,LOG_EXECUTION_ID=true" \
    --quiet

# Get PDF worker URL
PDF_WORKER_URL=$(gcloud run services describe "$PDF_WORKER_SERVICE" --region="$REGION" --format='value(status.url)')
print_info "PDF worker deployed: $PDF_WORKER_URL"

# Grant chatbot service account permission to invoke PDF worker
print_info "Granting chatbot service account invoker permission..."
gcloud run services add-iam-policy-binding "$PDF_WORKER_SERVICE" \
    --region="$REGION" \
    --member="serviceAccount:$CHATBOT_SA" \
    --role="roles/run.invoker" \
    --quiet

print_info "PDF worker security: ONLY $CHATBOT_SA can invoke (no public access)"

# ============================================================================
# STEP 2: Deploy ChatBot Staging
# ============================================================================
echo ""
print_info "Step 2/2: Deploying ChatBot Staging"

print_info "Ingress/auth: ${INGRESS_FLAG#*=}, ${ALLOW_FLAG}"

print_info "Building chatbot image..."
gcloud builds submit --config=apps/chatbot/cloudbuild.yaml --suppress-logs --quiet

IMAGE="gcr.io/${PROJECT}/cwe-chatbot:latest"

print_info "Deploying chatbot staging service: $SERVICE"
gcloud run deploy "$SERVICE" \
    --region="$REGION" \
    --image="$IMAGE" \
    --service-account="$CHATBOT_SA" \
    --add-cloudsql-instances="cwechatbot:us-central1:cwe-postgres-prod" \
    --vpc-connector="$VPC_CONNECTOR" \
    --vpc-egress=private-ranges-only \
    $INGRESS_FLAG \
    --memory=512Mi \
    --cpu=1 \
    --min-instances=0 \
    --max-instances=5 \
    --concurrency=80 \
    --timeout=300 \
    $ALLOW_FLAG \
    --execution-environment=gen2 \
    --set-env-vars="GOOGLE_CLOUD_PROJECT=${PROJECT},DB_HOST=10.43.0.3,DB_PORT=5432,DB_NAME=postgres,DB_USER=app_user,DB_SSLMODE=require,ENABLE_OAUTH=true,AUTH_MODE=hybrid,API_AUTH_MODE=hybrid,CHAINLIT_URL=https://staging-cwe.crashedmind.com,PUBLIC_ORIGIN=https://staging-cwe.crashedmind.com,CSP_MODE=strict,PDF_WORKER_URL=${PDF_WORKER_URL},CLOUD_SQL_CONNECTION_NAME=cwechatbot:us-central1:cwe-postgres-prod" \
    --update-secrets="GEMINI_API_KEY=gemini-api-key:latest,DB_PASSWORD=db-password-app-user:latest,CHAINLIT_AUTH_SECRET=chainlit-auth-secret:latest,TEST_API_KEY=test-api-key:latest,OAUTH_GOOGLE_CLIENT_ID=oauth-google-client-id:latest,OAUTH_GOOGLE_CLIENT_SECRET=oauth-google-client-secret:latest,OAUTH_GITHUB_CLIENT_ID=oauth-github-client-id:latest,OAUTH_GITHUB_CLIENT_SECRET=oauth-github-client-secret:latest" \
    --quiet

STAGING_URL=$(gcloud run services describe "$SERVICE" --region="$REGION" --format='value(status.url)')

# If private, optionally grant a tester principal IAM invoker for browser/CI access
if [[ "$EXPOSURE_MODE" != "public" && -n "$TESTER_PRINCIPAL" ]]; then
  print_info "Granting Cloud Run Invoker to $TESTER_PRINCIPAL"
  gcloud run services add-iam-policy-binding "$SERVICE" \
    --region="$REGION" \
    --member="$TESTER_PRINCIPAL" \
    --role="roles/run.invoker" \
    --quiet
fi

# ============================================================================
# Deployment Summary
# ============================================================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Deployment Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print_info "PDF Worker:  $PDF_WORKER_URL"
print_info "             🔒 Service account access only (no public access)"
print_info "ChatBot:     $STAGING_URL"
print_info "             🔐 OAuth (Google/GitHub) + hybrid test-login"
echo ""
print_warn "SECURITY SUMMARY:"
echo "   - ChatBot ingress: ${INGRESS_FLAG#*=}, auth: ${ALLOW_FLAG}"
echo "   - PDF Worker: private (service-account-only, no unauthenticated access)"
echo "   - App auth mode: API_AUTH_MODE=hybrid (OAuth Bearer OR secure test key in staging)"
if [[ "$EXPOSURE_MODE" == "public" ]]; then
  echo "   ⚠️  PUBLIC MODE - Front with HTTPS LB + Cloud Armor for DDoS protection"
else
  echo "   ✓ PRIVATE MODE - IAM authentication required for all access"
  if [[ -n "$TESTER_PRINCIPAL" ]]; then
    echo "   ✓ Tester access granted: $TESTER_PRINCIPAL"
  else
    echo "   ℹ️  To grant access: TESTER_PRINCIPAL='user:you@example.com' ./deploy_staging.sh"
  fi
fi
echo ""
print_info "Test the staging environment before promoting to production"
echo ""
