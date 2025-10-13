#!/usr/bin/env bash
# Staging deployment script for CWE ChatBot with Chainlit data layer
# Tests new features without affecting production

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

# Print functions
print_info() { echo -e "${GREEN}✓${NC} $1"; }
print_warn() { echo -e "${YELLOW}⚠${NC}  $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }

# Deploy staging
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CWE ChatBot STAGING Deployment"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
print_warn "Deploying to STAGING - production unaffected"

gcloud config set project "$PROJECT" --quiet

print_info "Building image..."
gcloud builds submit --config=apps/chatbot/cloudbuild.yaml --suppress-logs --quiet

IMAGE="gcr.io/${PROJECT}/cwe-chatbot:latest"

print_info "Deploying staging service: $SERVICE"
gcloud run deploy "$SERVICE" \
    --region="$REGION" \
    --image="$IMAGE" \
    --service-account="cwe-chatbot-run-sa@${PROJECT}.iam.gserviceaccount.com" \
    --add-cloudsql-instances="cwechatbot:us-central1:cwe-postgres-prod" \
    --vpc-connector="run-us-central1" \
    --vpc-egress=private-ranges-only \
    --memory=512Mi \
    --cpu=1 \
    --min-instances=0 \
    --max-instances=5 \
    --concurrency=80 \
    --timeout=300 \
    --allow-unauthenticated \
    --execution-environment=gen2 \
    --set-env-vars="GOOGLE_CLOUD_PROJECT=${PROJECT},DB_HOST=10.43.0.3,DB_PORT=5432,DB_NAME=postgres,DB_USER=app_user,DB_SSLMODE=require,ENABLE_OAUTH=true,AUTH_MODE=hybrid,CHAINLIT_URL=https://staging-cwe.crashedmind.com,PUBLIC_ORIGIN=https://staging-cwe.crashedmind.com,CSP_MODE=compatible,PDF_WORKER_URL=https://pdf-worker-bmgj6wj65a-uc.a.run.app,CLOUD_SQL_CONNECTION_NAME=cwechatbot:us-central1:cwe-postgres-prod" \
    --update-secrets="GEMINI_API_KEY=gemini-api-key:latest,DB_PASSWORD=db-password-app-user:latest,CHAINLIT_AUTH_SECRET=chainlit-auth-secret:latest,TEST_API_KEY=test-api-key:latest,OAUTH_GOOGLE_CLIENT_ID=oauth-google-client-id:latest,OAUTH_GOOGLE_CLIENT_SECRET=oauth-google-client-secret:latest,OAUTH_GITHUB_CLIENT_ID=oauth-github-client-id:latest,OAUTH_GITHUB_CLIENT_SECRET=oauth-github-client-secret:latest" \
    --quiet

STAGING_URL=$(gcloud run services describe "$SERVICE" --region="$REGION" --format='value(status.url)')

echo ""
print_info "Staging deployed: $STAGING_URL"
print_info "Test the staging environment before promoting to production"
echo ""
