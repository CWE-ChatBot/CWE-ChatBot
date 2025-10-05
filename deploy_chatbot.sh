#!/usr/bin/env bash
# Deploy CWE ChatBot to Cloud Run with Direct Private IP Connection
# No Cloud SQL Proxy - Uses direct Private IP connection to Cloud SQL
#
# Prerequisites:
#   - Cloud SQL instance with Private IP configured
#   - VPC connector created for Cloud Run
#   - Secrets created in Secret Manager
#   - Docker image built and pushed to Artifact Registry

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

PROJECT="${PROJECT:-cwechatbot}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-cwe-chatbot}"

# Cloud SQL Configuration (Direct Private IP)
DB_HOST="${DB_HOST:-10.43.0.3}"  # Private IP of Cloud SQL instance
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-postgres}"  # Database containing cwe_chunks table
DB_USER="${DB_USER:-app_user}"
DB_SSLMODE="${DB_SSLMODE:-require}"

# Cloud Run Configuration
MEMORY="${MEMORY:-512Mi}"
CPU="${CPU:-1}"
MIN_INSTANCES="${MIN_INSTANCES:-1}"
MAX_INSTANCES="${MAX_INSTANCES:-10}"
CONCURRENCY="${CONCURRENCY:-40}"

# VPC Connector (required for Private IP access)
VPC_CONNECTOR="${VPC_CONNECTOR:-run-us-central1}"

# Runtime Service Account
RUN_SA="${RUN_SA:-cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com}"

# Secret Manager Secret Names
SECRET_GEMINI_KEY="${SECRET_GEMINI_KEY:-gemini-api-key}"
SECRET_DB_PASSWORD="${SECRET_DB_PASSWORD:-db-password-app-user}"
SECRET_CHAINLIT_AUTH="${SECRET_CHAINLIT_AUTH:-chainlit-auth-secret}"
SECRET_GOOGLE_CLIENT_ID="${SECRET_GOOGLE_CLIENT_ID:-oauth-google-client-id}"
SECRET_GOOGLE_CLIENT_SECRET="${SECRET_GOOGLE_CLIENT_SECRET:-oauth-google-client-secret}"
SECRET_GITHUB_CLIENT_ID="${SECRET_GITHUB_CLIENT_ID:-oauth-github-client-id}"
SECRET_GITHUB_CLIENT_SECRET="${SECRET_GITHUB_CLIENT_SECRET:-oauth-github-client-secret}"

# Docker Image
IMAGE_URI="${IMAGE_URI:-us-central1-docker.pkg.dev/cwechatbot/chatbot/chatbot:latest}"

# ============================================================================
# FUNCTIONS
# ============================================================================

print_header() {
    echo "============================================================================"
    echo "$1"
    echo "============================================================================"
}

print_info() {
    echo "✓ $1"
}

print_warning() {
    echo "⚠️  $1"
}

print_error() {
    echo "❌ $1"
}

# ============================================================================
# MAIN DEPLOYMENT
# ============================================================================

print_header "CWE ChatBot Deployment Configuration"
echo "Project:        $PROJECT"
echo "Region:         $REGION"
echo "Service:        $SERVICE"
echo "Database:       $DB_HOST:$DB_PORT/$DB_NAME (user: $DB_USER)"
echo "VPC Connector:  $VPC_CONNECTOR"
echo "Service Account: $RUN_SA"
echo "Image:          $IMAGE_URI"
echo ""

# Confirm deployment
read -p "Deploy with these settings? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    exit 0
fi

# Set project
print_info "Setting project to $PROJECT"
gcloud config set project "$PROJECT" >/dev/null 2>&1

# Deploy to Cloud Run
print_header "Deploying to Cloud Run"

gcloud run deploy "$SERVICE" \
  --region="$REGION" \
  --image="$IMAGE_URI" \
  --service-account="$RUN_SA" \
  --vpc-connector="$VPC_CONNECTOR" \
  --vpc-egress=private-ranges-only \
  --memory="$MEMORY" \
  --cpu="$CPU" \
  --min-instances="$MIN_INSTANCES" \
  --max-instances="$MAX_INSTANCES" \
  --concurrency="$CONCURRENCY" \
  --timeout=300 \
  --allow-unauthenticated \
  --set-env-vars="DB_HOST=${DB_HOST},DB_PORT=${DB_PORT},DB_NAME=${DB_NAME},DB_USER=${DB_USER},DB_SSLMODE=${DB_SSLMODE},PDF_WORKER_URL=https://pdf-worker-bmgj6wj65a-uc.a.run.app" \
  --update-secrets="GEMINI_API_KEY=${SECRET_GEMINI_KEY}:latest,DB_PASSWORD=${SECRET_DB_PASSWORD}:latest,CHAINLIT_AUTH_SECRET=${SECRET_CHAINLIT_AUTH}:latest,OAUTH_GOOGLE_CLIENT_ID=${SECRET_GOOGLE_CLIENT_ID}:latest,OAUTH_GOOGLE_CLIENT_SECRET=${SECRET_GOOGLE_CLIENT_SECRET}:latest,OAUTH_GITHUB_CLIENT_ID=${SECRET_GITHUB_CLIENT_ID}:latest,OAUTH_GITHUB_CLIENT_SECRET=${SECRET_GITHUB_CLIENT_SECRET}:latest"

# Get service URL
SERVICE_URL=$(gcloud run services describe "$SERVICE" --region="$REGION" --format='value(status.url)')

print_header "Deployment Complete"
print_info "Service URL: $SERVICE_URL"
echo ""
echo "Next steps:"
echo "1. Update OAuth redirect URIs:"
echo "   - Google: ${SERVICE_URL}/auth/callback/google"
echo "   - GitHub: ${SERVICE_URL}/auth/callback/github"
echo ""
echo "2. Test the deployment:"
echo "   curl -sI $SERVICE_URL"
echo ""
echo "3. Monitor logs:"
echo "   gcloud logging read 'resource.type=\"cloud_run_revision\" resource.labels.service_name=\"${SERVICE}\"' --limit=50 --project=$PROJECT"
echo ""
echo "4. Check initialization:"
echo "   Open $SERVICE_URL in browser and verify OAuth login works"
echo ""

print_header "Verification Commands"
echo "# Check service status"
echo "gcloud run services describe $SERVICE --region=$REGION --format='value(status.conditions[0].status)'"
echo ""
echo "# Check environment variables"
echo "gcloud run services describe $SERVICE --region=$REGION --format=json | jq -r '.spec.template.spec.containers[0].env[]'"
echo ""
echo "# Check recent logs"
echo "gcloud logging read 'resource.labels.service_name=\"${SERVICE}\" severity>=WARNING' --limit=20 --project=$PROJECT"
echo ""
