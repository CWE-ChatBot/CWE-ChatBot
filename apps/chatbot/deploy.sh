#!/usr/bin/env bash
# Quick deployment script for CWE ChatBot
# Builds and deploys to Google Cloud Run with proper configuration

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROJECT="${PROJECT:-cwechatbot}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-cwe-chatbot}"

# Print functions
print_info() { echo -e "${GREEN}✓${NC} $1"; }
print_warn() { echo -e "${YELLOW}⚠${NC}  $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_header() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    if ! command -v gcloud &> /dev/null; then
        print_error "gcloud CLI not found. Install from: https://cloud.google.com/sdk/docs/install"
        exit 1
    fi
    print_info "gcloud CLI installed"

    if ! command -v docker &> /dev/null; then
        print_error "Docker not found. Install from: https://docs.docker.com/get-docker/"
        exit 1
    fi
    print_info "Docker installed"

    # Check if in project root
    if [[ ! -f "apps/chatbot/main.py" ]]; then
        print_error "Must run from project root directory"
        echo "    Current: $(pwd)"
        echo "    Expected: /path/to/cwe_chatbot_bmad"
        exit 1
    fi
    print_info "Running from project root"

    # Set and verify project
    gcloud config set project "$PROJECT" --quiet
    CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null)
    if [[ "$CURRENT_PROJECT" != "$PROJECT" ]]; then
        print_error "Failed to set project to $PROJECT"
        exit 1
    fi
    print_info "GCP project: $PROJECT"
}

# Build Docker image
build_image() {
    print_header "Building Docker Image"

    IMAGE_TAG="us-central1-docker.pkg.dev/${PROJECT}/chatbot/chatbot:latest"

    print_info "Building from project root (required for apps/cwe_ingestion access)"
    print_info "Image: $IMAGE_TAG"

    gcloud builds submit \
        --config=apps/chatbot/cloudbuild.yaml \
        --suppress-logs \
        --quiet || {
        print_error "Build failed"
        exit 1
    }

    print_info "Image built successfully"
}

# Deploy to Cloud Run
deploy_service() {
    print_header "Deploying to Cloud Run"

    IMAGE_TAG="us-central1-docker.pkg.dev/${PROJECT}/chatbot/chatbot:latest"

    print_info "Service: $SERVICE"
    print_info "Region: $REGION"
    print_info "Image: $IMAGE_TAG"

    print_info "Mounting secrets from Secret Manager (including ALLOWED_USERS)"

    gcloud run deploy "$SERVICE" \
        --region="$REGION" \
        --image="$IMAGE_TAG" \
        --service-account="cwe-chatbot-run-sa@${PROJECT}.iam.gserviceaccount.com" \
        --vpc-connector="run-us-central1" \
        --vpc-egress=private-ranges-only \
        --memory=512Mi \
        --cpu=1 \
        --min-instances=1 \
        --max-instances=10 \
        --concurrency=80 \
        --timeout=300 \
        --allow-unauthenticated \
        --execution-environment=gen2 \
        --set-env-vars="GOOGLE_CLOUD_PROJECT=${PROJECT},DB_HOST=10.43.0.3,DB_PORT=5432,DB_NAME=postgres,DB_USER=app_user,DB_SSLMODE=require,ENABLE_OAUTH=true,AUTH_MODE=oauth,CHAINLIT_URL=https://cwe.crashedmind.com,PUBLIC_ORIGIN=https://cwe.crashedmind.com,CSP_MODE=compatible,HSTS_MAX_AGE=31536000,PDF_WORKER_URL=https://pdf-worker-bmgj6wj65a-uc.a.run.app" \
        --update-secrets="GEMINI_API_KEY=gemini-api-key:latest,DB_PASSWORD=db-password-app-user:latest,CHAINLIT_AUTH_SECRET=chainlit-auth-secret:latest,OAUTH_GOOGLE_CLIENT_ID=oauth-google-client-id:latest,OAUTH_GOOGLE_CLIENT_SECRET=oauth-google-client-secret:latest,OAUTH_GITHUB_CLIENT_ID=oauth-github-client-id:latest,OAUTH_GITHUB_CLIENT_SECRET=oauth-github-client-secret:latest,ALLOWED_USERS=allowed-users:latest" \
        --quiet || {
        print_error "Deployment failed"
        exit 1
    }

    print_info "Secrets retrieved from Secret Manager at runtime (including ALLOWED_USERS)"

    print_info "Deployment successful"
}

# Verify deployment
verify_deployment() {
    print_header "Verifying Deployment"

    SERVICE_URL=$(gcloud run services describe "$SERVICE" --region="$REGION" --format='value(status.url)' 2>/dev/null)

    if [[ -z "$SERVICE_URL" ]]; then
        print_error "Could not get service URL"
        exit 1
    fi

    print_info "Service URL: $SERVICE_URL"

    # CRITICAL: Verify test-login endpoint is NOT available (production)
    print_info "Verifying test-login endpoint is disabled (AUTH_MODE=oauth)..."
    TEST_LOGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$SERVICE_URL/api/v1/test-login" -H "X-API-Key: test" || echo "000")

    if [[ "$TEST_LOGIN_CODE" == "404" ]]; then
        print_info "✓ test-login endpoint properly disabled (returned 404 as expected)"
    elif [[ "$TEST_LOGIN_CODE" == "401" ]] || [[ "$TEST_LOGIN_CODE" == "200" ]]; then
        print_error "✗ CRITICAL: test-login endpoint is AVAILABLE in production!"
        print_error "This indicates AUTH_MODE is set to 'hybrid' instead of 'oauth'"
        print_error "SECURITY ISSUE: Test-only authentication bypass enabled in production"
        exit 1
    else
        print_warn "⚠ test-login endpoint returned unexpected HTTP $TEST_LOGIN_CODE"
    fi

    # Check health endpoint
    print_info "Checking health endpoint..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/health" || echo "000")

    if [[ "$HTTP_CODE" == "200" ]]; then
        print_info "Health check passed (HTTP 200)"
    else
        print_warn "Health check returned HTTP $HTTP_CODE"
        print_warn "Service may still be starting up..."
    fi

    # Verify configuration
    print_info "Verifying capacity limits..."
    MAX_SCALE=$(gcloud run services describe "$SERVICE" --region="$REGION" --format='value(spec.template.metadata.annotations."autoscaling.knative.dev/maxScale")' 2>/dev/null || echo "unknown")
    CONCURRENCY=$(gcloud run services describe "$SERVICE" --region="$REGION" --format='value(spec.template.spec.containerConcurrency)' 2>/dev/null || echo "unknown")

    if [[ "$MAX_SCALE" == "10" ]] && [[ "$CONCURRENCY" == "80" ]]; then
        print_info "Capacity limits correct: maxScale=$MAX_SCALE, concurrency=$CONCURRENCY"
    else
        print_warn "Capacity limits: maxScale=$MAX_SCALE, concurrency=$CONCURRENCY"
    fi
}

# Show next steps
show_next_steps() {
    print_header "Deployment Complete"

    SERVICE_URL=$(gcloud run services describe "$SERVICE" --region="$REGION" --format='value(status.url)' 2>/dev/null)

    echo ""
    echo "🎉 CWE ChatBot deployed successfully!"
    echo ""
    echo "Service URL: $SERVICE_URL"
    echo ""
    echo "Next Steps:"
    echo ""
    echo "1. Update OAuth redirect URIs:"
    echo "   Google: ${SERVICE_URL}/auth/oauth/google/callback"
    echo "   GitHub: ${SERVICE_URL}/auth/oauth/github/callback"
    echo ""
    echo "2. Test the deployment:"
    echo "   curl ${SERVICE_URL}/health"
    echo "   open ${SERVICE_URL}  # Open in browser"
    echo ""
    echo "3. Monitor logs:"
    echo "   gcloud logging tail 'resource.type=\"cloud_run_revision\" resource.labels.service_name=\"${SERVICE}\"'"
    echo ""
    echo "4. View metrics:"
    echo "   https://console.cloud.google.com/run/detail/${REGION}/${SERVICE}/metrics?project=${PROJECT}"
    echo ""
}

# Main execution
main() {
    print_header "CWE ChatBot Deployment Script"

    check_prerequisites
    build_image
    deploy_service
    verify_deployment
    show_next_steps
}

# Run main function
main "$@"
