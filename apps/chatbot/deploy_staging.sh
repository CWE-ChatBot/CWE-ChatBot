#!/usr/bin/env bash
# Staging deployment script for CWE ChatBot
# Deploys with AUTH_MODE=hybrid for E2E testing with test-login endpoint
# NEVER use this script for production deployment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROJECT="${PROJECT:-cwechatbot}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-cwe-chatbot-staging}"  # Different service name for staging

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

# Safety check - prevent accidental production deployment
safety_check() {
    print_header "🛡️  Staging Deployment Safety Check"

    if [[ "$SERVICE" == "cwe-chatbot" ]]; then
        print_error "DANGER: SERVICE='cwe-chatbot' is production!"
        print_error "This script is for STAGING only (cwe-chatbot-staging)"
        print_error "Use apps/chatbot/deploy.sh for production"
        exit 1
    fi

    print_info "Service name: $SERVICE (staging)"
    print_info "This deployment will use AUTH_MODE=hybrid"
    print_warn "NEVER deploy to production with AUTH_MODE=hybrid"

    echo ""
    echo "This will deploy to STAGING with the following configuration:"
    echo "  - AUTH_MODE=hybrid (enables test-login endpoint)"
    echo "  - TEST_API_KEY from Secret Manager"
    echo "  - OAuth enabled for interactive testing"
    echo ""
    read -p "Continue with staging deployment? (yes/no): " confirm

    if [[ "$confirm" != "yes" ]]; then
        print_warn "Deployment cancelled"
        exit 0
    fi
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

    # Verify test-api-key secret exists
    if ! gcloud secrets describe test-api-key &>/dev/null; then
        print_error "Secret 'test-api-key' not found in Secret Manager"
        print_error "Create it first: echo 'your-secure-key' | gcloud secrets create test-api-key --data-file=-"
        exit 1
    fi
    print_info "Secret 'test-api-key' exists"
}

# Build Docker image
build_image() {
    print_header "Building Docker Image"

    # Use same image as production (:latest tag)
    # Staging behavior is controlled by AUTH_MODE=hybrid env var, not image tag
    IMAGE_TAG="us-central1-docker.pkg.dev/${PROJECT}/chatbot/chatbot:latest"

    print_info "Building image from project root (shared image with production)"
    print_info "Image: $IMAGE_TAG"
    print_info "Note: Staging behavior controlled by AUTH_MODE=hybrid environment variable"

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
    print_header "Deploying to Cloud Run (STAGING)"

    IMAGE_TAG="us-central1-docker.pkg.dev/${PROJECT}/chatbot/chatbot:latest"

    print_info "Service: $SERVICE"
    print_info "Region: $REGION"
    print_info "Image: $IMAGE_TAG"
    print_warn "AUTH_MODE=hybrid (test-login endpoint ENABLED)"

    gcloud run deploy "$SERVICE" \
        --region="$REGION" \
        --image="$IMAGE_TAG" \
        --service-account="cwe-chatbot-run-sa@${PROJECT}.iam.gserviceaccount.com" \
        --vpc-connector="run-us-central1" \
        --vpc-egress=private-ranges-only \
        --memory=512Mi \
        --cpu=1 \
        --min-instances=0 \
        --max-instances=5 \
        --concurrency=40 \
        --timeout=300 \
        --allow-unauthenticated \
        --execution-environment=gen2 \
        --set-env-vars="GOOGLE_CLOUD_PROJECT=${PROJECT},DB_HOST=10.43.0.3,DB_PORT=5432,DB_NAME=postgres,DB_USER=app_user,DB_SSLMODE=require,ENABLE_OAUTH=true,AUTH_MODE=hybrid,CHAINLIT_URL=https://cwe-staging.crashedmind.com,PUBLIC_ORIGIN=https://cwe-staging.crashedmind.com,CSP_MODE=compatible,HSTS_MAX_AGE=31536000,PDF_WORKER_URL=https://pdf-worker-bmgj6wj65a-uc.a.run.app" \
        --quiet || {
        print_error "Deployment failed"
        exit 1
    }

    print_info "Secrets retrieved from Secret Manager at runtime (including test-api-key)"
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

    # Check health endpoint
    print_info "Checking health endpoint..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$SERVICE_URL/health" || echo "000")

    if [[ "$HTTP_CODE" == "200" ]]; then
        print_info "Health check passed (HTTP 200)"
    else
        print_warn "Health check returned HTTP $HTTP_CODE"
        print_warn "Service may still be starting up..."
    fi

    # CRITICAL: Verify test-login endpoint is available (hybrid mode)
    print_info "Verifying test-login endpoint is available (AUTH_MODE=hybrid)..."
    TEST_LOGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$SERVICE_URL/api/v1/test-login" -H "X-API-Key: invalid" || echo "000")

    if [[ "$TEST_LOGIN_CODE" == "401" ]]; then
        print_info "✓ test-login endpoint available (returned 401 for invalid key as expected)"
    elif [[ "$TEST_LOGIN_CODE" == "404" ]]; then
        print_error "✗ test-login endpoint NOT available (returned 404)"
        print_error "This indicates AUTH_MODE is NOT set to 'hybrid'"
        print_error "Check environment variables in Cloud Run console"
        exit 1
    else
        print_warn "⚠ test-login endpoint returned unexpected HTTP $TEST_LOGIN_CODE"
    fi

    # Verify configuration
    print_info "Verifying capacity limits..."
    MAX_SCALE=$(gcloud run services describe "$SERVICE" --region="$REGION" --format='value(spec.template.metadata.annotations."autoscaling.knative.dev/maxScale")' 2>/dev/null || echo "unknown")
    CONCURRENCY=$(gcloud run services describe "$SERVICE" --region="$REGION" --format='value(spec.template.spec.containerConcurrency)' 2>/dev/null || echo "unknown")

    if [[ "$MAX_SCALE" == "5" ]] && [[ "$CONCURRENCY" == "40" ]]; then
        print_info "Capacity limits correct for staging: maxScale=$MAX_SCALE, concurrency=$CONCURRENCY"
    else
        print_warn "Capacity limits: maxScale=$MAX_SCALE, concurrency=$CONCURRENCY"
    fi
}

# Show next steps
show_next_steps() {
    print_header "Staging Deployment Complete"

    SERVICE_URL=$(gcloud run services describe "$SERVICE" --region="$REGION" --format='value(status.url)' 2>/dev/null)

    echo ""
    echo "🎉 CWE ChatBot STAGING deployed successfully!"
    echo ""
    echo "Service URL: $SERVICE_URL"
    echo ""
    echo "⚠️  STAGING Configuration:"
    echo "   - AUTH_MODE=hybrid (test-login endpoint enabled)"
    echo "   - TEST_API_KEY available from Secret Manager"
    echo "   - Lower capacity limits (max 5 instances, 40 concurrent)"
    echo ""
    echo "Next Steps:"
    echo ""
    echo "1. Test the test-login endpoint:"
    echo "   export TEST_API_KEY=\$(gcloud secrets versions access latest --secret=test-api-key)"
    echo "   curl -X POST ${SERVICE_URL}/api/v1/test-login -H \"X-API-Key: \$TEST_API_KEY\""
    echo ""
    echo "2. Run E2E tests:"
    echo "   cd apps/chatbot/tests"
    echo "   CHATBOT_URL=${SERVICE_URL} TEST_API_KEY=\$TEST_API_KEY poetry run pytest integration/test_cwe_e2e_playwright.py"
    echo ""
    echo "3. Monitor logs:"
    echo "   gcloud logging tail 'resource.type=\"cloud_run_revision\" resource.labels.service_name=\"${SERVICE}\"'"
    echo ""
    echo "4. View metrics:"
    echo "   https://console.cloud.google.com/run/detail/${REGION}/${SERVICE}/metrics?project=${PROJECT}"
    echo ""
    echo "⚠️  REMINDER: NEVER deploy to production with AUTH_MODE=hybrid"
    echo "   Production deployment: ./apps/chatbot/deploy.sh"
    echo ""
}

# Main execution
main() {
    print_header "CWE ChatBot STAGING Deployment Script"

    safety_check
    check_prerequisites
    build_image
    deploy_service
    verify_deployment
    show_next_steps
}

# Run main function
main "$@"
