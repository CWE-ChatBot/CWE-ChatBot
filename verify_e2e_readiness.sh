#!/bin/bash
# Phase 5 E2E Readiness Verification Script
# Verifies infrastructure is ready for manual E2E testing

set -e

PROJECT_ID="cwechatbot"
REGION="us-central1"
CHATBOT_URL="https://cwe-chatbot-bmgj6wj65a-uc.a.run.app"
PDF_WORKER_URL="https://pdf-worker-bmgj6wj65a-uc.a.run.app"

echo "=================================="
echo "Phase 5 E2E Readiness Verification"
echo "=================================="
echo ""

# Test 1: Chainlit Service
echo "✓ Test 1: Chainlit Cloud Run service"
CHATBOT_STATUS=$(gcloud run services describe cwe-chatbot --region=$REGION --project=$PROJECT_ID --format="value(status.conditions[0].status)" 2>/dev/null || echo "FAIL")
if [ "$CHATBOT_STATUS" = "True" ]; then
    echo "  ✅ Chainlit service is READY"
else
    echo "  ❌ Chainlit service NOT ready (status: $CHATBOT_STATUS)"
    exit 1
fi

# Test 2: PDF Worker Service
echo "✓ Test 2: PDF Worker Cloud Function"
PDF_WORKER_STATUS=$(gcloud functions describe pdf-worker --region=$REGION --project=$PROJECT_ID --gen2 --format="value(state)" 2>/dev/null || echo "FAIL")
if [ "$PDF_WORKER_STATUS" = "ACTIVE" ]; then
    echo "  ✅ PDF Worker is ACTIVE"
else
    echo "  ❌ PDF Worker NOT active (status: $PDF_WORKER_STATUS)"
    exit 1
fi

# Test 3: PDF_WORKER_URL Environment Variable
echo "✓ Test 3: PDF_WORKER_URL configuration"
CONFIGURED_URL=$(gcloud run services describe cwe-chatbot --region=$REGION --project=$PROJECT_ID --format="value(spec.template.spec.containers[0].env)" 2>/dev/null | grep -oP "PDF_WORKER_URL.*?value': '\K[^']*" || echo "")
if [ "$CONFIGURED_URL" = "$PDF_WORKER_URL" ]; then
    echo "  ✅ PDF_WORKER_URL correctly configured: $CONFIGURED_URL"
else
    echo "  ❌ PDF_WORKER_URL mismatch (expected: $PDF_WORKER_URL, got: $CONFIGURED_URL)"
    exit 1
fi

# Test 4: IAM Permissions
echo "✓ Test 4: IAM permissions for Chainlit → PDF Worker"
SA_EMAIL="cwe-chatbot-run-sa@$PROJECT_ID.iam.gserviceaccount.com"
HAS_INVOKER=$(gcloud functions get-iam-policy pdf-worker --region=$REGION --project=$PROJECT_ID --gen2 --format=json 2>/dev/null | grep -c "$SA_EMAIL" 2>/dev/null || echo "0")
if [ "$HAS_INVOKER" != "0" ]; then
    echo "  ✅ Chainlit SA has invoker permissions"
else
    echo "  ❌ Chainlit SA missing invoker permissions"
    exit 1
fi

# Test 5: Chainlit HTTP Accessibility
echo "✓ Test 5: Chainlit HTTP endpoint"
CHATBOT_HTTP=$(curl -sI "$CHATBOT_URL" -w "%{http_code}" -o /dev/null)
if [ "$CHATBOT_HTTP" = "200" ] || [ "$CHATBOT_HTTP" = "302" ]; then
    echo "  ✅ Chainlit accessible (HTTP $CHATBOT_HTTP)"
else
    echo "  ❌ Chainlit not accessible (HTTP $CHATBOT_HTTP)"
    exit 1
fi

# Test 6: PDF Worker HTTP Accessibility (should be 403 without auth)
echo "✓ Test 6: PDF Worker authentication"
PDF_HTTP=$(curl -sI "$PDF_WORKER_URL" -w "%{http_code}" -o /dev/null)
if [ "$PDF_HTTP" = "403" ]; then
    echo "  ✅ PDF Worker requires authentication (HTTP 403)"
else
    echo "  ⚠️  PDF Worker returned HTTP $PDF_HTTP (expected 403)"
fi

# Test 7: Test Fixtures Exist
echo "✓ Test 7: Test fixtures availability"
FIXTURE_COUNT=$(find tests/fixtures/ -name "*.pdf" 2>/dev/null | wc -l)
if [ "$FIXTURE_COUNT" -ge "3" ]; then
    echo "  ✅ Test fixtures found ($FIXTURE_COUNT PDFs)"
    ls -lh tests/fixtures/*.pdf | awk '{print "    - " $9 " (" $5 ")"}'
else
    echo "  ❌ Missing test fixtures (found $FIXTURE_COUNT, need 3)"
    exit 1
fi

# Test 8: Recent Deployment Check
echo "✓ Test 8: Recent deployment status"
LAST_DEPLOY=$(gcloud run services describe cwe-chatbot --region=$REGION --project=$PROJECT_ID --format="value(status.latestReadyRevisionName)" 2>/dev/null)
DEPLOY_TIME=$(gcloud run revisions describe "$LAST_DEPLOY" --region=$REGION --project=$PROJECT_ID --format="value(metadata.creationTimestamp)" 2>/dev/null)
echo "  ✅ Latest revision: $LAST_DEPLOY"
echo "  ✅ Deployed at: $DEPLOY_TIME"

# Test 9: OAuth Configuration
echo "✓ Test 9: OAuth secrets configured"
OAUTH_SECRETS=$(gcloud run services describe cwe-chatbot --region=$REGION --project=$PROJECT_ID --format="value(spec.template.spec.containers[0].env)" 2>/dev/null | grep -c "OAUTH" || echo "0")
if [ "$OAUTH_SECRETS" -ge "4" ]; then
    echo "  ✅ OAuth configuration present ($OAUTH_SECRETS env vars)"
else
    echo "  ⚠️  OAuth may not be fully configured ($OAUTH_SECRETS env vars found)"
fi

# Test 10: Phase 0 Tests Still Passing
echo "✓ Test 10: Phase 0 tests (local OIDC)"
echo "  Running abbreviated Phase 0 test..."
if python3 test_pdf_worker.py > /tmp/phase0_test.log 2>&1; then
    echo "  ✅ Phase 0 tests PASSING"
else
    echo "  ❌ Phase 0 tests FAILING - see /tmp/phase0_test.log"
    tail -20 /tmp/phase0_test.log
    exit 1
fi

echo ""
echo "=================================="
echo "✅ ALL READINESS CHECKS PASSED"
echo "=================================="
echo ""
echo "Environment is ready for Phase 5 E2E testing."
echo ""
echo "Next steps:"
echo "1. Open browser: $CHATBOT_URL"
echo "2. Follow test guide: docs/E2E_TEST_GUIDE_PHASE_5.md"
echo "3. Complete all 8 manual test cases"
echo "4. Document results in test report"
echo ""
echo "Quick test commands:"
echo "  - Upload sample.pdf and ask: 'What's in this PDF?'"
echo "  - Upload test.txt and ask: 'Summarize this file'"
echo "  - Try encrypted.pdf to test error handling"
echo ""
