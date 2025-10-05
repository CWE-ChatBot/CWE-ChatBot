#!/bin/bash
set -e

FUNCTION_URL="https://pdf-worker-bmgj6wj65a-uc.a.run.app"
SA="cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com"

echo "=== Test 1: Unauthenticated request (expect 403) ==="
curl -sS -w "\nHTTP: %{http_code}\n" "$FUNCTION_URL" 2>&1 | grep -E "(HTTP:|403|Forbidden)" | head -3

echo ""
echo "=== Test 2: GET with auth (expect 405 Method Not Allowed) ==="
TOKEN=$(gcloud auth print-identity-token --impersonate-service-account=$SA --audiences="$FUNCTION_URL" 2>/dev/null)
curl -sS -w "\nHTTP: %{http_code}\n" -H "Authorization: Bearer $TOKEN" "$FUNCTION_URL" 2>&1 | grep -E "(HTTP:|405|Method|error)"

echo ""
echo "=== Test 3: POST with sample.pdf (expect 200 with JSON) ==="
curl -sS -w "\nHTTP: %{http_code}\n" -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/pdf" \
  --data-binary @tests/fixtures/sample.pdf \
  "$FUNCTION_URL"

echo ""
echo "=== Test 4: POST with encrypted.pdf (expect 422) ==="
curl -sS -w "\nHTTP: %{http_code}\n" -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/pdf" \
  --data-binary @tests/fixtures/encrypted.pdf \
  "$FUNCTION_URL"

echo ""
echo "=== Test 5: POST with scanned.pdf (expect 422 or 200 with empty text) ==="
curl -sS -w "\nHTTP: %{http_code}\n" -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/pdf" \
  --data-binary @tests/fixtures/scanned.pdf \
  "$FUNCTION_URL"
