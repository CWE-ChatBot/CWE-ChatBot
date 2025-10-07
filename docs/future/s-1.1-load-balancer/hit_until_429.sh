#!/usr/bin/env bash
# scripts/hit_until_429.sh
#
# Purpose: Load test script to validate Cloud Armor rate limiting
# Usage: ./scripts/hit_until_429.sh https://your-endpoint.run.app
#
# This script sends requests rapidly until receiving HTTP 429 (Too Many Requests)
# to verify Cloud Armor per-IP rate limiting is working correctly.
#
# Environment variables:
#   MAX_REQUESTS    - Maximum requests to send (default: 100)
#   REQUEST_DELAY   - Delay between requests in seconds (default: 0.5)
#   ENDPOINT_PATH   - Path to append to URL (default: /)

set -euo pipefail

# Configuration
ENDPOINT="${1:-}"
MAX_REQUESTS="${MAX_REQUESTS:-100}"
REQUEST_DELAY="${REQUEST_DELAY:-0.5}"
ENDPOINT_PATH="${ENDPOINT_PATH:-/}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Usage
if [[ -z "${ENDPOINT}" ]]; then
  echo "Usage: $0 <endpoint-url>"
  echo ""
  echo "Example:"
  echo "  $0 https://cwe-chatbot-xxxx.run.app"
  echo ""
  echo "Options (env vars):"
  echo "  MAX_REQUESTS=${MAX_REQUESTS}    - Max requests to send"
  echo "  REQUEST_DELAY=${REQUEST_DELAY}  - Seconds between requests"
  echo "  ENDPOINT_PATH=${ENDPOINT_PATH}    - Path to test"
  exit 1
fi

# Normalize URL
FULL_URL="${ENDPOINT}${ENDPOINT_PATH}"
FULL_URL="${FULL_URL//\/\//\/}" # Remove double slashes except in https://

echo "=== Cloud Armor Rate Limit Test ==="
echo "Endpoint: ${FULL_URL}"
echo "Max requests: ${MAX_REQUESTS}"
echo "Request delay: ${REQUEST_DELAY}s"
echo ""
echo "Expected behavior:"
echo "  - First ~60 requests: HTTP 200"
echo "  - After rate limit: HTTP 429"
echo "  - Ban duration: 300s (5 minutes)"
echo ""
echo "Press Ctrl+C to stop"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Counters
SUCCESS_COUNT=0
RATE_LIMITED_COUNT=0
ERROR_COUNT=0
FIRST_429=0

# Start time
START_TIME=$(date +%s)

# Send requests
for i in $(seq 1 "${MAX_REQUESTS}"); do
  # Get current time for rate calculation
  CURRENT_TIME=$(date +%s)
  ELAPSED=$((CURRENT_TIME - START_TIME))
  RATE=0
  if [[ ${ELAPSED} -gt 0 ]]; then
    RATE=$((i / ELAPSED))
  fi

  # Send request
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "User-Agent: rate-limit-test-script" \
    --max-time 10 \
    "${FULL_URL}" 2>/dev/null || echo "000")

  # Format output with color
  TIMESTAMP=$(date "+%H:%M:%S")
  printf "[%s] Request #%-3d | HTTP %s" "${TIMESTAMP}" "${i}" "${HTTP_CODE}"

  case "${HTTP_CODE}" in
    200|201|204)
      printf " ${GREEN}✓${NC}"
      SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
      ;;
    429)
      printf " ${RED}✗ RATE LIMITED${NC}"
      RATE_LIMITED_COUNT=$((RATE_LIMITED_COUNT + 1))

      # Record first 429
      if [[ ${FIRST_429} -eq 0 ]]; then
        FIRST_429=${i}
        printf " ${YELLOW}(FIRST BLOCK at request #${i})${NC}"
      fi
      ;;
    000)
      printf " ${RED}✗ TIMEOUT/ERROR${NC}"
      ERROR_COUNT=$((ERROR_COUNT + 1))
      ;;
    *)
      printf " ${YELLOW}? UNEXPECTED${NC}"
      ERROR_COUNT=$((ERROR_COUNT + 1))
      ;;
  esac

  # Show running stats
  printf " | Rate: ~%d req/min | Total: %d OK, %d 429, %d ERR\n" \
    "$((RATE * 60))" "${SUCCESS_COUNT}" "${RATE_LIMITED_COUNT}" "${ERROR_COUNT}"

  # Stop if we hit rate limit threshold
  if [[ ${RATE_LIMITED_COUNT} -ge 5 ]]; then
    echo ""
    echo "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo "${YELLOW}Rate limit threshold reached (5 consecutive 429s)${NC}"
    echo "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    break
  fi

  # Delay between requests
  sleep "${REQUEST_DELAY}"
done

# Summary
END_TIME=$(date +%s)
TOTAL_ELAPSED=$((END_TIME - START_TIME))
TOTAL_REQUESTS=$((SUCCESS_COUNT + RATE_LIMITED_COUNT + ERROR_COUNT))
AVG_RATE=0
if [[ ${TOTAL_ELAPSED} -gt 0 ]]; then
  AVG_RATE=$((TOTAL_REQUESTS * 60 / TOTAL_ELAPSED))
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Duration: ${TOTAL_ELAPSED}s"
echo "Total requests: ${TOTAL_REQUESTS}"
echo "Average rate: ~${AVG_RATE} req/min"
echo ""
echo "Results:"
printf "  ${GREEN}✓ Success (2xx):${NC}    %d requests\n" "${SUCCESS_COUNT}"
printf "  ${RED}✗ Rate limited (429):${NC} %d requests\n" "${RATE_LIMITED_COUNT}"
printf "  ${YELLOW}? Errors/timeouts:${NC}   %d requests\n" "${ERROR_COUNT}"
echo ""

# Validation
if [[ ${FIRST_429} -gt 0 ]]; then
  echo "First rate limit at request #${FIRST_429}"

  if [[ ${FIRST_429} -ge 55 && ${FIRST_429} -le 65 ]]; then
    echo "${GREEN}✓ PASS: Rate limit triggered near expected threshold (60 rpm)${NC}"
  else
    echo "${YELLOW}⚠ WARNING: Rate limit at request #${FIRST_429} (expected ~60)${NC}"
  fi
else
  echo "${YELLOW}⚠ WARNING: No rate limiting observed${NC}"
  echo ""
  echo "Possible issues:"
  echo "  - Cloud Armor policy not attached to backend"
  echo "  - Rate limit threshold higher than test rate"
  echo "  - Backend service not fronted by Load Balancer"
fi
echo ""

# Check logs suggestion
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Next steps:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Check Cloud Armor logs:"
echo "   gcloud logging read 'resource.type=\"http_load_balancer\" AND jsonPayload.enforcedAction=\"DENY_429\"' \\"
echo "     --limit=10 --format=json"
echo ""
echo "2. Verify metric increments:"
echo "   gcloud logging metrics describe rate_limit_blocks"
echo ""
echo "3. Check alert fired:"
echo "   gcloud alpha monitoring policies list --filter='displayName:\"Rate-limit blocks\"'"
echo ""
echo "4. Wait ${BAN_DURATION_SEC:-300}s for ban to expire before re-testing"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
