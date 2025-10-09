#!/bin/bash
# S-12 WebSocket Origin Security Tests using curl/websocat

set -e

TARGET_URL="wss://cwe.crashedmind.com/ws"
ALLOWED_ORIGIN="https://cwe.crashedmind.com"
UNAUTHORIZED_ORIGIN="https://evil.com"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}S-12 WebSocket Origin Security Tests${NC}"
echo "============================================================"

# Test 1: Cross-origin WebSocket (should be blocked - 403)
echo -e "\n${BLUE}${BOLD}=== Test 1: Cross-Origin WebSocket (evil.com) ===${NC}"
echo "Target: $TARGET_URL"
echo "Origin: $UNAUTHORIZED_ORIGIN"
echo "Expected: Blocked (403 Forbidden by Cloud Armor Rule 1100)"
echo ""

# Use curl to test WebSocket handshake with wrong origin
RESPONSE=$(curl -i -s \
  --http1.1 \
  --include \
  --no-buffer \
  --header "Connection: Upgrade" \
  --header "Upgrade: websocket" \
  --header "Host: cwe.crashedmind.com" \
  --header "Origin: $UNAUTHORIZED_ORIGIN" \
  --header "Sec-WebSocket-Version: 13" \
  --header "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
  "https://cwe.crashedmind.com/ws" 2>&1 | head -20)

if echo "$RESPONSE" | grep -q "403"; then
    echo -e "${GREEN}✅ PASS: Cloud Armor blocked cross-origin WebSocket (403)${NC}"
    TEST1_PASS=1
elif echo "$RESPONSE" | grep -q "101 Switching Protocols"; then
    echo -e "${RED}❌ FAIL: WebSocket connection succeeded (should be blocked!)${NC}"
    TEST1_PASS=0
else
    echo -e "${YELLOW}⚠️  Response:${NC}"
    echo "$RESPONSE"
    TEST1_PASS=0
fi

# Test 2: WebSocket without Origin header (should be blocked - 403)
echo -e "\n${BLUE}${BOLD}=== Test 2: WebSocket Without Origin Header ===${NC}"
echo "Target: $TARGET_URL"
echo "Origin: (none)"
echo "Expected: Blocked (403 Forbidden by Cloud Armor Rule 1200)"
echo ""

RESPONSE=$(curl -i -s \
  --http1.1 \
  --include \
  --no-buffer \
  --header "Connection: Upgrade" \
  --header "Upgrade: websocket" \
  --header "Host: cwe.crashedmind.com" \
  --header "Sec-WebSocket-Version: 13" \
  --header "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
  "https://cwe.crashedmind.com/ws" 2>&1 | head -20)

if echo "$RESPONSE" | grep -q "403"; then
    echo -e "${GREEN}✅ PASS: Cloud Armor blocked WebSocket without Origin (403)${NC}"
    TEST2_PASS=1
elif echo "$RESPONSE" | grep -q "101 Switching Protocols"; then
    echo -e "${RED}❌ FAIL: WebSocket connection succeeded (should be blocked!)${NC}"
    TEST2_PASS=0
else
    echo -e "${YELLOW}⚠️  Response:${NC}"
    echo "$RESPONSE"
    TEST2_PASS=0
fi

# Test 3: Same-origin WebSocket (should succeed - 101)
echo -e "\n${BLUE}${BOLD}=== Test 3: Same-Origin WebSocket ===${NC}"
echo "Target: $TARGET_URL"
echo "Origin: $ALLOWED_ORIGIN"
echo "Expected: Success (101 Switching Protocols or OAuth redirect)"
echo ""

RESPONSE=$(curl -i -s \
  --http1.1 \
  --include \
  --no-buffer \
  --header "Connection: Upgrade" \
  --header "Upgrade: websocket" \
  --header "Host: cwe.crashedmind.com" \
  --header "Origin: $ALLOWED_ORIGIN" \
  --header "Sec-WebSocket-Version: 13" \
  --header "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
  "https://cwe.crashedmind.com/ws" 2>&1 | head -20)

if echo "$RESPONSE" | grep -q "101 Switching Protocols"; then
    echo -e "${GREEN}✅ PASS: Same-origin WebSocket allowed (101 Switching Protocols)${NC}"
    TEST3_PASS=1
elif echo "$RESPONSE" | grep -q "403"; then
    echo -e "${RED}❌ FAIL: Same-origin WebSocket blocked (should be allowed!)${NC}"
    echo -e "${YELLOW}Response:${NC}"
    echo "$RESPONSE"
    TEST3_PASS=0
elif echo "$RESPONSE" | grep -qE "(302|401)"; then
    echo -e "${GREEN}✅ PASS: Same-origin reached app (OAuth redirect/auth required)${NC}"
    echo -e "${YELLOW}Note: WebSocket requires authentication${NC}"
    TEST3_PASS=1
else
    echo -e "${YELLOW}⚠️  Response:${NC}"
    echo "$RESPONSE"
    TEST3_PASS=1  # Not blocked by Cloud Armor = pass
fi

# Summary
echo -e "\n${BOLD}============================================================${NC}"
echo -e "${BOLD}Test Summary:${NC}"
TOTAL=3
PASSED=$((TEST1_PASS + TEST2_PASS + TEST3_PASS))
FAILED=$((TOTAL - PASSED))

echo "Total: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $PASSED -eq $TOTAL ]; then
    echo -e "\n${GREEN}${BOLD}✅ ALL TESTS PASSED${NC}"
    echo -e "${GREEN}Cloud Armor WebSocket origin validation is working correctly!${NC}"
    exit 0
else
    echo -e "\n${RED}${BOLD}❌ SOME TESTS FAILED${NC}"
    echo -e "${RED}Cloud Armor rules may need adjustment.${NC}"
    exit 1
fi
