#!/bin/bash

# Quick Conversational Flow Test Script
# Tests the running CWE ChatBot at localhost:8080 for key conversational patterns

echo "🤖 CWE ChatBot Quick Flow Tests"
echo "================================="
echo "Testing against running application at http://localhost:8080"
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TOTAL_TESTS=0
PASSED_TESTS=0

# Function to run a test
run_test() {
    local test_name="$1"
    local description="$2"

    echo -e "${YELLOW}🧪 Test:${NC} $test_name"
    echo "   $description"
    echo
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

# Function to mark test result
mark_result() {
    local passed="$1"
    local reason="$2"

    if [ "$passed" = "true" ]; then
        echo -e "   ${GREEN}✅ PASS${NC}: $reason"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "   ${RED}❌ FAIL${NC}: $reason"
    fi
    echo
}

echo "📋 MANUAL TEST INSTRUCTIONS"
echo "============================"
echo
echo "Please run these tests manually in your browser at http://localhost:8080"
echo "Copy and paste each query, then verify the expected behavior:"
echo

# Test 1: Off-topic query handling
run_test "Off-Topic Query Detection" "Test that non-security queries are redirected appropriately"
echo "   Query: 'what is a dog?'"
echo "   Expected: Polite redirection message mentioning cybersecurity focus"
echo "   Should contain: 'cybersecurity assistant', 'CWE analysis', 'security topics'"
echo "   Should NOT contain: 'animal', 'mammal', 'pet'"
echo "   ➤ Did this work correctly? (y/n): "
read -r response
if [[ $response =~ ^[Yy]$ ]]; then
    mark_result true "Off-topic query redirected appropriately"
else
    mark_result false "Off-topic query not handled correctly"
fi

# Test 2: Follow-up context maintenance
run_test "Follow-up Context Maintenance" "Test that 'tell me more' maintains CWE context"
echo "   Step 1 - Query: 'what is CWE-79?'"
echo "   Expected: Information about Cross-site Scripting (XSS)"
echo "   Step 2 - Query: 'tell me more'"
echo "   Expected: Additional CWE-79/XSS details (NOT a different CWE!)"
echo "   ➤ Did the follow-up maintain CWE-79 context? (y/n): "
read -r response
if [[ $response =~ ^[Yy]$ ]]; then
    mark_result true "Follow-up context maintained correctly"
else
    mark_result false "Follow-up context switched to wrong CWE"
fi

# Test 3: Security topic processing
run_test "Security Topic Processing" "Test that legitimate security queries are processed"
echo "   Query: 'what is SQL injection?'"
echo "   Expected: Detailed response about SQL injection vulnerabilities"
echo "   Should contain: CWE information, prevention guidance, examples"
echo "   Should NOT contain: redirection message"
echo "   ➤ Was this processed as a security topic? (y/n): "
read -r response
if [[ $response =~ ^[Yy]$ ]]; then
    mark_result true "Security topic processed correctly"
else
    mark_result false "Security topic incorrectly redirected"
fi

# Test 4: UI elements
run_test "UI Text Visibility" "Test that popup windows show text properly"
echo "   Action: Click the settings gear icon"
echo "   Expected: Settings dialog opens with visible text and controls"
echo "   Action: Click persona dropdown"
echo "   Expected: All persona options visible with text"
echo "   ➤ Are all UI elements showing text properly? (y/n): "
read -r response
if [[ $response =~ ^[Yy]$ ]]; then
    mark_result true "UI elements display text correctly"
else
    mark_result false "UI elements missing text"
fi

# Test 5: Color system
run_test "Color System Visibility" "Test that CWE/CVE colors are visible"
echo "   Expected: Interface should show CWE Blue, CVE Orange, CWE Maroon"
echo "   Look for: Colored borders, buttons, accents throughout interface"
echo "   Top border should be orange, message borders blue, etc."
echo "   ➤ Are the brand colors (blue, orange, maroon) visible? (y/n): "
read -r response
if [[ $response =~ ^[Yy]$ ]]; then
    mark_result true "Brand colors visible in interface"
else
    mark_result false "Brand colors not visible"
fi

# Test 6: Complex follow-up scenario
run_test "Complex Context Switching" "Test context switching between different CWEs"
echo "   Step 1 - Query: 'what is CWE-79?'"
echo "   Step 2 - Query: 'what about CWE-89?'"
echo "   Step 3 - Query: 'tell me more'"
echo "   Expected: Step 3 should give more info about CWE-89 (SQL injection), not CWE-79"
echo "   ➤ Did the context switch correctly to CWE-89? (y/n): "
read -r response
if [[ $response =~ ^[Yy]$ ]]; then
    mark_result true "Context switching works correctly"
else
    mark_result false "Context switching failed"
fi

# Summary
echo "📊 TEST SUMMARY"
echo "==============="
echo "Total Tests: $TOTAL_TESTS"
echo "Passed: $PASSED_TESTS"
echo "Failed: $((TOTAL_TESTS - PASSED_TESTS))"

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED!${NC}"
    echo "The CWE ChatBot conversational flows are working correctly."
else
    success_rate=$(($PASSED_TESTS * 100 / $TOTAL_TESTS))
    echo -e "${YELLOW}Success Rate: $success_rate%${NC}"

    if [ $success_rate -ge 80 ]; then
        echo -e "${GREEN}✅ Good overall performance${NC} - minor issues to address"
    elif [ $success_rate -ge 60 ]; then
        echo -e "${YELLOW}⚠️  Moderate performance${NC} - several issues need attention"
    else
        echo -e "${RED}❌ Poor performance${NC} - major issues need fixing"
    fi
fi

echo
echo "💡 TIP: For automated testing in CI/CD, consider implementing WebSocket"
echo "   communication to test these flows programmatically."

echo
echo "🔗 Application URL: http://localhost:8080"
echo "📋 Detailed test cases: manual_test_flows.md"