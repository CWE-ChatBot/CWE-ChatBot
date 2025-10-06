#!/usr/bin/env bash
#
# Comprehensive Test Runner for CWE ChatBot
# Runs all unit, integration, security, and E2E tests unattended
#

set -e  # Exit on first failure

echo "================================"
echo "CWE ChatBot Test Suite"
echo "================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_SUITES=0

run_test_suite() {
    local suite_name="$1"
    local test_command="$2"

    echo -e "${YELLOW}Running: $suite_name${NC}"
    echo "Command: $test_command"

    if eval "$test_command"; then
        echo -e "${GREEN}✓ PASSED: $suite_name${NC}"
        ((PASSED_TESTS++))
    else
        echo -e "${RED}✗ FAILED: $suite_name${NC}"
        ((FAILED_TESTS++))
    fi
    ((TOTAL_TESTS++))
    echo ""
}

run_optional_suite() {
    local suite_name="$1"
    local test_command="$2"
    local skip_reason="$3"

    echo -e "${YELLOW}Optional: $suite_name${NC}"

    if eval "$test_command 2>&1 | grep -q 'no tests ran\|collected 0 items'"; then
        echo -e "${YELLOW}⊘ SKIPPED: $suite_name ($skip_reason)${NC}"
        ((SKIPPED_SUITES++))
    else
        run_test_suite "$suite_name" "$test_command"
    fi
    echo ""
}

echo "1. Unit Tests"
echo "----------------------------------------"

# Chatbot unit tests
run_test_suite "Chatbot Unit Tests" \
    "cd apps/chatbot && poetry run pytest tests/unit/ -v --tb=short -x"

# CWE Ingestion unit tests
run_test_suite "CWE Ingestion Unit Tests" \
    "cd apps/cwe_ingestion && poetry run pytest tests/unit/ -v --tb=short -x"

echo ""
echo "2. Integration Tests"
echo "----------------------------------------"

# Chatbot integration tests
run_test_suite "Chatbot Integration Tests" \
    "cd apps/chatbot && poetry run pytest tests/integration/ -v --tb=short -x"

# CWE Ingestion integration tests
run_optional_suite "CWE Ingestion Integration Tests" \
    "cd apps/cwe_ingestion && poetry run pytest tests/integration/ -v --tb=short -x" \
    "requires live database"

echo ""
echo "3. Security Tests"
echo "----------------------------------------"

# Story-specific security tests
run_test_suite "Story 4.3 Security Tests" \
    "python3 tests/scripts/test_story_4_3_security.py"

run_test_suite "Command Injection Prevention" \
    "python3 tests/scripts/test_command_injection_fix.py"

run_test_suite "Container Security" \
    "python3 tests/scripts/test_container_security_fix.py"

echo ""
echo "4. File Processing Tests"
echo "----------------------------------------"

# PDF worker integration (if available)
run_optional_suite "PDF Worker Integration" \
    "cd apps/chatbot && poetry run pytest tests/test_pdf_worker_integration.py -v" \
    "requires PDF worker deployment"

# File processor tests
run_test_suite "File Processor Tests" \
    "cd apps/chatbot && poetry run pytest tests/test_file_processor.py -v --tb=short"

echo ""
echo "5. End-to-End Tests (Optional)"
echo "----------------------------------------"

# E2E tests require running server - skip by default
echo -e "${YELLOW}⊘ SKIPPED: E2E tests (require running server)${NC}"
echo "To run E2E tests manually:"
echo "  cd apps/chatbot && poetry run pytest tests/e2e/ -v"
((SKIPPED_SUITES++))

echo ""
echo "================================"
echo "Test Summary"
echo "================================"
echo -e "Total Suites: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"
echo -e "${YELLOW}Skipped: $SKIPPED_SUITES${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    exit 1
fi
