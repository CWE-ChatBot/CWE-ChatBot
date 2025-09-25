#!/bin/bash
#
# Comprehensive E2E Test Runner for CWE ChatBot
# Runs complete end-to-end test suite with different configurations
#
# Usage:
#   ./run_e2e_tests.sh [OPTIONS]
#
# Options:
#   --quick       Run only smoke tests (fast)
#   --full        Run all tests including cross-browser and performance
#   --with-db     Run tests that require database and API keys
#   --headless    Run in headless mode (default)
#   --visible     Run with visible browser windows
#   --browser     Specify browser: chromium, firefox, webkit, all (default: chromium)
#   --parallel    Run tests in parallel where possible
#   --help        Show this help message


# Example: ./run_e2e_tests.sh --full --with-db --headless --browser chromium
set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_TIMEOUT=${TEST_TIMEOUT:-120}
PLAYWRIGHT_HEADLESS=${PLAYWRIGHT_HEADLESS:-true}
BROWSER_TYPE="chromium"
TEST_MODE="quick"
WITH_DATABASE=false
PARALLEL_TESTS=false

echo -e "${BLUE}🧪 CWE ChatBot - E2E Test Suite Runner${NC}"
echo "============================================"

# Function to print usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --quick       Run only smoke tests (default, ~5 minutes)"
    echo "  --full        Run comprehensive test suite (~20-30 minutes)"
    echo "  --with-db     Include tests requiring database and API keys"
    echo "  --headless    Run in headless mode (default)"
    echo "  --visible     Run with visible browser windows (for debugging)"
    echo "  --browser     Browser: chromium (default), firefox, webkit, all"
    echo "  --parallel    Run tests in parallel (faster but uses more resources)"
    echo "  --help        Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  TEST_TIMEOUT               Test timeout in seconds (default: 120)"
    echo "  PLAYWRIGHT_HEADLESS        true/false (default: true)"
    echo "  GEMINI_API_KEY            Required for database tests"
    echo "  POSTGRES_HOST             PostgreSQL host (for database tests)"
    echo "  POSTGRES_PORT             PostgreSQL port"
    echo "  POSTGRES_DATABASE         PostgreSQL database name"
    echo "  POSTGRES_USER             PostgreSQL username"
    echo "  POSTGRES_PASSWORD         PostgreSQL password"
    echo ""
    echo "Examples:"
    echo "  $0                         # Quick smoke tests"
    echo "  $0 --full                 # Complete test suite"
    echo "  $0 --with-db --full       # Everything including database tests"
    echo "  $0 --visible --browser firefox  # Firefox with visible windows"
    echo "  $0 --parallel --quick     # Fast parallel execution"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            TEST_MODE="quick"
            shift
            ;;
        --full)
            TEST_MODE="full"
            shift
            ;;
        --with-db)
            WITH_DATABASE=true
            shift
            ;;
        --headless)
            PLAYWRIGHT_HEADLESS=true
            shift
            ;;
        --visible)
            PLAYWRIGHT_HEADLESS=false
            shift
            ;;
        --browser)
            BROWSER_TYPE="$2"
            shift 2
            ;;
        --parallel)
            PARALLEL_TESTS=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            usage
            exit 1
            ;;
    esac
done

# Change to chatbot directory
echo -e "${BLUE}📁 Changing to chatbot directory...${NC}"
cd "$SCRIPT_DIR"

# Check if poetry is available
if ! command -v poetry &> /dev/null; then
    echo -e "${RED}❌ Poetry not found. Please install Poetry first.${NC}"
    exit 1
fi

# Load environment variables from chatbot-specific env file (shared with run_local_full.sh)
USER_ENV_FILE="$HOME/work/env/.env_cwe_chatbot"

# Helper to load a single key from the user env file if unset
load_env_key() {
    local key="$1"
    local current_val="${!key:-}"
    if [[ -z "$current_val" && -f "$USER_ENV_FILE" ]]; then
        local line
        line=$(grep -E "^${key}=" "$USER_ENV_FILE" | tail -n 1 || true)
        if [[ -n "$line" ]]; then
            local val
            val=$(echo "$line" | sed -E "s/^${key}=//; s/^\"(.*)\"$/\1/; s/^'(.*)'$/\1/")
            if [[ -n "$val" ]]; then
                export "$key"="$val"
                echo -e "${GREEN}✅ Loaded ${key} from ${USER_ENV_FILE}${NC}"
            fi
        fi
    fi
}

# Attempt to load commonly used keys for tests
for KEY in \
    GEMINI_API_KEY \
    POSTGRES_HOST \
    POSTGRES_PORT \
    POSTGRES_DATABASE \
    POSTGRES_USER \
    POSTGRES_PASSWORD
do
    load_env_key "$KEY"
done

# Hint the application env loader by pointing to the same env file when present
if [[ -f "$USER_ENV_FILE" && -z "${ENV_FILE_PATH:-}" ]]; then
    export ENV_FILE_PATH="$USER_ENV_FILE"
    echo -e "${GREEN}✅ ENV_FILE_PATH set to ${USER_ENV_FILE}${NC}"
fi

# Set sensible local defaults for DB config if missing (aligns with run_local_full.sh)
export POSTGRES_HOST=${POSTGRES_HOST:-localhost}
export POSTGRES_PORT=${POSTGRES_PORT:-5432}
export POSTGRES_DATABASE=${POSTGRES_DATABASE:-cwe}
export POSTGRES_USER=${POSTGRES_USER:-postgres}

# Check if playwright browsers are installed
echo -e "${BLUE}🔍 Checking Playwright browser installation...${NC}"
if ! poetry run python -c "from playwright.sync_api import sync_playwright; sync_playwright()" &> /dev/null; then
    echo -e "${YELLOW}⚠️  Installing Playwright browsers...${NC}"
    poetry run playwright install chromium firefox webkit
fi

# Validate environment for database tests
if [[ "$WITH_DATABASE" == true ]]; then
    echo -e "${BLUE}🔍 Validating database test environment...${NC}"

    missing_vars=()

    if [[ -z "$GEMINI_API_KEY" ]]; then
        missing_vars+=("GEMINI_API_KEY")
    fi

    if [[ -z "$POSTGRES_HOST" ]]; then
        missing_vars+=("POSTGRES_HOST")
    fi

    if [[ -z "$POSTGRES_PASSWORD" ]]; then
        missing_vars+=("POSTGRES_PASSWORD")
    fi

    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        echo -e "${YELLOW}⚠️  Database tests require environment variables:${NC}"
        printf '   %s\n' "${missing_vars[@]}"
        echo -e "${YELLOW}   Continuing without database tests...${NC}"
        WITH_DATABASE=false
    else
        echo -e "${GREEN}✅ Database test environment configured${NC}"
    fi
fi

# Set environment variables
export TEST_TIMEOUT
export PLAYWRIGHT_HEADLESS

echo -e "${BLUE}🔧 Test Configuration:${NC}"
echo "  Mode: $TEST_MODE"
echo "  Browser: $BROWSER_TYPE"
echo "  Headless: $PLAYWRIGHT_HEADLESS"
echo "  With Database: $WITH_DATABASE"
echo "  Parallel: $PARALLEL_TESTS"
echo "  Timeout: ${TEST_TIMEOUT}s"
echo ""

# Create test results directory
mkdir -p test-results/videos
mkdir -p test-results/screenshots
export LLM_FALLBACK_MARKER_PATH="test-results/llm_fallback_marker"

# Build pytest command based on configuration
# Build pytest arguments using an array to avoid quoting issues
# Disable pytest-playwright plugin to avoid duplicate parametrization with our tests
PYTEST_ARGS=("-v" "--tb=short" "-p" "no:playwright")

# Add parallel execution if requested
if [[ "$PARALLEL_TESTS" == true ]]; then
    if poetry run python -c "import xdist" >/dev/null 2>&1; then
        PYTEST_ARGS+=("-n" "auto")
    else
        echo -e "${YELLOW}⚠️  pytest-xdist not installed; running without parallelism${NC}"
    fi
fi

# Set test markers based on mode
if [[ "$TEST_MODE" == "quick" ]]; then
    TEST_PATTERNS="tests/e2e/test_smoke_playwright.py tests/e2e/test_ui_full_paths.py::test_ui_full_paths tests/e2e/test_comprehensive_ui_flows.py::test_persona_switching_workflow"
    ESTIMATED_TIME="5-8 minutes"
    # For UI smoke tests, run offline to avoid LLM flakiness
    export E2E_OFFLINE_AI=1
elif [[ "$TEST_MODE" == "full" ]]; then
    TEST_PATTERNS="tests/e2e/"
    PYTEST_ARGS+=("-m" "not slow or slow")
    ESTIMATED_TIME="20-30 minutes"
fi

# Add database tests if enabled
if [[ "$WITH_DATABASE" == true ]]; then
    : # Include requires_secrets tests (no marker filter)
else
    # Exclude tests that require external secrets/DB
    PYTEST_ARGS+=("-m" "not requires_secrets")
fi

# Browser-specific execution
if [[ "$BROWSER_TYPE" == "all" ]]; then
    echo -e "${CYAN}🌐 Running cross-browser tests (chromium, firefox, webkit)${NC}"
    TEST_PATTERNS="$TEST_PATTERNS tests/e2e/test_cross_browser_compatibility.py"
elif [[ "$BROWSER_TYPE" != "chromium" ]]; then
    export PYTEST_BROWSER="$BROWSER_TYPE"
else
    # Constrain to Chromium-only by excluding other parametrized cases in node ids
    PYTEST_ARGS+=("-k" "not [firefox] and not [webkit]")
fi

echo -e "${GREEN}🚀 Starting E2E test execution...${NC}"
echo -e "${CYAN}   Estimated time: $ESTIMATED_TIME${NC}"
echo -e "${CYAN}   Test patterns: $TEST_PATTERNS${NC}"
echo ""

# Start timing
START_TIME=$(date +%s)

# Execute tests
if [[ "$TEST_MODE" == "quick" ]]; then
    # Run specific quick tests
    echo -e "${BLUE}Running quick smoke tests...${NC}"
    poetry run pytest "${PYTEST_ARGS[@]}" \
        tests/e2e/test_smoke_playwright.py::test_application_loads_without_errors \
        tests/e2e/test_smoke_playwright.py::test_basic_smoke_flow \
        tests/e2e/test_comprehensive_ui_flows.py::test_persona_switching_workflow \
        tests/e2e/test_comprehensive_ui_flows.py::test_error_recovery_scenarios \
        2>&1 | tee test-results/quick_test_output.log

    TEST_EXIT_CODE=${PIPESTATUS[0]}
else
    # Run full test suite
    echo -e "${BLUE}Running comprehensive test suite...${NC}"
    poetry run pytest "${PYTEST_ARGS[@]}" tests/e2e/ \
        2>&1 | tee test-results/full_test_output.log

    TEST_EXIT_CODE=${PIPESTATUS[0]}
fi

# Calculate duration
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
DURATION_MIN=$((DURATION / 60))
DURATION_SEC=$((DURATION % 60))

echo ""
echo "============================================"

if [[ $TEST_EXIT_CODE -eq 0 ]]; then
    # If strict assertion is requested, fail if any LLM fallback occurred
    if [[ "${ASSERT_NO_FALLBACK:-}" == "1" && -f "$LLM_FALLBACK_MARKER_PATH" ]]; then
        echo -e "${RED}❌ LLM fallback detected while ASSERT_NO_FALLBACK=1${NC}"
        TEST_EXIT_CODE=1
    fi
    echo -e "${GREEN}✅ E2E Tests PASSED${NC}"
    echo -e "${GREEN}   Duration: ${DURATION_MIN}m ${DURATION_SEC}s${NC}"

    # Count test results from output
    if [[ -f "test-results/${TEST_MODE}_test_output.log" ]]; then
        PASSED=$(grep -c "PASSED" "test-results/${TEST_MODE}_test_output.log" || echo "0")
        FAILED=$(grep -c "FAILED" "test-results/${TEST_MODE}_test_output.log" || echo "0")
        SKIPPED=$(grep -c "SKIPPED" "test-results/${TEST_MODE}_test_output.log" || echo "0")

        echo -e "${GREEN}   Results: $PASSED passed, $FAILED failed, $SKIPPED skipped${NC}"
    fi

    echo ""
    echo -e "${CYAN}📊 Test artifacts available in:${NC}"
    echo "   • Logs: test-results/${TEST_MODE}_test_output.log"
    echo "   • Videos: test-results/videos/"
    echo "   • Screenshots: test-results/screenshots/"

else
    echo -e "${RED}❌ E2E Tests FAILED${NC}"
    echo -e "${RED}   Duration: ${DURATION_MIN}m ${DURATION_SEC}s${NC}"
    echo -e "${RED}   Exit code: $TEST_EXIT_CODE${NC}"

    echo ""
    echo -e "${YELLOW}🔍 Debugging information:${NC}"
    echo "   • Check test-results/${TEST_MODE}_test_output.log for detailed output"
    echo "   • Review test-results/videos/ for test recordings"
    echo "   • Run with --visible to see browser interactions"
    echo ""
    echo -e "${YELLOW}💡 Common issues:${NC}"
    echo "   • Server startup timeout (increase TEST_TIMEOUT)"
    echo "   • Missing environment variables (check GEMINI_API_KEY, DATABASE_URL)"
    echo "   • Browser compatibility (try different --browser option)"
    echo "   • Port conflicts (ensure ports 8000-9000 are available)"
    if [[ -f "$LLM_FALLBACK_MARKER_PATH" ]]; then
        echo "   • LLM fallback occurred (check logs and provider configuration)"
    fi
fi

# Cleanup
echo ""
echo -e "${BLUE}🧹 Cleanup completed${NC}"

exit $TEST_EXIT_CODE
