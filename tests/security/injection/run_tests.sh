#!/bin/bash
# SQL Injection Prevention Test Suite Runner
#
# This script runs comprehensive SQL injection tests for the CWE ChatBot project.
# It provides multiple test execution modes for different scenarios.

set -e  # Exit on error

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$PROJECT_ROOT"

echo "========================================================================"
echo "SQL INJECTION PREVENTION TEST SUITE"
echo "========================================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "$1"
}

# Check if database is available
check_database() {
    if [[ -z "${DB_HOST}" ]] || [[ -z "${DB_NAME}" ]] || [[ -z "${DB_USER}" ]] || [[ -z "${DB_PASSWORD}" ]]; then
        return 1
    fi
    return 0
}

# Parse command line arguments
MODE="${1:-all}"

case "$MODE" in
    all)
        print_info "Running ALL SQL injection tests (requires database)..."
        echo ""

        if ! check_database; then
            print_warning "Database not configured. Many tests will be skipped."
            print_info "Set DB_HOST, DB_NAME, DB_USER, DB_PASSWORD to enable full testing."
            echo ""
        fi

        poetry run pytest tests/security/injection/test_sql_injection_prevention.py -v --tb=short
        ;;

    critical)
        print_info "Running CRITICAL security tests only..."
        echo ""

        poetry run pytest tests/security/injection/test_sql_injection_prevention.py \
            -m security_critical -v --tb=short
        ;;

    static)
        print_info "Running STATIC ANALYSIS tests (no database required)..."
        echo ""

        print_info "Test 1: Checking for string concatenation in SQL queries..."
        poetry run pytest \
            tests/security/injection/test_sql_injection_prevention.py::TestSQLInjectionPrevention::test_no_string_concatenation_in_queries \
            -v --tb=short

        echo ""
        print_info "Test 2: Verifying parameterized queries usage..."
        poetry run pytest \
            tests/security/injection/test_sql_injection_prevention.py::TestSQLInjectionPrevention::test_parameterized_queries_used_everywhere \
            -v --tb=short
        ;;

    summary)
        print_info "Running test summary report..."
        echo ""

        poetry run pytest \
            tests/security/injection/test_sql_injection_prevention.py::test_sql_injection_prevention_summary \
            -v -s --tb=short
        ;;

    category)
        CATEGORY="${2:-basic}"
        print_info "Running tests for category: $CATEGORY"
        echo ""

        case "$CATEGORY" in
            basic)
                poetry run pytest tests/security/injection/test_sql_injection_prevention.py \
                    -k "test_basic_injection" -v --tb=short
                ;;
            vector)
                poetry run pytest tests/security/injection/test_sql_injection_prevention.py \
                    -k "test_vector" -v --tb=short
                ;;
            fts)
                poetry run pytest tests/security/injection/test_sql_injection_prevention.py \
                    -k "test_fts" -v --tb=short
                ;;
            union)
                poetry run pytest tests/security/injection/test_sql_injection_prevention.py \
                    -k "test_union" -v --tb=short
                ;;
            blind)
                poetry run pytest tests/security/injection/test_sql_injection_prevention.py \
                    -k "test_blind" -v --tb=short
                ;;
            parameterization)
                poetry run pytest tests/security/injection/test_sql_injection_prevention.py \
                    -k "parameterization" -v --tb=short
                ;;
            *)
                print_error "Unknown category: $CATEGORY"
                print_info "Valid categories: basic, vector, fts, union, blind, parameterization"
                exit 1
                ;;
        esac
        ;;

    help|--help|-h)
        echo "Usage: $0 [MODE] [OPTIONS]"
        echo ""
        echo "Modes:"
        echo "  all        - Run all SQL injection tests (default, requires database)"
        echo "  critical   - Run only security-critical tests"
        echo "  static     - Run static analysis tests (no database required)"
        echo "  summary    - Run test summary report"
        echo "  category   - Run specific category of tests"
        echo "  help       - Show this help message"
        echo ""
        echo "Category Options (use with 'category' mode):"
        echo "  basic            - Basic SQL injection tests"
        echo "  vector           - Vector search injection tests"
        echo "  fts              - Full-text search injection tests"
        echo "  union            - UNION-based injection tests"
        echo "  blind            - Time-based blind injection tests"
        echo "  parameterization - Parameterized query verification tests"
        echo ""
        echo "Examples:"
        echo "  $0                      # Run all tests"
        echo "  $0 static               # Run static analysis tests"
        echo "  $0 category basic       # Run basic injection tests"
        echo "  $0 critical             # Run critical security tests"
        echo ""
        echo "Environment Variables (for full testing):"
        echo "  DB_HOST      - Database host"
        echo "  DB_NAME      - Database name"
        echo "  DB_USER      - Database user"
        echo "  DB_PASSWORD  - Database password"
        echo ""
        exit 0
        ;;

    *)
        print_error "Unknown mode: $MODE"
        print_info "Run '$0 help' for usage information"
        exit 1
        ;;
esac

echo ""
echo "========================================================================"
print_success "Test execution complete!"
echo "========================================================================"
