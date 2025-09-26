# Test Execution Guide for CWE ChatBot

## Overview

This guide provides comprehensive instructions for running the CWE ChatBot test suite, covering unit tests, integration tests, and end-to-end browser automation tests.

## Prerequisites

### Required Dependencies
```bash
# Ensure all test dependencies are installed
poetry install --with dev

# Install Playwright browsers
poetry run playwright install chromium
```

### Environment Setup

#### Minimal Setup (Unit + Basic Integration)
```bash
# No additional environment variables needed
# Tests will run with minimal functionality
```

#### Full Setup (Complete E2E with Database)
```bash
# API Keys
export GEMINI_API_KEY="your-gemini-api-key"

# PostgreSQL Database (for retrieval tests)
export POSTGRES_HOST="127.0.0.1"
export POSTGRES_PORT="5432"
export POSTGRES_DATABASE="cwe_chatbot"
export POSTGRES_USER="postgres"
export POSTGRES_PASSWORD="your-password"

# Optional Test Configuration
export TEST_TIMEOUT="60"                # Server startup timeout (seconds)
export PLAYWRIGHT_HEADLESS="true"       # Set to "false" for visible browser
export TEST_LOG_LEVEL="INFO"           # DEBUG for verbose logging
```

## Test Execution Commands

### Quick Development Testing

#### Unit Tests Only (Fastest ~30 seconds)
```bash
# Run all unit tests
poetry run pytest tests/unit -v

# Run specific component tests
poetry run pytest tests/unit/test_cwe_extractor.py -v
poetry run pytest tests/unit/test_input_security.py -v
poetry run pytest tests/unit/test_role_manager.py -v

# Run single test method
poetry run pytest tests/unit/test_cwe_extractor.py::TestCWEExtractor::test_has_direct_cwe_reference_positive -v
```

#### Integration Tests (Headless Server ~2 minutes)
```bash
# Run integration tests (starts real Chainlit server)
poetry run pytest tests/integration -v

# Test server fixtures only
poetry run pytest tests/integration/test_chainlit_server.py -v
```

### Complete Testing

#### E2E Tests without External Dependencies (~3 minutes)
```bash
# Basic E2E tests (no API keys or database required)
poetry run pytest tests/e2e -m "not requires_secrets" -v

# Specific smoke tests
poetry run pytest tests/e2e/test_smoke_playwright.py -v
```

#### Full E2E with Database and API (~10 minutes)
```bash
# Requires GEMINI_API_KEY and PostgreSQL setup
poetry run pytest tests/e2e -v

# Only retrieval tests
poetry run pytest tests/e2e/test_retrieval_full.py -v
```

### Test Categories by Markers

#### By Speed
```bash
# Fast tests only (unit + quick integration)
poetry run pytest -m "not slow" -v

# Slow tests only (complete E2E workflows)
poetry run pytest -m "slow" -v
```

#### By Type
```bash
# Unit tests
poetry run pytest -m "unit" tests/unit/ -v

# Integration tests
poetry run pytest -m "integration" tests/integration/ -v

# E2E tests
poetry run pytest -m "e2e" tests/e2e/ -v

# Security-focused tests
poetry run pytest -m "security" -v
```

#### By Requirements
```bash
# Tests that don't need external secrets
poetry run pytest -m "not requires_secrets" -v

# Tests that require API keys/database
poetry run pytest -m "requires_secrets" -v
```

### Debugging and Development

#### Visible Browser Mode
```bash
# Run E2E tests with visible browser for debugging
export PLAYWRIGHT_HEADLESS="false"
poetry run pytest tests/e2e/test_smoke_playwright.py::test_basic_smoke_flow -v -s

# Or use pytest option
poetry run pytest tests/e2e/test_smoke_playwright.py -v -s --browser-debug
```

#### Verbose Output and Logging
```bash
# Maximum verbosity
poetry run pytest tests/ -v -s --tb=long --log-cli-level=DEBUG

# Capture stdout/stderr
poetry run pytest tests/ -v -s --capture=no

# Show local variables in failures
poetry run pytest tests/ -v --tb=long --showlocals
```

#### Run Specific Failing Tests
```bash
# Re-run last failed tests
poetry run pytest --lf -v

# Re-run failed tests first, then continue
poetry run pytest --ff -v

# Stop on first failure
poetry run pytest tests/ -v -x
```

## Test Output and Results

### Understanding Test Results

#### Successful Test Run
```
============================= test session starts ==============================
collected 45 items

tests/unit/test_cwe_extractor.py::TestCWEExtractor::test_has_direct_cwe_reference_positive PASSED [100%]
tests/integration/test_chainlit_server.py::test_server_startup_and_health PASSED [100%]
tests/e2e/test_smoke_playwright.py::test_basic_smoke_flow PASSED [100%]

============================== 45 passed in 125.23s ==============================
```

#### Test Skips (Expected for Missing Dependencies)
```
tests/e2e/test_retrieval_full.py::test_cwe_retrieval_with_content SKIPPED [reason: GEMINI_API_KEY not set]
tests/e2e/test_retrieval_full.py::test_multiple_cwe_comparison SKIPPED [reason: PostgreSQL environment variables not set]

============================== 40 passed, 5 skipped in 95.12s ==============================
```

#### Server Startup Issues
```
tests/integration/test_chainlit_server.py::test_server_startup_and_health SKIPPED [reason: Failed to start Chainlit on http://127.0.0.1:54321 within 45s]
```

### Performance Benchmarks

#### Expected Test Durations
- **Unit Tests**: 20-60 seconds total
- **Integration Tests**: 1-3 minutes (includes server startup)
- **E2E Basic**: 2-5 minutes (browser automation)
- **E2E Full**: 5-15 minutes (with API calls and database)

#### Performance Red Flags
- Unit tests taking > 2 minutes
- Server startup taking > 30 seconds
- Individual E2E tests taking > 5 minutes

## Continuous Integration

### GitHub Actions Configuration

#### Basic CI Workflow
```yaml
name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        test-type: [unit, integration, e2e-basic]

    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install Poetry
        run: pip install poetry

      - name: Install Dependencies
        run: poetry install --with dev

      - name: Install Playwright
        run: poetry run playwright install chromium

      - name: Run Unit Tests
        if: matrix.test-type == 'unit'
        run: poetry run pytest tests/unit -v

      - name: Run Integration Tests
        if: matrix.test-type == 'integration'
        run: poetry run pytest tests/integration -v

      - name: Run E2E Basic Tests
        if: matrix.test-type == 'e2e-basic'
        run: poetry run pytest tests/e2e -m "not requires_secrets" -v
```

#### Full E2E with Secrets (Optional)
```yaml
  test-full:
    if: contains(github.event.head_commit.message, '[full-test]')
    runs-on: ubuntu-latest
    steps:
      - name: Full E2E Tests
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
          POSTGRES_HOST: ${{ secrets.POSTGRES_HOST }}
          # ... other secrets
        run: poetry run pytest tests/e2e -v
```

### Local CI Simulation
```bash
# Simulate CI environment locally
unset GEMINI_API_KEY POSTGRES_HOST POSTGRES_PORT POSTGRES_USER POSTGRES_PASSWORD
poetry run pytest tests/ -m "not requires_secrets" -v

# Test with minimal environment
poetry run pytest tests/unit tests/integration -v
```

## Troubleshooting

### Common Issues and Solutions

#### Server Startup Failures
```bash
# Issue: Chainlit server won't start
# Solution: Check port availability and dependencies
poetry run chainlit run main.py --port 8001 --headless

# Check if port is in use
netstat -tulpn | grep :8000

# Kill existing processes
pkill -f chainlit
```

#### Import Errors
```bash
# Issue: ModuleNotFoundError for src modules
# Solution: Verify PYTHONPATH and working directory
cd /path/to/apps/chatbot
poetry run python -c "from src.processing.cwe_extractor import CWEExtractor"

# Check Python path resolution
poetry run python -c "import sys; print(sys.path)"
```

#### Playwright Browser Issues
```bash
# Issue: Browser installation problems
# Solution: Reinstall browsers with dependencies
poetry run playwright install --with-deps chromium

# Check browser installation
poetry run playwright install --dry-run
```

#### Database Connection Issues
```bash
# Issue: PostgreSQL connection failures in retrieval tests
# Solution: Verify database connectivity
poetry run python -c "
import psycopg2
import os
conn = psycopg2.connect(
    host=os.getenv('POSTGRES_HOST'),
    port=os.getenv('POSTGRES_PORT'),
    database=os.getenv('POSTGRES_DATABASE'),
    user=os.getenv('POSTGRES_USER'),
    password=os.getenv('POSTGRES_PASSWORD')
)
print('Database connection successful')
"
```

#### API Key Issues
```bash
# Issue: GEMINI_API_KEY not working
# Solution: Verify API key format and permissions
poetry run python -c "
import os
key = os.getenv('GEMINI_API_KEY')
print(f'API key present: {bool(key)}')
print(f'API key format: {key[:10] + \"...\" if key else \"None\"}')
"
```

### Debug Mode Testing
```bash
# Run single test with maximum debug output
poetry run pytest tests/e2e/test_smoke_playwright.py::test_basic_smoke_flow -v -s --tb=long --log-cli-level=DEBUG --capture=no

# Run with Python debugger on failure
poetry run pytest tests/ -v --pdb

# Generate test coverage report
poetry run pytest tests/ --cov=src --cov-report=html
open htmlcov/index.html
```

### Performance Profiling
```bash
# Profile test execution time
poetry run pytest tests/ --durations=10

# Profile memory usage
poetry run pytest tests/ --memmon

# Generate timing report
poetry run pytest tests/ --duration-slow=1.0
```

## Best Practices

### Development Workflow
1. **Start with unit tests** - fastest feedback loop
2. **Run integration tests** - verify component interaction
3. **Run basic E2E tests** - verify UI functionality
4. **Run full E2E tests** - complete validation (when secrets available)

### Writing New Tests
1. **Use appropriate markers** - `@pytest.mark.unit`, `@pytest.mark.e2e`, etc.
2. **Environment gate heavy tests** - use `@pytest.mark.skipif` for dependencies
3. **Keep unit tests fast** - no external dependencies or I/O
4. **Make E2E tests resilient** - handle different UI states gracefully

### Maintenance
1. **Update test data regularly** - keep sample inputs current
2. **Monitor test performance** - watch for degradation
3. **Review skipped tests** - ensure they still serve a purpose
4. **Update dependencies** - keep Playwright and pytest current

## Test Coverage Goals

### Current Coverage Targets
- **Unit Tests**: 90%+ coverage for core business logic
- **Integration**: All conversation flows and API endpoints
- **E2E**: Critical user journeys (role selection, Q&A, error handling)
- **Security**: 100% coverage for input validation and sanitization

### Coverage Reports
```bash
# Generate coverage report
poetry run pytest tests/ --cov=src --cov-report=html --cov-report=term-missing

# View coverage in browser
open htmlcov/index.html

# Check coverage thresholds
poetry run pytest tests/ --cov=src --cov-fail-under=80
```