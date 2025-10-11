# Story CWE-82: 4-Phase Testing Strategy

**Story**: CWE-82 - Implement comprehensive CWE query testing to verify chatbot accuracy
**Status**: Phase 1 Complete ✅ | Phase 2-4 Ready ⏸️ (API integration deployed)
**Date**: 2025-10-11

## Overview

Comprehensive testing strategy to validate CWE ChatBot accuracy and prevent regressions, with focus on the "CWE-82 not found" bug where mentioned CWE IDs were missing from search results.

## Testing Pyramid

```
        ┌─────────────────────────┐
        │  Phase 4: Random (30)   │  ← Sampling (corpus-wide coverage)
        ├─────────────────────────┤
        │   Phase 3: E2E (9)      │  ← Browser automation
        ├─────────────────────────┤
        │  Phase 2: LLM Judge (21)│  ← AI-powered validation
        ├─────────────────────────┤
        │  Phase 1: Unit (13)     │  ← Fast, focused tests
        └─────────────────────────┘
```

## Phase 1: Unit Tests ✅ COMPLETE

**File**: `apps/chatbot/tests/unit/test_cwe_id_force_injection.py`
**Status**: ✅ All 13 tests passing in ~1 second
**Purpose**: Verify force-injection logic that ensures mentioned CWE IDs appear in results

### Test Coverage

1. **Force-Injection When Missing** (4 tests)
   - `test_force_inject_single_missing_cwe` - CWE in query but not in results
   - `test_force_inject_multiple_missing_cwes` - Multiple CWEs mentioned
   - `test_no_injection_when_cwe_already_present` - Don't duplicate existing results
   - `test_force_inject_adds_to_existing_results` - Merge with existing results

2. **Score Boost Verification** (2 tests)
   - `test_force_injected_cwe_has_boosted_score` - +3.0 score boost applied
   - `test_force_injected_cwe_sorted_correctly` - Boosted CWE appears first

3. **Edge Cases** (7 tests)
   - `test_no_force_inject_when_no_query_cwes` - No CWEs in query
   - `test_no_force_inject_when_empty_results` - Empty result set handling
   - `test_extract_cwe_ids_from_query_various_formats` - Multiple query formats
   - `test_extract_cwe_ids_case_insensitive` - "cwe-79", "CWE-79", etc.
   - `test_extract_cwe_ids_multiple_cwes_in_query` - Multiple mentions
   - `test_extract_cwe_ids_ignores_invalid_formats` - "CWE-INVALID" ignored
   - `test_extract_cwe_ids_no_cwes_in_query` - Returns empty list

### Running Phase 1 Tests

```bash
# From project root
cd apps/chatbot/tests

# Run all unit tests
poetry run pytest unit/test_cwe_id_force_injection.py -v

# Run specific test
poetry run pytest unit/test_cwe_id_force_injection.py::test_force_inject_single_missing_cwe -v

# Run with coverage
poetry run pytest unit/test_cwe_id_force_injection.py --cov=src.query_handler --cov-report=term-missing
```

### Results

```
================================ test session starts =================================
collected 13 items

unit/test_cwe_id_force_injection.py::test_force_inject_single_missing_cwe PASSED
unit/test_cwe_id_force_injection.py::test_force_inject_multiple_missing_cwes PASSED
unit/test_cwe_id_force_injection.py::test_no_injection_when_cwe_already_present PASSED
unit/test_cwe_id_force_injection.py::test_force_inject_adds_to_existing_results PASSED
unit/test_cwe_id_force_injection.py::test_force_injected_cwe_has_boosted_score PASSED
unit/test_cwe_id_force_injection.py::test_force_injected_cwe_sorted_correctly PASSED
unit/test_cwe_id_force_injection.py::test_no_force_inject_when_no_query_cwes PASSED
unit/test_cwe_id_force_injection.py::test_no_force_inject_when_empty_results PASSED
unit/test_cwe_id_force_injection.py::test_extract_cwe_ids_from_query_various_formats PASSED
unit/test_cwe_id_force_injection.py::test_extract_cwe_ids_case_insensitive PASSED
unit/test_cwe_id_force_injection.py::test_extract_cwe_ids_multiple_cwes_in_query PASSED
unit/test_cwe_id_force_injection.py::test_extract_cwe_ids_ignores_invalid_formats PASSED
unit/test_cwe_id_force_injection.py::test_extract_cwe_ids_no_cwes_in_query PASSED

================================= 13 passed in 0.92s =================================
```

## Phase 2: LLM-as-Judge ⏸️ READY

**File**: `apps/chatbot/tests/integration/test_cwe_response_accuracy_llm_judge.py`
**Status**: ✅ Implementation complete, API integration deployed
**Purpose**: Use Gemini to validate chatbot responses against MITRE ground truth

### Test Coverage

**21 Total Tests** = 10 high-priority + 10 low-frequency + 1 random sample

1. **High-Priority CWEs** (10 tests) - OWASP/CWE Top 25
   - CWE-79 (Cross-Site Scripting)
   - CWE-89 (SQL Injection)
   - CWE-20 (Improper Input Validation)
   - CWE-78 (OS Command Injection)
   - CWE-787 (Out-of-bounds Write)
   - CWE-22 (Path Traversal)
   - CWE-352 (CSRF)
   - CWE-434 (Unrestricted Upload)
   - CWE-862 (Missing Authorization)
   - CWE-476 (NULL Pointer Dereference)

2. **Low-Frequency CWEs** (10 tests) - Edge cases
   - CWE-82 (Improper Neutralization of Script in Attributes)
   - CWE-117 (Improper Output Neutralization for Logs)
   - CWE-209 (Generation of Error Message with Sensitive Info)
   - CWE-311 (Missing Encryption of Sensitive Data)
   - CWE-327 (Use of Broken Crypto)
   - CWE-759 (Use of One-Way Hash without Salt)
   - CWE-916 (Use of Password Hash with Insufficient Computational Effort)
   - CWE-1004 (Sensitive Cookie Without HttpOnly Flag)
   - CWE-1275 (Sensitive Cookie in HTTPS Without Secure Attribute)
   - CWE-1321 (Improperly Controlled Modification of Object Prototype)

3. **Random Sample** (1 test)
   - Tests 20 randomly selected CWEs from entire corpus
   - Ensures no systematic failures across CWE types

### LLM Judge Criteria

Gemini evaluates chatbot responses on:
- **Factual Accuracy**: Does response match MITRE definition?
- **Completeness**: Are key aspects covered?
- **Clarity**: Is explanation understandable?
- **Relevance**: Does it address the query?

**Scoring**: PASS (accurate response) | FAIL (inaccurate/incomplete)

### Running Phase 2 Tests

```bash
# Set environment variables
export CHATBOT_URL="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app"
export TEST_API_KEY="<from-secret-manager>"
export GEMINI_API_KEY="<your-gemini-key>"

# Run all LLM judge tests
poetry run pytest integration/test_cwe_response_accuracy_llm_judge.py -v

# Run specific test
poetry run pytest integration/test_cwe_response_accuracy_llm_judge.py::TestCWEResponseAccuracy::test_cwe_79_xss -v

# Run with detailed output
poetry run pytest integration/test_cwe_response_accuracy_llm_judge.py -v -s
```

### Prerequisites

- ✅ Staging chatbot deployed with REST API
- ✅ TEST_API_KEY secret created
- ✅ Gemini API key for LLM judging
- ✅ Network access to staging URL

## Phase 3: Puppeteer E2E ⏸️ READY

**File**: `apps/chatbot/tests/e2e/test_cwe_queries_puppeteer.py`
**Status**: ✅ Implementation complete, awaiting deployed chatbot
**Purpose**: Browser automation to test real user interactions

### Test Coverage

**9 Total Tests** covering:

1. **Specific CWE Queries** (3 tests)
   - `test_query_cwe_79_xss` - Well-known CWE
   - `test_query_cwe_89_sql_injection` - Common vulnerability
   - `test_query_cwe_82_script_in_attribute` - Edge case (the bug this story fixes)

2. **Semantic Queries** (2 tests)
   - `test_semantic_query_xss` - Natural language "cross-site scripting vulnerabilities"
   - `test_semantic_query_sql_injection` - Natural language "SQL injection"

3. **Edge Cases** (4 tests)
   - `test_query_invalid_cwe` - CWE-99999 (doesn't exist)
   - `test_query_cwe_comparison` - "Compare CWE-79 and CWE-89"
   - `test_query_follow_up` - Multi-turn conversation
   - `test_query_multiple_cwes` - "Tell me about CWE-79, CWE-89, CWE-22"

### Browser Automation Flow

```python
1. Navigate to chatbot URL
2. Call test-login API to get session cookie
3. Wait for chat interface to load
4. Type query into message input
5. Click send button
6. Wait for response (up to 30 seconds)
7. Verify response contains expected content
8. Extract CWE IDs from response
9. Verify mentioned CWEs are present
```

### Running Phase 3 Tests

```bash
# Install Playwright browsers (one-time setup)
poetry run playwright install chromium

# Set environment variables
export CHATBOT_URL="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app"
export TEST_API_KEY="<from-secret-manager>"

# Run all E2E tests
poetry run pytest e2e/test_cwe_queries_puppeteer.py -v

# Run in headful mode (see browser)
poetry run pytest e2e/test_cwe_queries_puppeteer.py -v --headed

# Run specific test
poetry run pytest e2e/test_cwe_queries_puppeteer.py::test_query_cwe_82_script_in_attribute -v
```

### Prerequisites

- ✅ Staging chatbot deployed with hybrid auth mode
- ✅ test-login endpoint working (session cookie authentication)
- ✅ Playwright browser installed
- ✅ TEST_API_KEY for authentication

## Phase 4: Random Sampling ⏸️ READY

**File**: `apps/chatbot/tests/integration/test_random_cwe_sampling.py`
**Status**: ✅ Implementation complete, API integration deployed
**Purpose**: Detect systematic issues across entire CWE corpus

### Test Coverage

**1 Test**: `test_random_cwe_sample`
- Samples 30 random CWEs from corpus (969 total)
- Queries each CWE by ID
- Validates mentioned CWE appears in response
- **Target**: <10% failure rate (≤3 failures out of 30)

### Sampling Strategy

```python
1. Get list of all valid CWE IDs from database (969 CWEs)
2. Randomly sample 30 CWEs
3. For each CWE:
   - Query: "What is CWE-{id}?"
   - Verify: CWE ID appears in response text
   - Record: PASS or FAIL
4. Calculate failure rate
5. Assert: failure_rate < 10%
```

### Running Phase 4 Tests

```bash
# Set environment variables
export CHATBOT_URL="https://cwe-chatbot-staging-bmgj6wj65a-uc.a.run.app"
export TEST_API_KEY="<from-secret-manager>"

# Run random sampling test
poetry run pytest integration/test_random_cwe_sampling.py -v

# Run with detailed output
poetry run pytest integration/test_random_cwe_sampling.py -v -s
```

### Expected Output

```
Random CWE Sample Test Results:
  Sample size: 30 CWEs
  Passed: 28
  Failed: 2
  Failure rate: 6.67%

Failed CWEs:
  - CWE-123: Response did not mention CWE ID
  - CWE-456: Response did not mention CWE ID

✅ PASSED (failure rate 6.67% < 10% threshold)
```

## CI/CD Integration

### GitHub Actions Workflow

```yaml
name: CWE ChatBot Testing

on:
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2am

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Phase 1 Unit Tests
        run: |
          cd apps/chatbot/tests
          poetry run pytest unit/test_cwe_id_force_injection.py -v

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v3
      - name: Run Phase 2 LLM Judge
        env:
          CHATBOT_URL: ${{ secrets.STAGING_URL }}
          TEST_API_KEY: ${{ secrets.TEST_API_KEY }}
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
        run: |
          cd apps/chatbot/tests
          poetry run pytest integration/test_cwe_response_accuracy_llm_judge.py -v

      - name: Run Phase 4 Random Sampling
        env:
          CHATBOT_URL: ${{ secrets.STAGING_URL }}
          TEST_API_KEY: ${{ secrets.TEST_API_KEY }}
        run: |
          cd apps/chatbot/tests
          poetry run pytest integration/test_random_cwe_sampling.py -v

  e2e-tests:
    runs-on: ubuntu-latest
    needs: integration-tests
    steps:
      - uses: actions/checkout@v3
      - name: Install Playwright
        run: poetry run playwright install chromium

      - name: Run Phase 3 E2E Tests
        env:
          CHATBOT_URL: ${{ secrets.STAGING_URL }}
          TEST_API_KEY: ${{ secrets.TEST_API_KEY }}
        run: |
          cd apps/chatbot/tests
          poetry run pytest e2e/test_cwe_queries_puppeteer.py -v
```

## Weekly Regression Testing

**Schedule**: Every Monday at 2am UTC
**Purpose**: Catch regressions after deployments or data updates

```bash
#!/bin/bash
# Weekly regression test script

set -e

echo "=== Phase 1: Unit Tests ==="
poetry run pytest apps/chatbot/tests/unit/test_cwe_id_force_injection.py -v

echo "=== Phase 2: LLM Judge ==="
poetry run pytest apps/chatbot/tests/integration/test_cwe_response_accuracy_llm_judge.py -v

echo "=== Phase 3: E2E Tests ==="
poetry run pytest apps/chatbot/tests/e2e/test_cwe_queries_puppeteer.py -v

echo "=== Phase 4: Random Sampling ==="
poetry run pytest apps/chatbot/tests/integration/test_random_cwe_sampling.py -v

echo "=== All phases completed ==="
```

## Debugging Failed Tests

### Phase 1 Failures

**Problem**: Force-injection not working
**Check**:
```bash
# Verify force-injection code exists
grep -n "force_inject_missing_cwes" apps/chatbot/src/query_handler.py

# Run single test with verbose output
poetry run pytest unit/test_cwe_id_force_injection.py::test_force_inject_single_missing_cwe -v -s
```

### Phase 2 Failures

**Problem**: LLM judge marking responses as incorrect
**Check**:
```bash
# View actual chatbot response
export CHATBOT_URL="..."
export TEST_API_KEY="..."
curl -X POST $CHATBOT_URL/api/v1/query \
  -H "X-API-Key: $TEST_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query":"What is CWE-79?","persona":"Developer"}'

# View LLM judge evaluation
poetry run pytest integration/test_cwe_response_accuracy_llm_judge.py::TestCWEResponseAccuracy::test_cwe_79_xss -v -s
```

### Phase 3 Failures

**Problem**: Playwright timeouts or element not found
**Check**:
```bash
# Run in headful mode to see browser
poetry run pytest e2e/test_cwe_queries_puppeteer.py::test_query_cwe_79_xss -v --headed

# Increase timeout
poetry run pytest e2e/test_cwe_queries_puppeteer.py -v --timeout=60

# Check test-login endpoint
curl -X POST $CHATBOT_URL/api/v1/test-login -H "X-API-Key: $TEST_API_KEY"
```

### Phase 4 Failures

**Problem**: High failure rate (>10%)
**Check**:
```bash
# View which CWEs are failing
poetry run pytest integration/test_random_cwe_sampling.py -v -s | grep "Failed CWEs" -A 20

# Test specific failing CWE
curl -X POST $CHATBOT_URL/api/v1/query \
  -H "X-API-Key: $TEST_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query":"What is CWE-123?","persona":"Developer"}'
```

## Future Improvements

1. **Expand Phase 2 Coverage**: Test all OWASP Top 10 and CWE Top 25
2. **Performance Testing**: Measure response latency for all phases
3. **Multi-Persona Testing**: Test different persona configurations
4. **Regression Baselines**: Track performance over time
5. **Automated Remediation**: Auto-file issues for failed tests

## Success Metrics

- **Phase 1 Unit Tests**: 100% pass rate (13/13)
- **Phase 2 LLM Judge**: ≥90% pass rate (≥19/21)
- **Phase 3 E2E Tests**: ≥90% pass rate (≥8/9)
- **Phase 4 Random Sample**: <10% failure rate (<3/30)

## Test Results Summary

| Phase | Tests | Status | Pass Rate | Last Run |
|-------|-------|--------|-----------|----------|
| Phase 1: Unit | 13 | ✅ PASSING | 100% (13/13) | 2025-10-11 |
| Phase 2: LLM Judge | 21 | ⏸️ READY | Not run | - |
| Phase 3: E2E | 9 | ⏸️ READY | Not run | - |
| Phase 4: Random | 1 | ⏸️ READY | Not run | - |

**Next Step**: Run Phase 2-4 tests against staging deployment.

## Related Documentation

- [README_CWE_TESTING.md](./README_CWE_TESTING.md) - Complete testing guide
- [STAGING_DEPLOYMENT_SUMMARY.md](../STAGING_DEPLOYMENT_SUMMARY.md) - Deployment status
- [DEPLOYMENT_GUIDE.md](../DEPLOYMENT_GUIDE.md) - Deployment procedures
- [HYBRID_AUTH_PATTERN.md](../HYBRID_AUTH_PATTERN.md) - Authentication architecture
