# CWE Query Testing Suite

Comprehensive testing for CWE chatbot query accuracy and correctness.

**Created**: 2025-10-11
**Purpose**: Prevent regressions like ISSUE-CWE-82-NOT-FOUND (force-injection bug)
**Documentation**: See [docs/stories/ISSUE-CWE-82-NOT-FOUND.md](../../../docs/stories/ISSUE-CWE-82-NOT-FOUND.md)

## Overview

This testing suite validates that:
1. Specific CWE IDs mentioned in queries are returned correctly (force-injection works)
2. Chatbot responses match MITRE ground truth (no hallucinations)
3. End-to-end user workflows function properly
4. Systematic issues are caught across the entire CWE corpus

## Test Types

### Phase 1: Unit Tests (Force-Injection Logic)

**File**: `tests/unit/test_cwe_id_force_injection.py`

**Purpose**: Verify CWE ID extraction and force-injection logic at the code level.

**Coverage**:
- ✅ Force-injection when CWE ID missing from results
- ✅ +3.0 score boost applied to injected CWEs
- ✅ No force-injection when CWE already in results
- ✅ Multiple missing CWE IDs handled correctly
- ✅ Edge cases (no results, no CWE IDs in query, various formats)

**Run**:
```bash
# Run all force-injection unit tests
poetry run pytest apps/chatbot/tests/unit/test_cwe_id_force_injection.py -v

# Run specific test
poetry run pytest apps/chatbot/tests/unit/test_cwe_id_force_injection.py::TestCWEIDForceInjection::test_force_injection_when_cwe_id_missing_from_results -v
```

**Expected**: 13 tests pass

**Speed**: Fast (~1-2 seconds)

### Phase 2: LLM-as-Judge Tests (Response Accuracy)

**File**: `tests/integration/test_cwe_response_accuracy_llm_judge.py`

**Purpose**: Validate chatbot responses match MITRE ground truth using an LLM judge.

**Coverage**:
- 10 high-priority CWEs (OWASP/CWE Top 25)
- 10 low-frequency CWEs (like CWE-82 that triggered the bug)
- 20 random CWEs from corpus

**Prerequisites**:
- MITRE CWE XML downloaded: `/tmp/cwec_v4.18.xml`
- Gemini API key: `export GEMINI_API_KEY=your_key`
- Chatbot API running (production or local): `export CHATBOT_URL=http://localhost:8081`
- **REST API Integration**: Tests now use `/api/v1/query` endpoint (anonymous access)

**Run**:
```bash
# Download MITRE CWE XML first
wget https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
unzip cwec_latest.xml.zip -d /tmp/

# Start chatbot with REST API (in another terminal)
cd apps/chatbot
ENABLE_OAUTH=false poetry run chainlit run main.py --port 8081

# Run LLM judge tests
CHATBOT_URL=http://localhost:8081 TEST_API_KEY=your_api_key GEMINI_API_KEY=your_gemini_key poetry run pytest --no-header -rN apps/chatbot/tests/integration/test_cwe_response_accuracy_llm_judge.py -v -s

# Run standalone for debugging
CHATBOT_URL=http://localhost:8081 TEST_API_KEY=your_api_key poetry run python apps/chatbot/tests/integration/test_cwe_response_accuracy_llm_judge.py
```

**Expected**: 21 tests (now integrated with REST API)

**Speed**: Slow (~2-3 seconds per CWE with Gemini API calls)

**Cost**: ~$0.01-0.02 per run (Gemini API usage)

### Phase 3: Puppeteer E2E Tests (Interactive Workflows)

**File**: `tests/e2e/test_cwe_queries_puppeteer.py`

**Purpose**: Test actual user interactions through browser automation.

**Coverage**:
- Specific CWE ID queries (CWE-79, CWE-89, CWE-82, etc.)
- Semantic queries ("How do I prevent SQL injection?")
- Invalid CWE IDs (error handling)
- Multi-CWE comparisons
- Follow-up questions

**Prerequisites**:
- Playwright installed: `poetry add playwright && poetry run playwright install`
- Chatbot deployed and accessible
- Anonymous access OR test service account configured

**Environment Variables**:
```bash
export CHATBOT_URL=https://cwe-chatbot.example.com  # Default: http://localhost:8000
export USE_AUTH=false  # Set to 'true' if OAuth required
export TEST_EMAIL=test@example.com  # If USE_AUTH=true
export TEST_PASSWORD=your_password  # If USE_AUTH=true
```

**Run**:
```bash
# Run all E2E tests
poetry run pytest apps/chatbot/tests/e2e/test_cwe_queries_puppeteer.py -v -s

# Run specific test
poetry run pytest apps/chatbot/tests/e2e/test_cwe_queries_puppeteer.py::TestCWEQueriesE2E::test_cwe_82_force_injection_fix_works_e2e -v
```

**Expected**: 9 tests (currently skipped - requires deployed chatbot)

**Speed**: Slow (~5-10 seconds per test with browser automation)

### Phase 4: Random CWE Sampling (Systematic Coverage)

**File**: `tests/integration/test_random_cwe_sampling.py`

**Purpose**: Detect systematic issues by testing 30 random CWEs from the corpus.

**Coverage**:
- Random sample of 30 CWEs from 1-1425 (entire MITRE range)
- Uses LLM-as-judge for accuracy validation
- Reproducible with random seed

**Prerequisites**:
- Same as Phase 2 (MITRE XML + Gemini API key + Chatbot API)
- **REST API Integration**: Tests now use `/api/v1/query` endpoint

**Run**:
```bash
# Start chatbot with REST API (in another terminal)
cd apps/chatbot
ENABLE_OAUTH=false poetry run chainlit run main.py --port 8081

# Run with random seed
CHATBOT_URL=http://localhost:8081 TEST_API_KEY=your_api_key GEMINI_API_KEY=your_gemini_key poetry run pytest apps/chatbot/tests/integration/test_random_cwe_sampling.py -v -s

# Run with specific seed (reproducible)
RANDOM_SEED=42 CHATBOT_URL=http://localhost:8081 TEST_API_KEY=your_api_key GEMINI_API_KEY=your_gemini_key poetry run pytest apps/chatbot/tests/integration/test_random_cwe_sampling.py -v -s

# Run standalone for debugging
CHATBOT_URL=http://localhost:8081 TEST_API_KEY=your_api_key poetry run python apps/chatbot/tests/integration/test_random_cwe_sampling.py
```

**Expected**: Maximum 10% failure rate (3/30 failures allowed for edge cases)

**Speed**: Very slow (~2-3 minutes for 30 CWEs with API calls)

**Cost**: ~$0.02-0.03 per run

## Test Status

| Phase | Tests | Status | Speed | Ready to Run | API Integration |
|-------|-------|--------|-------|--------------|-----------------|
| Phase 1: Unit Tests | 13 | ✅ Passing | Fast | ✅ Yes | N/A (mocked) |
| Phase 2: LLM Judge | 21 | ✅ Ready | Slow | ✅ Yes | REST API `/api/v1/query` |
| Phase 3: Puppeteer E2E | 9 | ⏸️ Skipped | Slow | ⚠️ Needs deployment | WebSocket UI |
| Phase 4: Random Sampling | 1 | ✅ Ready | Very Slow | ✅ Yes | REST API `/api/v1/query` |

**API Integration Status (2025-10-11)**:
- ✅ REST API endpoint created: `/api/v1/query` (API key authentication, rate-limited)
- ✅ API key stored in GCP Secret Manager (`test-api-key`) with env fallback
- ✅ Phase 2 tests updated with `httpx` API client + `X-API-Key` header
- ✅ Phase 4 tests updated with `httpx` API client + `X-API-Key` header
- ⚠️ Requires `TEST_API_KEY` environment variable for testing
- ⚠️ Requires running chatbot with full configuration (DB + GEMINI_API_KEY)
- ⚠️ Local testing requires `.env` setup with database credentials

## Running All Tests

```bash
# Run only passing tests (Phase 1)
poetry run pytest apps/chatbot/tests/unit/test_cwe_id_force_injection.py -v

# Run all tests (including skipped ones - will show skip reasons)
poetry run pytest apps/chatbot/tests/ -v

# Run with coverage
poetry run pytest apps/chatbot/tests/unit/test_cwe_id_force_injection.py --cov=src/processing/pipeline --cov-report=html
```

## REST API Integration (Completed 2025-10-11)

Phase 2-4 now use the REST API endpoint for anonymous CWE queries.

### API Endpoint: `/api/v1/query`

**Authentication**: Requires `X-API-Key` header with valid API key.

**API Key Setup**:
```bash
# Generate a secure API key (32 bytes URL-safe)
python -c "import secrets; print(secrets.token_urlsafe(32))"

# For local testing: Set environment variable
export TEST_API_KEY="your-generated-key-here"

# For production: Store in GCP Secret Manager
gcloud secrets create test-api-key --data-file=- <<< "your-generated-key-here"
```

**Request**:
```json
POST /api/v1/query
Content-Type: application/json
X-API-Key: your-api-key-here

{
  "query": "What is CWE-82?",
  "persona": "Developer"  // Optional: Developer, PSIRT Member, Academic Researcher, etc.
}
```

**Response**:
```json
{
  "response": "CWE-82 (Improper Neutralization of Script in Attributes...",
  "retrieved_cwes": ["CWE-82"],
  "chunk_count": 5,
  "session_id": "api-test-a1b2c3d4"
}
```

**Rate Limiting**: 10 requests/minute per IP address

**Health Check**: `GET /api/v1/health` (no authentication required) returns service status and database connectivity

### Testing with curl

```bash
# Generate and set API key
export TEST_API_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
echo "API Key: $TEST_API_KEY"

# Test health endpoint (no auth required)
curl http://localhost:8081/api/v1/health

# Test CWE query (requires X-API-Key header)
curl -X POST http://localhost:8081/api/v1/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $TEST_API_KEY" \
  -d '{"query": "What is CWE-79?", "persona": "Developer"}'

# Test authentication failure (invalid API key)
curl -X POST http://localhost:8081/api/v1/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: invalid-key" \
  -d '{"query": "What is CWE-82?"}'

# Test rate limiting (run 15 times quickly)
for i in {1..15}; do
  curl -X POST http://localhost:8081/api/v1/query \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $TEST_API_KEY" \
    -d '{"query": "What is CWE-82?"}'
  echo ""
done
```

## CI/CD Integration

**Recommended CI/CD Pipeline**:

```yaml
# .github/workflows/cwe-tests.yml
name: CWE Query Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run unit tests
        run: poetry run pytest apps/chatbot/tests/unit/test_cwe_id_force_injection.py -v

  llm-judge-tests:
    runs-on: ubuntu-latest
    if: github.event_name == 'schedule' # Weekly
    steps:
      - uses: actions/checkout@v3
      - name: Download MITRE CWE XML
        run: wget https://cwe.mitre.org/data/xml/cwec_latest.xml.zip && unzip cwec_latest.xml.zip -d /tmp/
      - name: Run LLM judge tests
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
        run: poetry run pytest apps/chatbot/tests/integration/test_cwe_response_accuracy_llm_judge.py -v
```

## Weekly Regression Testing

**Schedule**: Run Phase 2-4 weekly to catch regressions

```bash
#!/bin/bash
# weekly_cwe_tests.sh

echo "Weekly CWE Regression Testing"
echo "=============================="

# Download latest MITRE CWE XML
wget https://cwe.mitre.org/data/xml/cwec_latest.xml.zip -O /tmp/cwec_latest.xml.zip
unzip -o /tmp/cwec_latest.xml.zip -d /tmp/

# Run Phase 2: LLM Judge (high priority + low frequency)
poetry run pytest apps/chatbot/tests/integration/test_cwe_response_accuracy_llm_judge.py::TestCWEResponseAccuracyWithLLMJudge::test_high_priority_cwe_accuracy -v

poetry run pytest apps/chatbot/tests/integration/test_cwe_response_accuracy_llm_judge.py::TestCWEResponseAccuracyWithLLMJudge::test_low_frequency_cwe_accuracy -v

# Run Phase 4: Random sampling (30 random CWEs)
RANDOM_SEED=$(date +%Y%m%d) poetry run pytest apps/chatbot/tests/integration/test_random_cwe_sampling.py -v

echo "Weekly testing complete!"
```

## Debugging Failed Tests

### Unit Test Failures

If Phase 1 unit tests fail:
1. Check pipeline.py - force-injection logic may be broken
2. Verify QueryProcessor extracting CWE IDs correctly
3. Run with `-vv` for verbose output: `pytest -vv`

### LLM Judge Test Failures

If Phase 2 LLM judge tests fail:
1. Check chatbot is returning responses (not empty/error)
2. Verify MITRE XML path correct (`/tmp/cwec_v4.18.xml`)
3. Check Gemini API key valid
4. Review judge reasoning - may be false positive (response incomplete but not wrong)

### E2E Test Failures

If Phase 3 Puppeteer tests fail:
1. Check chatbot URL accessible
2. Verify chat interface selectors match actual DOM (`.message`, `#chat-input`, etc.)
3. Increase timeout if responses slow
4. Run with headless=False to see browser: `playwright.chromium.launch(headless=False)`

### Random Sampling Failures

If Phase 4 random sampling > 10% failure rate:
1. Check which CWEs failing (may indicate systematic issue)
2. Run with same seed to reproduce: `RANDOM_SEED=42`
3. Verify not just edge cases (deprecated CWEs, categories, etc.)

## Adding New Test Cases

### Add High-Priority CWE

Edit `test_cwe_response_accuracy_llm_judge.py`:
```python
HIGH_PRIORITY_CWES = [
    "CWE-79",
    "CWE-89",
    # Add new CWE here
    "CWE-XXX",  # Your new high-priority CWE
]
```

### Add E2E Test Case

Edit `test_cwe_queries_puppeteer.py`:
```python
@pytest.mark.parametrize("cwe_id,expected_keywords", [
    ("CWE-XXX", ["keyword1", "keyword2"]),  # Add new test case
])
async def test_cwe_id_query_returns_correct_info(self, page, cwe_id, expected_keywords):
    # Test logic
```

## Metrics and Reporting

**Track over time**:
- Unit test pass rate (should be 100%)
- LLM judge PASS rate (target: >90%)
- LLM judge PARTIAL rate (acceptable: <10%)
- Random sampling failure rate (threshold: <10%)

**Weekly report**:
```
Week 42 CWE Testing Report
==========================
Unit Tests: 13/13 PASS (100%)
High-Priority CWEs: 9/10 PASS, 1/10 PARTIAL (90% PASS rate)
Low-Frequency CWEs: 8/10 PASS, 2/10 PARTIAL (80% PASS rate)
Random Sample: 28/30 PASS, 2/30 FAIL (93% PASS rate, seed=20251011)

Failures:
- CWE-XXX: [reasoning]
- CWE-YYY: [reasoning]
```

## Known Limitations

1. **LLM Judge Variability**: Gemini responses may vary slightly (use temperature=0.0 to minimize)
2. **API Costs**: Phase 2-4 incur Gemini API costs (~$0.05 per full run)
3. **Speed**: Phase 2-4 slow due to LLM API calls (consider parallelization)
4. **Ground Truth**: MITRE XML must be manually downloaded and updated
5. **Edge Cases**: Deprecated CWEs, categories, views may fail (expected)

## Future Improvements

- [ ] Parallel execution of LLM judge tests (faster)
- [ ] Cache LLM judge verdicts to reduce API costs
- [ ] Integrate with CI/CD for automated weekly runs
- [ ] Add performance benchmarks (response time <2s)
- [ ] Implement chatbot API client for easier test integration
- [ ] Add test result dashboard/reporting
- [ ] Automated MITRE XML download in tests

## Questions?

See [ISSUE-CWE-82-NOT-FOUND.md](../../../docs/stories/ISSUE-CWE-82-NOT-FOUND.md) for full context on why these tests were created.
