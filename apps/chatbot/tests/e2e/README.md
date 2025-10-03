# E2E Tests for CWE ChatBot

End-to-end tests using puppeteer to validate production chainlit app behavior.

## Test Files

### `test_non_cwe_query_regression.py`
Automated regression test for non-CWE semantic queries.

**Purpose:** Prevent regression of the "No relevant CWE information found" bug where queries like "SQL injection prevention techniques" returned 0 chunks.

**What it tests:**
- 5 personas (PSIRT Member, Academic Researcher, Developer, Bug Bounty Hunter, Product Manager)
- Semantic queries without explicit CWE IDs
- Verifies chunks are retrieved successfully
- Validates Cloud Run logs for successful hybrid retrieval

**Test queries:**
- "Show me SQL injection prevention techniques" (expects CWE-89)
- "Buffer overflow vulnerabilities" (expects CWE-120)
- "XSS mitigation strategies" (expects CWE-79)
- "Path traversal attack vectors" (expects CWE-22)
- "Authentication bypass weaknesses" (expects CWE-287)

## Running Tests

### Prerequisites
1. Chainlit app must be deployed and accessible
2. Set environment variable: `CHAINLIT_APP_URL` (defaults to production URL)
3. GCP authentication configured for log access: `gcloud auth login`

### Run all E2E tests
```bash
poetry run pytest apps/chatbot/tests/e2e/ -v
```

### Run specific test
```bash
poetry run pytest apps/chatbot/tests/e2e/test_non_cwe_query_regression.py -v
```

### Run with markers
```bash
# E2E tests only
poetry run pytest -m e2e -v

# Skip E2E tests
poetry run pytest -m "not e2e" -v
```

## Test Output

Tests generate:
- Screenshots for each query test (for debugging)
- Detailed console output showing pass/fail status
- Summary report with passed/failed counts
- Log verification results (if GCP access available)

## Environment Configuration

```bash
# Set custom chainlit app URL (optional)
export CHAINLIT_APP_URL="https://your-custom-url.run.app"

# GCP authentication for log verification
gcloud auth login
gcloud config set project cwechatbot
```

## Test Architecture

These tests use:
- **Puppeteer MCP tools** via pytest fixtures
- **Async test execution** with pytest-asyncio
- **Real production app** interaction (no mocks)
- **Cloud Run logs** verification for complete validation

## Adding New Tests

1. Create test file in `apps/chatbot/tests/e2e/`
2. Mark with `@pytest.mark.e2e` and `@pytest.mark.asyncio`
3. Use puppeteer fixtures from `conftest.py`:
   - `mcp__puppeteer__puppeteer_navigate`
   - `mcp__puppeteer__puppeteer_fill`
   - `mcp__puppeteer__puppeteer_click`
   - `mcp__puppeteer__puppeteer_evaluate`
   - `mcp__puppeteer__puppeteer_screenshot`

4. Follow pattern from `test_non_cwe_query_regression.py`

## Known Limitations

1. **Puppeteer fixtures**: Currently assumes MCP tools are available as imports. If fixtures fail, verify MCP server configuration.

2. **Chainlit UI selectors**: Tests use generic selectors (`textarea[placeholder*="Ask"]`). Update if UI changes.

3. **Log verification**: Requires GCP authentication. Skips gracefully if unavailable.

4. **Timing**: Uses fixed `time.sleep()` delays. May need adjustment for slower deployments.

## Troubleshooting

### Test fails with "No response received"
- Increase `time.sleep()` delays in test
- Verify chainlit app is deployed and accessible
- Check Cloud Run logs for errors

### Puppeteer fixtures not found
- Verify MCP server is configured
- Check `conftest.py` fixture imports
- Ensure `pytest-asyncio` is installed

### Log verification fails
- Run `gcloud auth login`
- Verify project is set: `gcloud config get-value project`
- Check service name matches: `cwe-chatbot`

### Screenshots not generated
- Check write permissions in current directory
- Verify puppeteer screenshot tool is available
- Screenshots saved with naming pattern: `test_non_cwe_<persona>.png`

## Related Documentation

- **Review document**: `docs/stories/4.1/R4.1_prod_sql.md` (C4 regression test requirement)
- **Hybrid retrieval implementation**: `apps/cwe_ingestion/cwe_ingestion/pg_chunk_store.py`
- **Query handler**: `apps/chatbot/src/query_handler.py`
