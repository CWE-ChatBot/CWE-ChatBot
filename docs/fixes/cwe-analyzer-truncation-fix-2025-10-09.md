# CWE Analyzer Truncation Fix - 2025-10-09

## Issue Summary

**Reported**: CWE Analyzer persona response was truncated mid-generation, showing table headers but no table rows.

**Root Causes Identified**:
1. **MAX_OUTPUT_TOKENS too low** (4096) - Insufficient for detailed CWE analysis tables
2. **Database cursor closed error** - Manual `conn.commit()` calls within context managers causing "cursor is closed" errors

## Investigation Details

### Issue 1: Truncated LLM Response

**Symptoms**:
- CWE Analyzer table showing only headers:
  ```
  | CWE ID  | CWE Name | CWE Vulnerability Mapping Label | Confidence | CWE Abstraction Level | CWE-Vulnerability Mapping Notes
  ```
- No table rows generated
- Response cuts off mid-generation

**Root Cause**:
- `MAX_OUTPUT_TOKENS` set to 4096 tokens (default in `apps/chatbot/src/app_config.py:86`)
- CWE Analyzer persona generates detailed analysis including:
  - Key Vulnerability Phrases section
  - Multi-row CWE Mapping Table
  - Evidence and Confidence section
  - Detailed analysis and justification
- Total output often exceeds 4096 tokens

**Fix Applied**:
```bash
gcloud run services update cwe-chatbot \
  --region us-central1 \
  --update-env-vars MAX_OUTPUT_TOKENS=8192
```

**Result**:
- Revision: cwe-chatbot-00169-xhh deployed
- MAX_OUTPUT_TOKENS increased from 4096 → 8192
- 100% traffic routed to new revision

### Issue 2: Database Cursor Closed Error

**Symptoms**:
- Log message: `"halfvec query failed, falling back to vector column: the cursor is closed"`
- Occurred on every CWE Analyzer query
- Fallback to regular vector column worked but was slower (1.1s vs 150ms)

**Root Cause**:
- Manual `conn.commit()` calls within psycopg context managers
- Context managers automatically handle commit/rollback on exit
- Manual commit closes the cursor prematurely
- When context manager tries to exit, cursor is already closed → error

**Affected Code Locations** (`apps/cwe_ingestion/cwe_ingestion/pg_chunk_store.py`):
1. Line 236: `_ensure_schema()` - manual commit after DDL
2. Line 299: `store_chunks()` - manual commit after batch insert
3. Line 621: `hybrid_search()` - manual commit in halfvec transaction
4. Line 713: `hybrid_search()` - manual commit in fallback transaction

**Fix Applied**:
Removed all 4 manual `conn.commit()` calls, replaced with comments:
```python
# Transaction will auto-commit on successful context manager exit
# No manual commit needed - prevents "cursor is closed" errors
```

**Why This Works**:
- psycopg context manager `with conn:` automatically commits on successful exit
- If exception occurs, context manager automatically rolls back
- Manual commit is redundant and causes cursor to close prematurely
- Removing manual commits allows context manager to handle transaction lifecycle correctly

**Expected Result**:
- No more "cursor is closed" errors
- halfvec fast path should work consistently
- Performance improvement: 1.1s → 150ms (1.8x speedup)

## Deployment Timeline

1. **22:24 UTC** - MAX_OUTPUT_TOKENS fix deployed (revision cwe-chatbot-00169-xhh)
2. **22:26 UTC** - Database cursor fix code changes committed
3. **22:26 UTC** - Build started for cursor fix
4. **[Pending]** - Deploy cursor fix revision
5. **[Pending]** - Verify both fixes working together

## Verification Steps

### Test 1: CWE Analyzer Table Generation
```
Query: "A SQL injection issue was found in SFOS 17.0, 17.1, 17.5, and 18.0
       before 2020-04-25 on Sophos XG Firewall devices..."

Expected Result:
✅ Complete table with multiple CWE rows
✅ Full analysis including Evidence and Confidence sections
✅ No truncation mid-response
```

### Test 2: Database Performance (halfvec)
```
Check logs for:
✅ No "halfvec query failed" messages
✅ Query times ~150ms (not 1000ms+)
✅ "Retrieved 10 chunks in XXXms" showing fast retrieval
```

### Test 3: End-to-End Workflow
```
1. Ask CWE Analyzer query
2. Verify complete response with full table
3. Click "❓ Ask a Question" button
4. Ask follow-up question
5. Verify no errors, fast response
```

## Technical Details

### MAX_OUTPUT_TOKENS Configuration
- **Default**: 4096 tokens
- **New Value**: 8192 tokens
- **Rationale**: gemini-2.5-flash-lite supports up to 8192 output tokens
- **Environment Variable**: `MAX_OUTPUT_TOKENS=8192`
- **Applied To**: Cloud Run service configuration

### Psycopg Context Manager Transaction Handling
```python
# WRONG - manual commit causes "cursor is closed"
with conn:
    with conn.cursor() as cur:
        cur.execute(sql)
        conn.commit()  # ❌ Closes cursor prematurely

# CORRECT - let context manager handle commit
with conn:
    with conn.cursor() as cur:
        cur.execute(sql)
        # Context manager commits on successful exit ✅
```

## Related Issues

- **halfvec Performance Optimization**: See `apps/cwe_ingestion/docs/CWE_RETRIEVAL_PERFORMANCE_REPORT_UPDATED.md`
- **Database IAM Authentication**: See `apps/cwe_ingestion/docs/IAM_AUTHENTICATION_FINAL.md`

## Lessons Learned

1. **LLM Token Limits**: Always consider output token requirements for complex persona responses
2. **Context Manager Usage**: Never manually commit within psycopg context managers - let them handle transaction lifecycle
3. **Error Handling**: "cursor is closed" errors often indicate improper transaction handling
4. **Performance Monitoring**: Log analysis revealed fallback was working but slower - masking the cursor issue
5. **Defense in Depth**: Fallback mechanism prevented complete failure, allowing issue to be diagnosed in production

## References

- Issue reported by user at: 2025-10-09 22:17 UTC
- Investigation started: 2025-10-09 22:19 UTC
- MAX_OUTPUT_TOKENS fix: 2025-10-09 22:24 UTC
- Cursor fix code: 2025-10-09 22:26 UTC
