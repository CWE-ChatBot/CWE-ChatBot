# Performance Fix Validation - Connection Pooling

**Fix Deployed:** 2025-10-03
**Revision:** cwe-chatbot-00098-lb8
**Expected Improvement:** 10x database query speedup

---

## What Was Fixed

### Root Cause (Confirmed)
PostgresChunkStore was being initialized WITHOUT a SQLAlchemy engine in production, causing it to fall back to:
```python
conn = psycopg.connect(self.database_url)  # NEW connection every query!
```

This meant:
- Every query opened a brand new database connection
- Full IAM authentication (~500-800ms)
- Full SSL/TLS handshake (~200-400ms)
- Total overhead: ~1000-1200ms per query

### The Fix

**Now PostgresChunkStore auto-creates a pooled engine if one isn't provided:**

```python
if self._engine is None and HAS_SQLALCHEMY and self.database_url:
    self._engine = sa.create_engine(
        self.database_url,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=1800,
        future=True,
    )
```

**Connection reuse behavior:**
- With Engine: `conn.close()` returns connection to pool (keeps TCP/TLS/IAM alive) ✅
- Without Engine: Single persistent psycopg connection reused ✅
- No more per-query `psycopg.connect()` ✅

---

## Expected Performance Improvement

### Before (Revision 00097-mdz)
| Metric | Value |
|--------|-------|
| Embedding | ~118ms |
| DB Query | **~1345ms** |
| Total | ~1463ms |

**Breakdown:**
- Actual query execution: ~150ms
- Connection overhead: **~1200ms** (IAM + TLS handshake)

### After (Revision 00098-lb8) - EXPECTED
| Metric | Value | Change |
|--------|-------|--------|
| Embedding | ~118ms | Same |
| DB Query | **~150-200ms** | **10x faster** |
| Total | **~270-320ms** | **5x faster** |

**Breakdown:**
- Actual query execution: ~150ms
- Connection overhead: **~0ms** (pooled)

---

## Validation Tests

### Test 1: Warm-up Loop (Critical)

**Purpose:** Verify connection reuse

**Steps:**
1. Navigate to: https://cwe-chatbot-258315443546.us-central1.run.app
2. Run the SAME query 5 times in a row:
   - Query: "Show me SQL injection prevention techniques"
   - Persona: PSIRT Member

**Expected Results:**
- **Query 1:** ~300-500ms (possible cold start + pool init)
- **Query 2-5:** ~150-250ms (connection from pool)

**How to Validate:**
```bash
gcloud run services logs read cwe-chatbot \
  --region=us-central1 \
  --limit=50 \
  --format='value(textPayload)' | \
  grep -E '(Retrieved.*chunks|Created pooled SQLAlchemy)'
```

**Success Criteria:**
- ✅ See "Created pooled SQLAlchemy engine" in logs (once)
- ✅ DB query time drops to ~150-250ms after first query
- ✅ Consistent low latency across queries 2-5

### Test 2: Connection Count (Cloud SQL Metrics)

**Purpose:** Verify no connection churn

**Steps:**
1. Go to Cloud Console → SQL → cwe-postgres-prod → Monitoring
2. Check "Active connections" graph during test period

**Expected Results:**
- **Before:** Spikes up and down with each request
- **After:** Flat line at ~2-5 connections (stable pool)

**Success Criteria:**
- ✅ Connection count stable (not spiking per request)
- ✅ Max connections ≤ pool_size (5) + max_overflow (10) = 15

### Test 3: Different Queries (Accuracy Check)

**Purpose:** Ensure fix doesn't affect retrieval quality

**Test Queries:**
1. "Buffer overflow vulnerabilities" (Academic Researcher)
2. "XSS mitigation strategies" (Developer)
3. "Path traversal attack vectors" (Bug Bounty Hunter)

**Expected Results:**
- Same CWE results as previous testing
- Same hybrid scores
- DB query time ~150-250ms (fast!)

**Success Criteria:**
- ✅ Top CWEs match previous results
- ✅ All queries return 10 chunks
- ✅ DB time consistently low

### Test 4: Performance Logs Analysis

**Purpose:** Confirm 10x improvement

**Command:**
```bash
gcloud run services logs read cwe-chatbot \
  --region=us-central1 \
  --limit=100 \
  --format='value(timestamp,textPayload)' | \
  grep -E '(Processing query|Retrieved.*chunks)' | \
  tee /tmp/perf_fix_results.txt
```

**Analysis:**
1. Extract DB query times from "Retrieved X chunks in Yms" logs
2. Calculate average, p50, p95
3. Compare to previous baseline (1345ms avg)

**Success Criteria:**
- ✅ Average DB time ≤ 250ms (down from 1345ms)
- ✅ p95 DB time ≤ 300ms (down from 1741ms)
- ✅ Total processing time ≤ 400ms (down from 1463ms)

---

## Validation Checklist

After running tests, confirm:

- [ ] "Created pooled SQLAlchemy engine" appears in logs (once per instance)
- [ ] First query: ~300-500ms (acceptable cold start)
- [ ] Subsequent queries: ~150-250ms (10x improvement confirmed)
- [ ] Connection count stable at ~2-5 (no spikes)
- [ ] CWE results identical to previous testing
- [ ] No errors or exceptions in logs
- [ ] Average DB time ≤ 250ms (target achieved)

---

## Troubleshooting

### Issue: DB time still high (~1s+)

**Possible causes:**
1. Engine not being created (check for "Created pooled SQLAlchemy engine" log)
2. Engine creation failing silently
3. Still using database_url without engine

**Debug:**
```bash
gcloud run services logs read cwe-chatbot --limit=200 | \
  grep -E '(engine|pool|connection|SQLAlchemy)'
```

**Look for:**
- "Created pooled SQLAlchemy engine" ✅ (should appear)
- "Using single persistent psycopg connection" ❌ (shouldn't appear in Cloud Run)

### Issue: Connection errors

**Possible causes:**
1. Pool exhausted (unlikely with pool_size=5, max_overflow=10)
2. Connection timeout (pool_recycle=1800s should prevent)

**Debug:**
Check Cloud SQL → Monitoring → Connections for errors or max connection issues.

### Issue: Different results than before

**Possible causes:**
1. Code change affected query logic (shouldn't happen - only connection management changed)
2. Database state changed

**Debug:**
Compare exact SQL queries in logs - should be identical to before.

---

## Rollback Plan

If issues occur:

1. **Quick rollback:**
   ```bash
   gcloud run services update-traffic cwe-chatbot \
     --region=us-central1 \
     --to-revisions=cwe-chatbot-00097-mdz=100
   ```

2. **Revert code:**
   ```bash
   git revert HEAD
   git push
   # Then rebuild and deploy
   ```

3. **Emergency fix:**
   Pass existing engine from apps/chatbot/src/db.py explicitly:
   ```python
   from apps.chatbot.src.db import get_engine
   store = PostgresChunkStore(..., engine=get_engine())
   ```

---

## Success Metrics

### Performance Targets (All Expected to Pass)

| Metric | Before | Target | Status |
|--------|--------|--------|--------|
| Avg DB Time | 1345ms | ≤250ms | ⏳ Test |
| p95 DB Time | 1741ms | ≤300ms | ⏳ Test |
| Total Processing | 1463ms | ≤400ms | ⏳ Test |
| Connection Reuse | ❌ No | ✅ Yes | ⏳ Test |

### Functionality Targets (Should Not Change)

| Metric | Expected | Status |
|--------|----------|--------|
| Chunks Retrieved | 10 per query | ⏳ Test |
| Top CWE Accuracy | 3/5 perfect | ⏳ Test |
| Error Rate | 0% | ⏳ Test |

---

## Post-Validation

After confirming performance improvement, update:

1. **TEST_RESULTS_NON_CWE_REGRESSION.md**
   - Add "Performance Fix Validated" section
   - Include before/after metrics
   - Mark Issue #2 as RESOLVED ✅

2. **PRODUCTION_TEST_SUMMARY.md**
   - Update recommendations (mark P0 as DONE)
   - Add performance fix results

3. **Git commit:**
   - Document validation results
   - Include actual metrics captured
   - Close performance optimization issue

---

## Expected Log Output

**Good (with pooling):**
```
INFO: Created pooled SQLAlchemy engine for PostgresChunkStore
INFO: Using SQLAlchemy pooled connection
INFO: Retrieved 10 chunks in 156.3ms (total: 274.8ms)
```

**Bad (without pooling - shouldn't see this):**
```
INFO: Using single persistent psycopg connection
INFO: Opening persistent psycopg connection
INFO: Retrieved 10 chunks in 1245.7ms (total: 1363.2ms)
```

---

**Ready to test!** Please run the validation tests above and share the results.
