# D4 Transaction Warnings Investigation

**Date**: 2025-10-10
**Status**: 🔍 INVESTIGATING
**Related**: D4 warning analysis, commit 966c85f (previous cursor fix)

## Problem Summary

34 warnings observed in production logs (2025-10-10):
```
WARNING: there is already a transaction in progress
```

**Sources**:
- 28 warnings from host 10.8.0.2 (Cloud SQL instance 1)
- 6 warnings from host 10.8.0.3 (Cloud SQL instance 2)

**Database**: postgres
**User**: app_user
**Connection**: SQLAlchemy pooled connections via psycopg

## Root Cause Analysis

### Transaction Management Architecture

The codebase uses a `_get_connection()` context manager that handles transaction lifecycle:

**File**: [apps/cwe_ingestion/cwe_ingestion/pg_chunk_store.py:182-227](apps/cwe_ingestion/cwe_ingestion/pg_chunk_store.py#L182)

```python
@contextlib.contextmanager
def _get_connection(self) -> Generator[Any, None, None]:
    """
    Connection factory with transaction management:
      - With Engine: checkout a pooled connection from SQLAlchemy
      - Commits on successful completion
      - Rolls back on exceptions
    """
    if self._engine is not None:
        conn = self._engine.raw_connection()
        try:
            yield conn
            # Commit transaction on successful completion
            conn.commit()
        except Exception:
            # Rollback on error
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()  # return to pool
    else:
        # Persistent psycopg connection path
        # ...
```

### psycopg Transaction Behavior

psycopg (v3) uses **autocommit=False** by default, which means:

1. **First SQL statement** automatically starts a transaction (implicit BEGIN)
2. Transaction remains open until explicit COMMIT or ROLLBACK
3. Attempting to issue BEGIN while transaction is active → WARNING

### Potential Causes

#### Hypothesis 1: Connection Pool Recycling
When SQLAlchemy recycles a connection from the pool, it might be:
- Issuing `BEGIN` to start a new transaction
- But if previous transaction wasn't properly closed, this causes the warning
- Pool configuration: `pool_size=4, max_overflow=0, pool_recycle=1800`

#### Hypothesis 2: Nested Transaction Attempts
Code pattern in multiple files:
```python
with self.store._get_connection() as conn:
    with self.store._cursor(conn) as cur:
        cur.execute("SELECT ...")  # Implicit BEGIN here
        # ...
```

If connection is reused within same request, might attempt BEGIN twice.

#### Hypothesis 3: Connection Not Returned Properly
If exception occurs and `conn.close()` in finally block fails, connection might:
- Stay in pool with active transaction
- Next checkout attempts BEGIN → warning

## Evidence from Previous Fix (commit 966c85f)

**Previous issue**: "cursor is closed" errors
**Cause**: Manual `conn.commit()` calls inside `with _get_connection()` blocks
**Fix**: Removed manual commits, rely on context manager auto-commit

**Current issue is DIFFERENT**:
- Previous: Cursor closed by premature commit
- Current: Transaction already started when BEGIN attempted

## Investigation Steps

### Step 1: Check Connection Pool Status ✅ DONE
```bash
# Check current pool configuration
apps/chatbot/src/db.py:
- pool_size=4 (from DB_POOL_SIZE env var, default 4)
- max_overflow=0 (fixed pool, no overflow)
- pool_pre_ping=True (validate before use)
- pool_recycle=1800 (30 minutes)
```

### Step 2: Search for Explicit BEGIN Statements ✅ DONE
```bash
grep -r "BEGIN" apps/chatbot/src/
# Result: No explicit BEGIN statements found
```

### Step 3: Analyze Warning Timing
```bash
# Get warning timestamps to identify pattern
gcloud logging read 'textPayload=~"transaction in progress"' \
  --limit=50 --format=json | \
  jq -r '.[] | .timestamp' | sort
```

Observations:
- Warnings appear in bursts (same timestamp, different hosts)
- Suggests concurrent request handling

### Step 4: Check Connection Lifecycle 🔍 IN PROGRESS

Need to verify:
1. Is `conn.close()` always executed?
2. Are exceptions in `conn.rollback()` being swallowed silently?
3. Is pool returning connections in clean state?

## Proposed Solutions

### Solution 1: Add Connection State Logging (RECOMMENDED)
Add logging to track connection lifecycle:

```python
# apps/cwe_ingestion/cwe_ingestion/pg_chunk_store.py
@contextlib.contextmanager
def _get_connection(self) -> Generator[Any, None, None]:
    if self._engine is not None:
        logger.debug("Checking out connection from pool")
        conn = self._engine.raw_connection()
        try:
            # Log transaction status before yield
            logger.debug(f"Connection transaction status: {conn.status}")
            yield conn
            logger.debug("Connection use successful, committing")
            conn.commit()
        except Exception as e:
            logger.warning(f"Connection use failed, rolling back: {e}")
            try:
                conn.rollback()
            except Exception as rb_error:
                logger.error(f"Rollback failed: {rb_error}")
            raise
        finally:
            logger.debug("Returning connection to pool")
            conn.close()
```

### Solution 2: Explicit Transaction Control
Force transactions to start/end explicitly instead of relying on implicit BEGIN:

```python
@contextlib.contextmanager
def _get_connection(self) -> Generator[Any, None, None]:
    if self._engine is not None:
        conn = self._engine.raw_connection()
        try:
            # Explicitly start transaction
            with conn.transaction():
                yield conn
        except Exception:
            # Transaction automatically rolled back by with block
            raise
        finally:
            conn.close()
```

### Solution 3: Reset Connection State Before Returning to Pool
Ensure clean state before returning to pool:

```python
finally:
    # Reset connection to known state before returning
    try:
        if conn.status != psycopg.pq.TransactionStatus.IDLE:
            conn.rollback()  # Clear any pending transaction
    except Exception as e:
        logger.error(f"Failed to reset connection state: {e}")
    conn.close()
```

### Solution 4: Increase Pool Size (WORKAROUND)
If issue is pool exhaustion, increase pool size:

```bash
# apps/chatbot/src/db.py
pool_size=8  # Increase from 4
max_overflow=2  # Allow temporary overflow
```

**Not recommended**: Doesn't fix root cause, just reduces frequency.

## Testing Plan

### Test 1: Add Debug Logging
1. Deploy Solution 1 (connection state logging)
2. Monitor logs for 24 hours
3. Correlate warnings with connection lifecycle events
4. Identify exact point where duplicate BEGIN occurs

### Test 2: Local Reproduction
1. Create test script that simulates concurrent requests
2. Use same pool configuration as production
3. Trigger multiple queries in parallel
4. Check if warnings appear locally

```python
# test_connection_pool.py
import concurrent.futures
from apps.chatbot.src.query_handler import QueryHandler

def run_query(i):
    handler = QueryHandler()
    handler.get_canonical_cwe_metadata([f"CWE-{i}"])

# Simulate 10 concurrent requests
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(run_query, i) for i in range(100)]
    concurrent.futures.wait(futures)
```

### Test 3: Verify Fix
1. Implement chosen solution
2. Deploy to staging
3. Run load test with concurrent requests
4. Verify warnings eliminated

## Impact Assessment

**Current Impact**:
- ⚠️ Functional: Queries still work (PostgreSQL ignores duplicate BEGIN)
- ⚠️ Performance: May indicate connection not released properly
- ⚠️ Connection pool: Could lead to pool exhaustion under high load
- ⚠️ Log noise: 34+ warnings per day making real errors harder to spot

**Risk if not fixed**:
- Connection pool exhaustion under sustained load
- Slower query performance due to connection churn
- Difficulty diagnosing real database issues due to log noise

## Comparison with D3 Fix

| Aspect | D3 (commit 966c85f) | D4 (current) |
|--------|---------------------|--------------|
| **Symptom** | "cursor is closed" errors | "transaction in progress" warnings |
| **Cause** | Manual `conn.commit()` in context manager | Duplicate BEGIN attempts |
| **Location** | `pg_chunk_store.py` (4 manual commits) | Connection pool lifecycle |
| **Impact** | Blocked halfvec fast path (critical) | Log noise + potential pool issues (medium) |
| **Fix** | Remove manual commits | Need investigation (add logging) |

## Implementation Status

### Solution 1: Connection State Logging ✅ IMPLEMENTED

**File Modified**: [apps/cwe_ingestion/cwe_ingestion/pg_chunk_store.py:181-237](apps/cwe_ingestion/cwe_ingestion/pg_chunk_store.py#L181)

**Changes Made**:
1. Added connection checkout logging: `"Checking out connection from SQLAlchemy pool"`
2. Added connection status logging before yield: `"Connection checked out, status: {status}"`
3. Added successful completion logging: `"Connection use completed successfully, committing transaction"`
4. Enhanced rollback logging with error type
5. **Added cleanup check**: Before returning to pool, check if connection is IDLE
   - If not IDLE, force rollback to clean up dangling transaction
   - Log warning if cleanup needed: `"Connection not idle before pool return"`
6. Added pool return logging: `"Returning connection to pool"`

**Expected Behavior**:
- Normal case: checkout → IDLE → use → commit → IDLE → return
- Error case: checkout → IDLE → use → error → rollback → IDLE → return
- **Cleanup case**: checkout → IN_TRANSACTION → use → commit → STILL_IN_TRANSACTION → force rollback → IDLE → return

This should eliminate the "transaction already in progress" warnings by ensuring connections are always returned to the pool in IDLE state.

## Next Steps

1. ✅ Document investigation findings (this file)
2. ✅ Implement Solution 1 (debug logging + cleanup)
3. 🔄 Deploy to production
4. ⏳ Monitor logs for 24 hours to verify fix
5. ⏳ Update D4.md with resolution if warnings eliminated

## References

- [D4 Warning Analysis](D4.md) - Initial warning count and categorization
- [D3 Truncation Fix](../../fixes/cwe-analyzer-truncation-fix-2025-10-09.md) - Previous database fix
- [PostgreSQL Transaction States](https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-EXT-QUERY)
- [psycopg3 Transactions](https://www.psycopg.org/psycopg3/docs/basic/transactions.html)

---

**Investigation Date**: 2025-10-10
**Priority**: HIGH (from D4 analysis)
**Next Update**: After 24h monitoring with debug logging
