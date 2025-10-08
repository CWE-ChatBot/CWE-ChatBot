# SQL Injection Test Suite - Quick Start Guide

## TL;DR - Run Tests Now

### Option 1: Static Analysis (No Database Needed) ⚡
```bash
cd /home/chris/work/CyberSecAI/cwe_chatbot_bmad
./tests/security/injection/run_tests.sh static
```
**Expected Output**: 2 tests pass in ~1 second

### Option 2: Full Test Suite (Requires Database) 🔒
```bash
cd /home/chris/work/CyberSecAI/cwe_chatbot_bmad

# Set environment variables first
export DB_HOST=your-db-host
export DB_NAME=cwe
export DB_USER=your-user
export DB_PASSWORD=your-password

./tests/security/injection/run_tests.sh all
```
**Expected Output**: 49 tests pass (some may skip if no database)

---

## What Gets Tested?

✅ **Basic SQL Injection** - DROP TABLE, OR 1=1, DELETE attacks
✅ **Vector Search Injection** - pgvector-specific attacks
✅ **Full-Text Search Injection** - PostgreSQL FTS attacks
✅ **UNION-Based Injection** - Data extraction attempts
✅ **Time-Based Blind Injection** - pg_sleep() timing attacks
✅ **Error-Based Injection** - Information disclosure via errors
✅ **Stacked Queries** - Multi-statement execution
✅ **Code Quality** - Static analysis for unsafe SQL patterns

**Total**: 49 test cases, 40+ injection payloads

---

## Common Commands

### Test Everything
```bash
./tests/security/injection/run_tests.sh all
```

### Security-Critical Only (Deployment Gate)
```bash
./tests/security/injection/run_tests.sh critical
```

### Static Analysis Only (Pre-Commit)
```bash
./tests/security/injection/run_tests.sh static
```

### Test Summary Report
```bash
./tests/security/injection/run_tests.sh summary
```

### Test Specific Category
```bash
./tests/security/injection/run_tests.sh category basic
./tests/security/injection/run_tests.sh category vector
./tests/security/injection/run_tests.sh category fts
```

### Help
```bash
./tests/security/injection/run_tests.sh help
```

---

## Using Pytest Directly

### Run All Tests
```bash
poetry run pytest tests/security/injection/test_sql_injection_prevention.py -v
```

### Run Security-Critical Tests
```bash
poetry run pytest tests/security/injection/ -m security_critical -v
```

### Run Specific Test
```bash
poetry run pytest tests/security/injection/test_sql_injection_prevention.py::TestSQLInjectionPrevention::test_no_string_concatenation_in_queries -v
```

### Run by Keyword
```bash
poetry run pytest tests/security/injection/ -k "basic_injection" -v
```

---

## Expected Results

### ✅ All Tests Pass
```
========================= 49 passed, 3 warnings in X.XXs =========================
```

### ⚠️ Some Tests Skip (No Database)
```
========================= 2 passed, 47 skipped, 3 warnings in X.XXs =========================
```
**This is normal** if database isn't configured. Static analysis tests still run.

### ❌ Tests Fail
**Immediate Action Required**: SQL injection vulnerability detected!

1. Check test output for specific failure
2. Review flagged code in `/apps/chatbot/src/db.py` or `/apps/cwe_ingestion/cwe_ingestion/pg_chunk_store.py`
3. Fix to use parameterized queries
4. Re-run tests

---

## Files Overview

| File | Purpose | Lines |
|------|---------|-------|
| `test_sql_injection_prevention.py` | Main test suite | 853 |
| `run_tests.sh` | Convenient test runner | 200 |
| `README.md` | Detailed documentation | 350 |
| `TEST_SUITE_OVERVIEW.md` | Architecture & design | 500 |
| `QUICK_START.md` | This file | 150 |

---

## Troubleshooting

### "Database not available" - Tests Skip
**Fix**: Set environment variables
```bash
export DB_HOST=10.x.x.x
export DB_NAME=cwe
export DB_USER=app_user
export DB_PASSWORD=your-password
```

### "Table cwe_chunks does not exist"
**Fix**: Run CWE ingestion pipeline first
```bash
poetry run python apps/cwe_ingestion/cli.py ingest-multi
```

### Static Analysis Tests Fail
**Problem**: Unsafe SQL found in code
**Fix**: Refactor to use parameterized queries
```python
# ❌ WRONG - String concatenation
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ✅ CORRECT - Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

---

## Integration with Development Workflow

### Pre-Commit Hook
Add to `.git/hooks/pre-commit`:
```bash
#!/bin/bash
./tests/security/injection/run_tests.sh static
```

### Pre-Deployment Gate
```bash
./tests/security/injection/run_tests.sh critical
if [ $? -ne 0 ]; then
    echo "❌ Security tests failed - deployment blocked!"
    exit 1
fi
```

### CI/CD Pipeline
```yaml
# .github/workflows/security-tests.yml
- name: Run SQL Injection Tests
  run: |
    poetry install
    ./tests/security/injection/run_tests.sh all
```

---

## Key Security Principles

1. **100% Parameterized Queries**
   Never use string concatenation in SQL

2. **No Shell Execution in Queries**
   Don't allow `shell=True` or `os.system()` near database code

3. **Validate All Inputs**
   Even parameterized queries need input validation

4. **Fail Securely**
   Error messages shouldn't leak sensitive information

5. **Test Everything**
   Every new database query needs injection tests

---

## Need Help?

1. **Read the docs**: `README.md` or `TEST_SUITE_OVERVIEW.md`
2. **Check test output**: Look for specific failure messages
3. **Review database code**: `/apps/chatbot/src/db.py`, `/apps/cwe_ingestion/cwe_ingestion/pg_chunk_store.py`
4. **Run help**: `./run_tests.sh help`

---

## Success Metrics

✅ **Zero SQL Injection Vulnerabilities**
✅ **100% Test Pass Rate**
✅ **All Parameterized Queries**
✅ **No Data Leakage**
✅ **Production Ready**

---

**Created**: 2025-10-08
**Status**: ✅ Production Ready
**Test Count**: 49 tests, 40+ payloads
**Execution Time**: ~1-5 seconds (static) or ~10-30 seconds (full)
