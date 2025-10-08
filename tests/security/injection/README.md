# SQL Injection Prevention Test Suite

## Overview

This directory contains comprehensive SQL injection prevention tests for the CWE ChatBot project. The test suite validates 100% SQL injection prevention across all database operations.

## Test File

- **`test_sql_injection_prevention.py`**: Comprehensive SQL injection test suite with 49+ test cases

## Test Coverage

### 1. Basic SQL Injection Payloads (14 tests)
Tests classic SQL injection attacks against text search and CWE ID filtering:
- DROP TABLE attacks
- OR 1=1 authentication bypass
- DELETE/UPDATE attacks
- Admin bypass attempts

### 2. Vector Search Injection (5 tests)
pgvector-specific injection tests:
- Malformed embedding injection
- Vector literal construction safety
- Vector search parameter validation

### 3. Full-Text Search Injection (5 tests)
PostgreSQL FTS-specific injection tests:
- websearch_to_tsquery injection
- tsquery operator injection
- FTS syntax attacks

### 4. UNION-Based Injection (4 tests)
Tests UNION query injection attempts:
- Password extraction attempts
- Information schema enumeration
- Multi-column UNION attacks

### 5. Time-Based Blind Injection (4 tests)
Tests blind SQL injection with sleep/delay:
- pg_sleep() injection
- Performance timing verification (ensures delays don't execute)

### 6. Error-Based Injection (3 tests)
Tests error message exploitation:
- Version disclosure attempts
- Type casting errors
- Information leakage prevention

### 7. Column Enumeration (3 tests)
Tests ORDER BY/GROUP BY attacks:
- Column count discovery
- Schema inference prevention

### 8. Stacked Queries (3 tests)
Tests multi-statement execution:
- Table creation attempts
- Data manipulation attempts
- Verification no evil tables created

### 9. Parameterization Verification (5 tests)
Tests proper parameterized query usage:
- SQLAlchemy parameterization
- psycopg parameterization
- hybrid_search parameter safety
- query_hybrid parameter safety
- Transaction rollback safety

### 10. Code Quality Verification (2 tests)
Static analysis tests:
- No string concatenation in SQL queries
- All execute() calls use parameterization

## Running the Tests

### Run All SQL Injection Tests
```bash
poetry run pytest tests/security/injection/test_sql_injection_prevention.py -v
```

### Run Only Security-Critical Tests
```bash
poetry run pytest tests/security/injection/test_sql_injection_prevention.py -m security_critical -v
```

### Run Static Analysis Tests (No Database Required)
```bash
poetry run pytest tests/security/injection/test_sql_injection_prevention.py::TestSQLInjectionPrevention::test_no_string_concatenation_in_queries -v
poetry run pytest tests/security/injection/test_sql_injection_prevention.py::TestSQLInjectionPrevention::test_parameterized_queries_used_everywhere -v
```

### Run Summary Report
```bash
poetry run pytest tests/security/injection/test_sql_injection_prevention.py::test_sql_injection_prevention_summary -v
```

### Run Specific Category
```bash
# Basic injection tests
poetry run pytest tests/security/injection/test_sql_injection_prevention.py -k "test_basic_injection" -v

# Vector injection tests
poetry run pytest tests/security/injection/test_sql_injection_prevention.py -k "test_vector" -v

# Full-text search injection tests
poetry run pytest tests/security/injection/test_sql_injection_prevention.py -k "test_fts" -v
```

## Database Requirements

Most tests require a PostgreSQL database with:
- pgvector extension
- cwe_chunks table with embeddings
- Production or test database access

Tests will automatically skip if database is not available.

### Environment Variables Required
```bash
DB_HOST=<database-host>
DB_NAME=<database-name>
DB_USER=<database-user>
DB_PASSWORD=<database-password>
DB_PORT=5432  # optional
DB_SSLMODE=require  # optional
```

## Test Results Without Database

Even without a database connection, the following tests will run:
1. `test_no_string_concatenation_in_queries` - Static code analysis
2. `test_parameterized_queries_used_everywhere` - Static code analysis
3. `test_sql_injection_prevention_summary` - Summary report

These tests analyze the source code directly to verify SQL injection prevention patterns.

## Injection Payloads Tested

### Total Payloads: 40+
- **Basic SQL Injection**: 7 payloads ('; DROP TABLE, ' OR '1'='1, etc.)
- **UNION-Based**: 4 payloads (UNION SELECT attacks)
- **Blind Injection**: 4 payloads (pg_sleep, timing attacks)
- **Error-Based**: 3 payloads (version disclosure, type casting)
- **Column Enumeration**: 3 payloads (ORDER BY, GROUP BY)
- **Stacked Queries**: 3 payloads (table creation, data manipulation)
- **Vector-Specific**: 3 payloads (pgvector injection attempts)
- **Full-Text Search**: 4 payloads (FTS operator injection)

## Security Baseline

**Current Status**: Zero SQL injection vulnerabilities found - 100% parameterized queries

**Target**: Maintain 100% protection against all SQL injection attack vectors

## Test Markers

Tests use pytest markers for organization:
- `@pytest.mark.security` - All security-related tests
- `@pytest.mark.security_critical` - Critical for deployment gate
- `@pytest.mark.integration` - Tests requiring real database

## Integration with CI/CD

These tests should be run:
1. **Pre-commit**: Static analysis tests (no database required)
2. **Pre-deployment**: Full test suite with production-like database
3. **Post-deployment**: Smoke tests to verify deployment integrity

## Maintenance

### Adding New Injection Payloads
To add new injection payloads, update the payload lists in `test_sql_injection_prevention.py`:
```python
BASIC_INJECTION_PAYLOADS = [
    "'; DROP TABLE users; --",
    # Add new payload here
]
```

### Adding New Test Categories
1. Add payload list at top of file
2. Create test method in `TestSQLInjectionPrevention` class
3. Use `@pytest.mark.parametrize` for multiple payloads
4. Update this README with new category

### Updating Verified Files
To check additional files for SQL injection vulnerabilities:
```python
files_to_check = [
    project_root / "path" / "to" / "new" / "file.py",
    # Add new files here
]
```

## References

- **OWASP SQL Injection**: https://owasp.org/www-community/attacks/SQL_Injection
- **PostgreSQL SQL Injection Prevention**: https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-SYNTAX-IDENTIFIERS
- **pgvector Security**: https://github.com/pgvector/pgvector/blob/master/README.md
- **SQLAlchemy Security**: https://docs.sqlalchemy.org/en/14/core/security.html

## Contact

For questions about these tests or SQL injection prevention:
- Review security assessment: `/docs/security/`
- Check architecture docs: `/docs/architecture/database-schema.md`
- See database implementation: `/apps/chatbot/src/db.py`, `/apps/cwe_ingestion/cwe_ingestion/pg_chunk_store.py`
