# Production Blockers Remediation Plan
## CWE ChatBot - Remaining Security Issues Before Production Deployment

**Date**: 2025-10-08
**Status**: 3 of 5 Critical Blockers Resolved
**Estimated Remaining Effort**: 48-56 hours (6-7 days)

---

## ✅ Completed Blockers (2025-10-08)

### 1. ✅ Update lxml Dependency (CRITICAL)
**Status**: COMPLETE
- Updated: lxml 4.9.4 → 6.0.2
- Commit: `2634c9f`
- Testing: CWE ingestion tests pass (6/6)
- Impact: Eliminates XXE vulnerability risk (CVE-2024-45519)

### 2. ✅ Update cryptography Dependency (HIGH)
**Status**: COMPLETE
- Updated: cryptography 45.0.6 → 46.0.2
- Commit: `2634c9f`
- Impact: Latest security patches for SSL/TLS

### 3. ✅ Update certifi CA Certificates (HIGH)
**Status**: COMPLETE
- Updated: certifi 2025.8.3 → 2025.10.5
- Commit: `2634c9f`
- Impact: Current CA certificate bundle

---

## 🚧 Remaining Production Blockers

### BLOCKER-1: Fix Failing Security Tests (CRITICAL)
**Priority**: 🔴 **HIGHEST - BLOCKING DEPLOYMENT**
**Status**: NOT STARTED
**Effort**: 16 hours (2 days)

**Description**:
14 of 28 security tests in `apps/chatbot/tests/test_security.py` are failing due to API signature mismatches. This represents a **50% failure rate** and indicates tests were not updated when implementation changed.

**Root Cause**:
- Tests expect `sanitize()` method, actual API is `sanitize_input()`
- Tests use unsupported `max_length` constructor parameter
- API mismatch indicates tests written after implementation (not TDD)

**Impact**:
- False confidence in security controls
- Cannot verify security features are working
- Blocks production deployment

**Failing Tests** (14 total):
```
apps/chatbot/tests/test_security.py:
- TestInputSanitizer (9 tests failing)
- TestPromptInjectionDetection (5 tests failing)
```

**Remediation Plan**:

**Step 1: Investigate Actual API** (2 hours)
```bash
# Read actual implementation
grep -n "class InputSanitizer" apps/chatbot/src/input_security.py
grep -n "def sanitize" apps/chatbot/src/input_security.py

# Understand constructor signature
grep -n "__init__" apps/chatbot/src/input_security.py -A 10
```

**Step 2: Fix Test API Signatures** (8 hours)
```python
# BEFORE (failing):
sanitizer = InputSanitizer(max_length=1000)  # Wrong parameter
result = sanitizer.sanitize(text)  # Wrong method name

# AFTER (fixed):
sanitizer = InputSanitizer()  # Correct constructor
result = sanitizer.sanitize_input(text, context)  # Correct API
```

**Step 3: Verify All Tests Pass** (2 hours)
```bash
poetry run pytest apps/chatbot/tests/test_security.py -v
# Must show 28/28 passing (0 failures)
```

**Step 4: Add Regression Prevention** (4 hours)
- Add CI job to fail if security tests fail
- Document correct API usage in test docstrings
- Add type hints to prevent future API mismatches

**Acceptance Criteria**:
- ✅ All 28 tests in test_security.py pass
- ✅ 100% pass rate on security test suite
- ✅ CI prevents merging if security tests fail
- ✅ Test API matches implementation API

**Files to Modify**:
- `apps/chatbot/tests/test_security.py` (refactor 14 failing tests)
- `.github/workflows/ci.yml` (add security test gate)

---

### BLOCKER-2: Create SQL Injection Test Suite (CRITICAL)
**Priority**: 🔴 **CRITICAL - ZERO COVERAGE**
**Status**: NOT STARTED
**Effort**: 24 hours (3 days)

**Description**:
**Zero test coverage** for SQL injection prevention despite parameterized query implementation. Database security is completely unvalidated.

**Impact**:
- Cannot verify SQL injection prevention works
- No regression tests if SQL code changes
- CVSS 9.0 vulnerability if queries become vulnerable
- Unacceptable for production deployment

**Remediation Plan**:

**Step 1: Create Test File Structure** (2 hours)
```bash
mkdir -p tests/security/injection
touch tests/security/injection/__init__.py
touch tests/security/injection/test_sql_injection_prevention.py
```

**Step 2: Implement Core SQL Injection Tests** (12 hours)
```python
# tests/security/injection/test_sql_injection_prevention.py

import pytest
from apps.chatbot.src.db import get_engine
from sqlalchemy import text

@pytest.mark.security
@pytest.mark.security_critical
class TestSQLInjectionPrevention:
    """Comprehensive SQL injection prevention tests."""

    def test_parameterized_queries_for_user_data(self, db_session):
        """Verify user input is parameterized in queries."""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "1; DELETE FROM conversations; --",
            "admin'--",
            "1' UNION SELECT password FROM users--"
        ]

        for payload in malicious_inputs:
            # Query should treat payload as literal string
            result = db_session.execute(
                text("SELECT * FROM conversations WHERE id = :id"),
                {"id": payload}
            )
            # Should find no results (safe)
            assert result.fetchall() == []
            # Session still valid (no SQL execution)
            assert db_session.is_active

    def test_search_query_injection_prevention(self):
        """Test search functionality is injection-safe."""
        injection_queries = [
            "test'; DELETE FROM conversations WHERE user_id = 1; --",
            "test' AND 1=(SELECT COUNT(*) FROM users)--"
        ]

        for query in injection_queries:
            # Import actual search function
            from apps.chatbot.src.query_handler import search_conversations

            results = search_conversations(query)

            # Should return empty or safe results
            assert isinstance(results, list)
            # Verify database integrity
            assert conversation_count_unchanged()

    def test_vector_similarity_query_injection(self):
        """Test vector similarity queries are injection-safe."""
        malicious_vectors = [
            "1,2,3); DROP TABLE cwe_chunks; --",
            "'); DELETE FROM embeddings; --"
        ]

        for payload in malicious_vectors:
            with pytest.raises((ValueError, TypeError)):
                # Should fail type validation before SQL
                execute_vector_search(payload)

    def test_dynamic_query_builder_safety(self):
        """Test SecureQueryBuilder prevents injection."""
        from apps.chatbot.src.db import SecureQueryBuilder

        builder = SecureQueryBuilder()

        # Malicious table name
        with pytest.raises(ValueError, match="Invalid table name"):
            builder.select_from("users; DROP TABLE conversations--")

        # Malicious column name
        with pytest.raises(ValueError, match="Invalid column"):
            builder.select_columns(["id; DROP TABLE users--"])

    def test_orm_injection_resistance(self, db_session):
        """Test ORM provides injection resistance."""
        injection_payloads = [
            "admin' OR '1'='1'--",
            "'; DROP TABLE users; --"
        ]

        for payload in injection_payloads:
            # ORM should treat as literal
            from apps.chatbot.src.models import User
            result = db_session.query(User).filter(
                User.username == payload
            ).all()

            assert len(result) == 0  # No results
            # Verify users table intact
            assert db_session.query(User).count() > 0
```

**Step 3: Add Integration Tests with Real Database** (6 hours)
```python
@pytest.mark.integration
@pytest.mark.security
def test_sql_injection_with_real_database(test_db_url):
    """Integration test with actual PostgreSQL database."""
    engine = create_engine(test_db_url)

    # Test real database queries
    malicious_queries = [
        "'; DROP TABLE conversations; --",
        "' OR 1=1--"
    ]

    for payload in malicious_queries:
        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT * FROM conversations WHERE user_id = :user_id"),
                {"user_id": payload}
            )
            assert result.fetchall() == []

        # Verify database integrity after each attempt
        with engine.connect() as conn:
            tables = conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
            assert "conversations" in [row[0] for row in tables]
```

**Step 4: Add pgvector-Specific Tests** (4 hours)
```python
@pytest.mark.security
def test_vector_query_injection_prevention():
    """Test pgvector extension queries are injection-safe."""
    from apps.cwe_ingestion.cwe_ingestion.pg_chunk_store import PgVectorStore

    store = PgVectorStore()

    # Malicious vector input
    malicious_input = "'); DROP TABLE cwe_chunks; SELECT ('"

    with pytest.raises((ValueError, TypeError, psycopg.Error)):
        # Should fail before SQL execution
        store.search(malicious_input, k=10)
```

**Acceptance Criteria**:
- ✅ 20+ SQL injection test cases covering all query types
- ✅ Tests cover parameterized queries, ORM queries, vector queries
- ✅ Integration tests with real PostgreSQL database
- ✅ All tests pass (100% success rate)
- ✅ Tests added to CI/CD security gate

**Files to Create**:
- `tests/security/injection/__init__.py`
- `tests/security/injection/test_sql_injection_prevention.py`
- `tests/security/injection/conftest.py` (test fixtures)

---

### BLOCKER-3: Implement CSRF Protection (HIGH)
**Priority**: 🟡 **HIGH - REQUIRED FOR PUBLIC DEPLOYMENT**
**Status**: NOT STARTED
**Effort**: 4 hours

**Description**:
Chainlit WebSocket connections lack CSRF token validation. State-changing operations could be triggered via CSRF attacks if users have active sessions.

**Impact**:
- CVSS 7.1 - Potential session hijacking
- Required for public deployment with authentication
- OAuth provides partial protection but not sufficient

**Current State**:
```python
# apps/chatbot/main.py - No CSRF validation
@cl.on_message
async def main(message: cl.Message):
    user_query = message.content.strip()
    # Processes without CSRF validation
    await conversation_manager.process_user_message_streaming(...)
```

**Remediation Plan**:

**Step 1: Generate CSRF Token on Session Start** (1 hour)
```python
# apps/chatbot/main.py
import secrets

@cl.on_chat_start
async def start():
    """Generate CSRF token for new session."""
    csrf_token = secrets.token_urlsafe(32)
    cl.user_session.set("csrf_token", csrf_token)
    cl.user_session.set("csrf_created_at", time.time())

    # Send token to client (Chainlit metadata)
    await cl.Message(
        content="Welcome! Your session is secure.",
        metadata={"csrf_token": csrf_token}
    ).send()
```

**Step 2: Validate CSRF Token on Messages** (2 hours)
```python
@cl.on_message
async def main(message: cl.Message):
    """Validate CSRF token before processing."""
    # Get expected token
    expected_token = cl.user_session.get("csrf_token")
    provided_token = message.metadata.get("csrf_token")

    # Validate token
    if not expected_token or expected_token != provided_token:
        logger.warning("CSRF token validation failed")
        await cl.Message(
            content="Invalid request token. Please refresh your session."
        ).send()
        return

    # Token valid - proceed with processing
    user_query = message.content.strip()
    await conversation_manager.process_user_message_streaming(...)
```

**Step 3: Add CSRF Token Rotation** (1 hour)
```python
def rotate_csrf_token():
    """Rotate CSRF token periodically (every 15 minutes)."""
    created_at = cl.user_session.get("csrf_created_at", 0)
    if time.time() - created_at > 900:  # 15 minutes
        new_token = secrets.token_urlsafe(32)
        cl.user_session.set("csrf_token", new_token)
        cl.user_session.set("csrf_created_at", time.time())
        return new_token
    return cl.user_session.get("csrf_token")
```

**Acceptance Criteria**:
- ✅ CSRF token generated on session start
- ✅ Token validated on every state-changing operation
- ✅ Token rotation every 15 minutes
- ✅ Tests verify CSRF protection works
- ✅ Graceful error handling for invalid tokens

**Files to Modify**:
- `apps/chatbot/main.py` (add CSRF validation)
- `apps/chatbot/tests/test_security.py` (add CSRF tests)

---

### BLOCKER-4: Implement Rate Limiting (HIGH)
**Priority**: 🟡 **HIGH - COST CONTROL & DOS PREVENTION**
**Status**: DOCUMENTED (Story S-1.1 exists)
**Effort**: 8 hours (or use Cloud Armor)

**Description**:
No application-layer rate limiting for expensive Gemini API calls. Attackers could exhaust API quota or generate significant costs.

**Impact**:
- CVSS 7.5 - Denial of Service potential
- Cost control risk (Gemini API charges per token)
- Required before exposing to public traffic

**Options**:

**Option A: Application-Layer Rate Limiting** (8 hours)
```python
# apps/chatbot/src/rate_limiter.py
import time
from collections import defaultdict
from typing import Dict, List

class RateLimiter:
    """In-memory rate limiter for user queries."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def is_rate_limited(self, user_id: str) -> bool:
        """Check if user has exceeded rate limit."""
        now = time.time()

        # Clean old requests
        self._requests[user_id] = [
            t for t in self._requests[user_id]
            if now - t < self.window_seconds
        ]

        # Check limit
        if len(self._requests[user_id]) >= self.max_requests:
            return True

        # Record request
        self._requests[user_id].append(now)
        return False

# Usage in main.py
rate_limiter = RateLimiter(max_requests=10, window_seconds=60)

@cl.on_message
async def main(message: cl.Message):
    user_id = cl.user_session.get("user").identifier

    if rate_limiter.is_rate_limited(user_id):
        await cl.Message(
            content="Rate limit exceeded. Please wait before sending more messages."
        ).send()
        return

    # Process message normally
    ...
```

**Option B: Cloud Armor Rate Limiting** (Recommended)
- Already documented in Story S-1.1
- Edge-level protection (more efficient)
- No application code changes needed
- GCP-managed infrastructure

**Recommendation**: **Use Story S-1.1 (Cloud Armor)** for production.

For immediate unblocking, implement simple application-layer limiting (Option A) as temporary measure.

**Acceptance Criteria**:
- ✅ Rate limiting enforced (10 requests/min per user)
- ✅ Clear error message when limit exceeded
- ✅ Tests verify rate limiting works
- ✅ Monitoring/logging for rate limit hits

**Files to Create/Modify**:
- `apps/chatbot/src/rate_limiter.py` (new - if Option A)
- `apps/chatbot/main.py` (integrate rate limiting)
- `apps/chatbot/tests/test_rate_limiting.py` (new - tests)

**Alternative**: Deploy Story S-1.1 for Cloud Armor configuration (recommended for production).

---

## Implementation Priority & Timeline

### Week 1 (Days 1-5) - CRITICAL PATH
**Goal**: Fix blocking test issues

**Days 1-2** (16 hours):
- Fix 14 failing security tests
- Verify 100% pass rate
- Add CI gate for security tests

**Days 3-5** (24 hours):
- Create SQL injection test suite
- Implement 20+ test cases
- Integration tests with real database

**Milestone**: All security tests passing, database security validated

---

### Week 2 (Days 6-7) - PRODUCTION HARDENING
**Goal**: Implement missing security controls

**Day 6** (4 hours):
- Implement CSRF protection
- Add token validation
- Test CSRF prevention

**Day 7** (4 hours):
- Implement application-layer rate limiting (temporary)
- Add monitoring/logging
- Test rate limit enforcement

**Milestone**: Production blockers resolved, deployment ready

---

## Post-Deployment (Story S-1.1)
**Timeline**: Sprint N+1

- Deploy Cloud Armor rate limiting (replace temporary app-layer limit)
- Configure per-user edge rate limits
- Add DDoS protection
- Monitor and tune rate limit policies

---

## Testing Strategy

### Security Test Gate (CI/CD)
```yaml
# .github/workflows/security-tests.yml
name: Security Test Gate
on: [push, pull_request]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - name: Run Security Tests
        run: |
          poetry run pytest -m security_critical --maxfail=1

      - name: Verify 100% Pass Rate
        run: |
          # Fail if ANY security tests fail
          poetry run pytest -m security --tb=short --strict-markers

      - name: SQL Injection Tests
        run: |
          poetry run pytest tests/security/injection/ -v
```

### Pre-Deployment Checklist
```bash
# Run before ANY production deployment

# 1. All security tests pass
poetry run pytest -m security -v
# Expected: 50+ tests, 0 failures

# 2. SQL injection tests pass
poetry run pytest tests/security/injection/ -v
# Expected: 20+ tests, 0 failures

# 3. CSRF protection enabled
grep -n "csrf_token" apps/chatbot/main.py
# Expected: Token generation and validation present

# 4. Rate limiting enabled
grep -n "rate_limit" apps/chatbot/main.py
# Expected: Rate limiting logic present

# 5. Dependency scan
poetry show --outdated | grep -E "(lxml|cryptography|certifi)"
# Expected: All up to date
```

---

## Success Criteria for Production Deployment

### ✅ Must Have (Blockers)
- [x] lxml updated to 6.0.2
- [x] cryptography updated to 46.0.2
- [x] certifi updated to latest
- [ ] **All 28 security tests passing (currently 14 failing)**
- [ ] **SQL injection test suite created (currently 0 tests)**
- [ ] **CSRF protection implemented**
- [ ] **Rate limiting implemented**

### ✅ Should Have (Hardening)
- [ ] Session timeout implemented (15 min idle, 1 hour max)
- [ ] CSP headers added
- [ ] Authentication rate limiting added
- [ ] Security test coverage > 80%

### ✅ Nice to Have (Future Sprints)
- [ ] Cloud Armor rate limiting (Story S-1.1)
- [ ] VPC connector for network isolation
- [ ] WAF rules deployed
- [ ] Penetration testing completed

---

## Risk Assessment

### Current Risk Level: **HIGH**
**Reason**: 2 critical test gaps prevent verification of security controls

### Target Risk Level: **LOW**
**After**: All blockers resolved, comprehensive testing in place

### Risk If Deployed Now:
- ❌ Unknown SQL injection vulnerabilities (no tests)
- ❌ Cannot verify security features work (50% test failure)
- ❌ CSRF attacks possible
- ❌ DoS/cost abuse possible (no rate limiting)

**Conclusion**: **DO NOT DEPLOY to public production** until all blockers resolved.

---

## Contact & Support

**Security Lead**: Tanja (Vulnerability Assessment Analyst)
**Documentation**: `docs/security/COMPREHENSIVE_SECURITY_ASSESSMENT_2025-10-08.md`
**Story Reference**: Story S-1.1 (Rate Limiting and Budget Monitoring)

**Questions?** Review comprehensive security assessment for detailed findings and recommendations.

---

**End of Production Blockers Remediation Plan**
