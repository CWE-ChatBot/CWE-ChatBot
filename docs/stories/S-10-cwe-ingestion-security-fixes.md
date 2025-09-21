# Story S-10: CWE Ingestion Security Vulnerability Remediation

**Epic:** Security Hardening
**Priority:** CRITICAL (P0)
**Story Points:** 8
**Sprint:** Security Sprint 1
**Dependencies:** None (blocking story)

## Story Overview

Address critical and high-severity security vulnerabilities identified in the CWE ingestion pipeline security assessment. This story is **BLOCKING** for any production deployment and must be completed before Story 1.5 production readiness.

**Security Assessment Reference:** `docs/security/cwe_ingestion_security_assessment.md`

## Business Value

- **Risk Mitigation**: Eliminates CRITICAL (CVSS 8.8) and HIGH (CVSS 7.0-7.5) security vulnerabilities
- **Production Readiness**: Enables safe deployment of CWE ingestion pipeline
- **Compliance**: Meets defensive security standards for cybersecurity applications
- **Trust**: Ensures secure handling of sensitive CWE vulnerability data

## User Story

**As a** Security Engineer deploying the CWE ChatBot system
**I want** all critical and high-severity vulnerabilities in the ingestion pipeline fixed
**So that** the system can be safely deployed in production without security risks

## Acceptance Criteria

### 🔴 CRITICAL Fixes (MANDATORY)

#### AC-1: Fix Path Traversal Vulnerability (CRIT-001)
- [ ] **Location**: `apps/cwe_ingestion/embedding_cache.py:61-68`
- [ ] **Issue**: CWE ID parameter allows path traversal in cache filenames
- [ ] **Fix**: Implement input sanitization for CWE IDs in `_get_cache_filename()`
- [ ] **Validation**: Security test verifies path traversal prevention
- [ ] **CVSS**: 8.8 → 0.0 (eliminated)

**Implementation Requirements:**
```python
def _get_cache_filename(self, cache_key: str, cwe_id: str = None) -> Path:
    if cwe_id:
        # Sanitize CWE ID to prevent path traversal
        safe_id = re.sub(r'[^a-zA-Z0-9\-_]', '', cwe_id)
        if not safe_id or not safe_id.startswith('CWE-'):
            raise ValueError(f"Invalid CWE ID format: {cwe_id}")
        return self.cache_dir / f"embedding_{safe_id}_{cache_key}.pkl"
    return self.cache_dir / f"embedding_{cache_key}.pkl"
```

### 🔴 HIGH Priority Fixes (MANDATORY)

#### AC-2: Eliminate API Key Exposure (HIGH-001)
- [ ] **Location**: `apps/cwe_ingestion/embedder.py:275`
- [ ] **Issue**: Gemini API keys exposed in error messages
- [ ] **Fix**: Remove all API key references from error messages
- [ ] **Validation**: No API key fragments in logs or error output
- [ ] **CVSS**: 7.5 → 0.0 (eliminated)

**Implementation Requirements:**
```python
# BEFORE (vulnerable)
raise Exception(f"Gemini API error (key: {self.api_key_masked}): {str(e)}")

# AFTER (secure)
correlation_id = str(uuid.uuid4())[:8]
logger.error(f"Gemini API error (correlation: {correlation_id}): {type(e).__name__}")
raise Exception(f"Gemini API error (correlation: {correlation_id})")
```

#### AC-3: Secure ZIP File Extraction (HIGH-002)
- [ ] **Location**: `apps/cwe_ingestion/downloader.py:89-94`
- [ ] **Issue**: ZIP extraction vulnerable to path traversal
- [ ] **Fix**: Validate all extracted filenames for safety
- [ ] **Validation**: Test with malicious ZIP files containing path traversal
- [ ] **CVSS**: 7.0 → 0.0 (eliminated)

**Implementation Requirements:**
```python
# Validate extracted filename for path traversal
safe_name = os.path.basename(xml_filename)
if safe_name != xml_filename or '..' in xml_filename:
    raise ValueError(f"Unsafe filename in ZIP: {xml_filename}")
extracted_path = output_file.parent / safe_name
```

#### AC-4: Add SQL Parameter Bounds Checking (HIGH-003)
- [ ] **Location**: `apps/cwe_ingestion/pg_chunk_store.py:156-157`
- [ ] **Issue**: Dynamic DDL without bounds checking
- [ ] **Fix**: Add explicit bounds validation for `ivf_lists` parameter
- [ ] **Validation**: Test with extreme values and edge cases
- [ ] **CVSS**: 7.2 → 2.0 (mitigated)

**Implementation Requirements:**
```python
# Add bounds checking before DDL
ivf_lists = max(64, min(8192, int(ivf_lists)))
if not isinstance(ivf_lists, int) or ivf_lists < 64:
    raise ValueError(f"Invalid ivf_lists value: {ivf_lists}")
```

### 🟡 MEDIUM Priority Fixes (Recommended for Sprint)

#### AC-5: Strengthen XML Security (MED-001)
- [ ] **Location**: `apps/cwe_ingestion/parser.py:65`
- [ ] **Fix**: Add explicit XXE protection configuration
- [ ] **CVSS**: 6.5 → 1.0 (mitigated)

#### AC-6: Enhance Database Authentication (MED-002)
- [ ] **Location**: `apps/cwe_ingestion/pg_vector_store.py:95-110`
- [ ] **Fix**: Strengthen Cloud SQL IAM detection logic
- [ ] **CVSS**: 6.0 → 2.0 (mitigated)

### Security Testing Requirements

#### AC-7: Comprehensive Security Test Suite
- [ ] **Path Traversal Test**: Validate cache filename sanitization
- [ ] **API Key Exposure Test**: Verify no credentials in error output
- [ ] **ZIP Bomb Test**: Validate secure ZIP extraction
- [ ] **SQL Injection Test**: Verify bounds checking effectiveness
- [ ] **XML Security Test**: Validate XXE prevention

## Technical Implementation Plan

### Phase 1: Critical Vulnerabilities (Day 1-2)
1. **Fix CRIT-001**: Path traversal in cache operations
2. **Create security test**: Path traversal validation
3. **Verify fix**: Run security test suite

### Phase 2: High Vulnerabilities (Day 3-4)
1. **Fix HIGH-001**: API key exposure elimination
2. **Fix HIGH-002**: Secure ZIP extraction
3. **Fix HIGH-003**: SQL parameter bounds checking
4. **Create security tests**: For each vulnerability
5. **Integration testing**: Full pipeline security validation

### Phase 3: Medium Vulnerabilities (Day 5)
1. **Fix MED-001**: XML security hardening
2. **Fix MED-002**: Database authentication strengthening
3. **Final testing**: Complete security test suite
4. **Documentation**: Update security assessment

## Security Test Scripts

### Test Script 1: Path Traversal Prevention
**Location**: `tests/security/test_path_traversal_fix.py`

```python
import pytest
from pathlib import Path
from apps.cwe_ingestion.embedding_cache import EmbeddingCache

def test_cache_filename_sanitization():
    """Test that malicious CWE IDs are properly sanitized."""
    cache = EmbeddingCache("test_cache")

    # Test path traversal attempts
    malicious_ids = [
        "../../../etc/passwd",
        "CWE-78/../../../etc/passwd",
        "CWE-78\x00/etc/passwd",
        "CWE-78;rm -rf /",
        "CWE-78|cat /etc/passwd"
    ]

    for malicious_id in malicious_ids:
        with pytest.raises(ValueError, match="Invalid CWE ID format"):
            cache._get_cache_filename("test_key", malicious_id)
```

### Test Script 2: API Key Exposure Prevention
**Location**: `tests/security/test_api_key_exposure_fix.py`

```python
def test_no_api_key_in_errors():
    """Verify API keys are not exposed in error messages."""
    embedder = GeminiEmbedder("test-api-key-should-not-appear")

    # Trigger error condition
    with pytest.raises(Exception) as exc_info:
        embedder.embed_text("invalid input that causes error")

    # Verify no API key fragments in error
    error_message = str(exc_info.value)
    assert "test-api-key" not in error_message.lower()
    assert "api" not in error_message.lower() or "correlation" in error_message.lower()
```

### Test Script 3: ZIP Security Validation
**Location**: `tests/security/test_zip_security_fix.py`

```python
def test_zip_path_traversal_prevention():
    """Test that ZIP extraction prevents path traversal."""
    # Create malicious ZIP with path traversal
    malicious_paths = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/passwd",
        "subdirectory/../../../etc/passwd"
    ]

    for path in malicious_paths:
        with pytest.raises(ValueError, match="Unsafe filename in ZIP"):
            downloader._extract_zip_safely(malicious_zip, path)
```

## Definition of Done

### Security Validation Checklist
- [ ] All CRITICAL vulnerabilities eliminated (CVSS 0.0)
- [ ] All HIGH vulnerabilities eliminated (CVSS 0.0)
- [ ] Security test suite passes 100%
- [ ] No API keys visible in logs or error messages
- [ ] Path traversal attacks prevented
- [ ] ZIP extraction secure against malicious archives
- [ ] SQL parameters properly bounded
- [ ] Security assessment updated with fixes
- [ ] Code review completed by security-focused reviewer

### Deployment Readiness
- [ ] All security tests integrated into CI/CD pipeline
- [ ] Security fixes verified in staging environment
- [ ] Production deployment security checklist completed
- [ ] Security documentation updated

## Risk Assessment

### Before Fixes (Current State)
- **Critical Risk**: Remote code execution via path traversal
- **High Risk**: Credential exposure and file system attacks
- **Production Readiness**: ❌ **BLOCKED**

### After Fixes (Target State)
- **Critical Risk**: ✅ **ELIMINATED**
- **High Risk**: ✅ **ELIMINATED**
- **Production Readiness**: ✅ **ENABLED**

## Dependencies and Blockers

### Blocking Items
- None (this story removes blockers for other stories)

### Dependent Stories
- **Story 1.5**: Production Infrastructure (blocked until S-10 complete)
- **Story 2.2**: Performance Optimization (should include security fixes)
- **All production deployment stories**

## Success Metrics

1. **Vulnerability Count**: 8 → 0 (Critical/High vulnerabilities)
2. **CVSS Score**: Reduce average from 7.1 to < 2.0
3. **Security Test Coverage**: 100% for all identified vulnerabilities
4. **Production Readiness**: Security gate passes

## Related Documentation

- **Security Assessment**: `docs/security/cwe_ingestion_security_assessment.md`
- **Testing Guide**: `tests/security/README.md` (to be created)
- **Security Architecture**: `docs/architecture/security.md`

---

**⚠️ CRITICAL NOTICE**: This story is **BLOCKING** for production deployment. All Critical and High severity vulnerabilities must be resolved before any production release.

**Security Review Required**: All fixes must be reviewed by security-focused team member before merging.

**Status**: 🔴 **NOT STARTED** - Awaiting immediate prioritization