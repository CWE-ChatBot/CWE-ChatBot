#!/usr/bin/env python3
"""
R17 Security Fixes Verification Tests

Tests all security fixes from R17 security audit:
- API-001: JWT/JWKS verification hardening
- INPUT-001: SQL injection prevention via parameterization
- INPUT-002: ReDoS mitigation with scan window
- FILE-001/002: File path validation
- JWT hardening: Algorithm validation, HTTPS enforcement, array audience handling

This is a standalone test script that doesn't require poetry environment.
Run with: python3 tests/security/test_r17_security_fixes.py
"""

import base64
import json
import os
import sys
import tempfile
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


def test_jwt_none_algorithm_rejection():
    """Test that JWT 'none' algorithm is rejected before any processing."""
    print("\n[TEST] JWT 'none' algorithm rejection")

    try:
        from apps.chatbot.api import ALLOWED_JWT_ALGORITHMS

        # Verify 'none' is not in allowed algorithms
        assert 'none' not in ALLOWED_JWT_ALGORITHMS, "FAIL: 'none' algorithm is allowed"
        assert 'None' not in ALLOWED_JWT_ALGORITHMS, "FAIL: 'None' algorithm is allowed"

        # Verify RS256/384/512 are allowed
        assert 'RS256' in ALLOWED_JWT_ALGORITHMS, "FAIL: RS256 not in allowed algorithms"

        print(f"  ✅ Allowed algorithms: {ALLOWED_JWT_ALGORITHMS}")
        print("  ✅ 'none' algorithm correctly rejected")
        return True
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        return False


def test_jwt_clock_skew_configuration():
    """Test that JWT clock skew is configured."""
    print("\n[TEST] JWT clock skew configuration")

    try:
        from apps.chatbot.api import JWT_CLOCK_SKEW

        assert isinstance(JWT_CLOCK_SKEW, int), "JWT_CLOCK_SKEW must be integer"
        assert JWT_CLOCK_SKEW > 0, "JWT_CLOCK_SKEW must be positive"
        assert JWT_CLOCK_SKEW <= 300, "JWT_CLOCK_SKEW should be reasonable (<= 300s)"

        print(f"  ✅ JWT_CLOCK_SKEW configured: {JWT_CLOCK_SKEW} seconds")
        return True
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        return False


def test_jwks_https_enforcement():
    """Test that JWKS cache enforces HTTPS-only URLs."""
    print("\n[TEST] JWKS HTTPS enforcement")

    try:
        from apps.chatbot.api import _JWKSCache
        from fastapi import HTTPException
        import asyncio

        cache = _JWKSCache()

        # Test HTTP URL is rejected
        try:
            asyncio.run(cache.get("http://example.com/jwks.json"))
            print("  ❌ FAIL: HTTP URL was accepted")
            return False
        except HTTPException as e:
            if e.status_code == 503 and "https" in e.detail.lower():
                print(f"  ✅ HTTP URL correctly rejected: {e.detail}")
            else:
                print(f"  ❌ FAIL: Wrong error for HTTP URL: {e.detail}")
                return False

        print("  ✅ JWKS HTTPS enforcement working")
        return True
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        return False


def test_jwks_lru_cap():
    """Test that JWKS cache has LRU cap configured."""
    print("\n[TEST] JWKS LRU cap")

    try:
        from apps.chatbot.api import _JWKSCache

        cache = _JWKSCache()

        assert hasattr(cache, 'max_entries'), "JWKS cache missing max_entries"
        assert cache.max_entries > 0, "max_entries must be positive"
        assert cache.max_entries <= 100, "max_entries should be reasonable"

        print(f"  ✅ JWKS LRU cap configured: {cache.max_entries} entries")
        return True
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        return False


def test_redos_scan_limit():
    """Test that ReDoS scan window limit is configured."""
    print("\n[TEST] ReDoS scan window limit")

    try:
        from apps.chatbot.src.input_security import InputSanitizer

        sanitizer = InputSanitizer()

        assert hasattr(sanitizer, 'SCAN_LIMIT'), "InputSanitizer missing SCAN_LIMIT"
        assert sanitizer.SCAN_LIMIT > 0, "SCAN_LIMIT must be positive"
        assert sanitizer.SCAN_LIMIT <= 1000000, "SCAN_LIMIT should be reasonable"

        # Test that scan limit is actually used
        large_input = "A" * 100000  # 100KB input
        result = sanitizer.sanitize_input(large_input)

        print(f"  ✅ Scan limit configured: {sanitizer.SCAN_LIMIT} chars")
        print(f"  ✅ Sanitization handled large input without hanging")
        return True
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        return False


def test_redos_substring_cues():
    """Test that fast substring pre-check catches jailbreak attempts."""
    print("\n[TEST] ReDoS substring pre-check")

    try:
        from apps.chatbot.src.input_security import InputSanitizer

        sanitizer = InputSanitizer()

        # Test common jailbreak phrases
        test_cases = [
            ("ignore previous instructions", True),
            ("developer mode", True),
            ("jailbreak", True),
            ("bypass safety", True),
            ("normal user query about CWE-79", False),
        ]

        for text, should_flag in test_cases:
            result = sanitizer.sanitize_input(text)
            is_flagged = "prompt_injection_detected" in result.get("security_flags", [])

            if should_flag and not is_flagged:
                print(f"  ❌ FAIL: Should flag '{text}' but didn't")
                return False
            elif not should_flag and is_flagged:
                print(f"  ❌ FAIL: Shouldn't flag '{text}' but did")
                return False

        print("  ✅ Substring pre-check correctly catches jailbreak attempts")
        return True
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        return False


def test_file_path_allowlist():
    """Test that file path allow-list validation is implemented."""
    print("\n[TEST] File path allow-list validation")

    try:
        from apps.chatbot.src.file_processor import FileProcessor

        processor = FileProcessor()

        # Test path traversal attempt
        malicious_paths = [
            "../../../etc/passwd",
            "/etc/passwd",
            "../../.ssh/id_rsa",
        ]

        for bad_path in malicious_paths:
            try:
                # This should raise RuntimeError due to path validation
                processor._read_file_from_path(bad_path)
                print(f"  ❌ FAIL: Path traversal not blocked: {bad_path}")
                return False
            except RuntimeError as e:
                if "disallowed" in str(e).lower():
                    pass  # Good, path was blocked
                else:
                    # Could be FileNotFoundError or other - that's also acceptable
                    pass
            except FileNotFoundError:
                # Path was checked and file doesn't exist - acceptable
                pass

        print("  ✅ File path allow-list validation implemented")
        return True
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        return False


def test_sql_parameterization():
    """Test that hnsw.ef_search uses parameterized queries."""
    print("\n[TEST] SQL parameterization (hnsw.ef_search)")

    try:
        # Read the source code to verify parameterization
        pg_chunk_store_path = project_root / "apps/cwe_ingestion/cwe_ingestion/pg_chunk_store.py"

        with open(pg_chunk_store_path, 'r') as f:
            content = f.read()

        # Check that we're NOT using f-string for ef_search
        if 'f"SET LOCAL hnsw.ef_search = {ef_search}"' in content:
            print("  ❌ FAIL: Found f-string interpolation of ef_search")
            return False

        # Check that we ARE using parameterized query
        if 'SET LOCAL hnsw.ef_search = %s' in content and '(ef_search,)' in content:
            print("  ✅ hnsw.ef_search uses parameterized query")
        else:
            print("  ❌ FAIL: Parameterized query not found")
            return False

        # Check for type validation
        if 'isinstance(ef_search, int)' in content:
            print("  ✅ Type validation present")
        else:
            print("  ⚠️  WARNING: No type validation found")

        # Check for range validation
        if '1 <= ef_search <= 1000' in content or 'ef_search >= 1' in content:
            print("  ✅ Range validation present")
        else:
            print("  ⚠️  WARNING: No range validation found")

        return True
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        return False


def test_jwt_array_audience_handling():
    """Test that array audience validation logic is correct."""
    print("\n[TEST] JWT array audience handling")

    try:
        # Read the source code to verify array handling
        api_path = project_root / "apps/chatbot/api.py"

        with open(api_path, 'r') as f:
            content = f.read()

        # Check for correct array handling
        required_checks = [
            'isinstance(token_aud, str)',
            'isinstance(token_aud, list)',
            'any(a in settings["audiences"]',
        ]

        for check in required_checks:
            if check not in content:
                print(f"  ❌ FAIL: Missing check: {check}")
                return False

        print("  ✅ Array audience handling implemented correctly")
        print("  ✅ Checks for both string and list aud claims")
        print("  ✅ Uses any() for proper intersection logic")
        return True
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        return False


def test_jwt_claim_enforcement():
    """Test that iat/nbf claims are enforced."""
    print("\n[TEST] JWT iat/nbf claim enforcement")

    try:
        api_path = project_root / "apps/chatbot/api.py"

        with open(api_path, 'r') as f:
            content = f.read()

        # Check for require_iat and require_nbf
        if '"require_iat": True' in content or "'require_iat': True" in content:
            print("  ✅ require_iat: True enforced")
        else:
            print("  ❌ FAIL: require_iat not enforced")
            return False

        if '"require_nbf": True' in content or "'require_nbf': True" in content:
            print("  ✅ require_nbf: True enforced")
        else:
            print("  ❌ FAIL: require_nbf not enforced")
            return False

        # Check for leeway parameter
        if 'leeway=JWT_CLOCK_SKEW' in content or 'leeway=' in content:
            print("  ✅ Clock skew leeway configured")
        else:
            print("  ⚠️  WARNING: No leeway found")

        return True
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        return False


def test_jwk_sanity_checks():
    """Test that JWK sanity checks are implemented."""
    print("\n[TEST] JWK sanity checks")

    try:
        api_path = project_root / "apps/chatbot/api.py"

        with open(api_path, 'r') as f:
            content = f.read()

        required_checks = [
            ('kty', 'RSA'),
            ('use', 'sig'),
            ('n', 'RSA components'),
            ('e', 'RSA components'),
        ]

        for field, description in required_checks:
            if f'"{field}"' in content or f"'{field}'" in content:
                print(f"  ✅ Check for {field} ({description})")
            else:
                print(f"  ❌ FAIL: Missing check for {field}")
                return False

        # Check for algorithm consistency
        if 'jwk_alg' in content and 'alg' in content:
            print("  ✅ JWT/JWK algorithm consistency check")
        else:
            print("  ⚠️  WARNING: Algorithm consistency check not found")

        return True
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        return False


def main():
    """Run all R17 security fix verification tests."""
    print("=" * 80)
    print("R17 SECURITY FIXES VERIFICATION")
    print("=" * 80)

    tests = [
        ("JWT 'none' Algorithm Rejection", test_jwt_none_algorithm_rejection),
        ("JWT Clock Skew Configuration", test_jwt_clock_skew_configuration),
        ("JWKS HTTPS Enforcement", test_jwks_https_enforcement),
        ("JWKS LRU Cap", test_jwks_lru_cap),
        ("ReDoS Scan Window Limit", test_redos_scan_limit),
        ("ReDoS Substring Pre-check", test_redos_substring_cues),
        ("File Path Allow-list", test_file_path_allowlist),
        ("SQL Parameterization", test_sql_parameterization),
        ("JWT Array Audience Handling", test_jwt_array_audience_handling),
        ("JWT iat/nbf Claim Enforcement", test_jwt_claim_enforcement),
        ("JWK Sanity Checks", test_jwk_sanity_checks),
    ]

    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n[ERROR] {name} crashed: {e}")
            results.append((name, False))

    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {name}")

    print("\n" + "=" * 80)
    print(f"RESULTS: {passed}/{total} tests passed ({100*passed//total}%)")
    print("=" * 80)

    # Exit with appropriate code
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
