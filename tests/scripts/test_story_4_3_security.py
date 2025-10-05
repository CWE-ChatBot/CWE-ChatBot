#!/usr/bin/env python3
"""
Security verification tests for Story 4.3 - Ephemeral PDF Extraction System.

Verifies security requirements:
- No disk persistence (AC9)
- Input validation (AC1, AC2, AC3)
- Size limits enforced (AC4, AC6)
- OIDC authentication required (AC5)
- Security headers present (AC8)

Run from project root:
    python3 tests/scripts/test_story_4_3_security.py
"""
import sys
import os
from pathlib import Path


def test_no_disk_writes_in_pdf_worker():
    """Verify PDF worker uses memory-only processing (AC9)."""
    print("\n[TEST] Verifying no disk writes in PDF worker...")

    pdf_worker_path = Path("apps/pdf_worker/main.py")
    if not pdf_worker_path.exists():
        print("❌ FAIL: PDF worker not found")
        return False

    content = pdf_worker_path.read_text()

    # Check for forbidden disk write operations
    forbidden_patterns = [
        (r"with open\(", "Context manager file open"),
        (r"\.write_", "Pathlib write"),
        (r"tempfile\.NamedTemporaryFile", "Named temp files"),
    ]

    # Allowed patterns that look like forbidden ones
    allowed_patterns = [
        "pikepdf.open",  # pikepdf library, not file open
        "BytesIO",  # Memory-only
    ]

    violations = []
    for pattern, description in forbidden_patterns:
        if pattern.replace("\\", "") in content:
            # Check if it's a false positive
            lines = [line for line in content.split('\n') if pattern.replace("\\", "") in line]
            for line in lines:
                # Skip comments
                if line.strip().startswith('#'):
                    continue
                # Skip if it's an allowed pattern
                if any(allowed in line for allowed in allowed_patterns):
                    continue
                violations.append(f"{description}: {line.strip()[:60]}")

    if violations:
        print(f"❌ FAIL: Disk write operations detected")
        for v in violations:
            print(f"  - {v}")
        return False

    # Check that BytesIO is used
    if "BytesIO" not in content:
        print("❌ FAIL: BytesIO not found (memory-only processing required)")
        return False

    print("✅ PASS: No disk writes detected, using BytesIO for memory-only processing")
    return True


def test_input_validation_in_pdf_worker():
    """Verify PDF worker validates inputs (AC1, AC2, AC6)."""
    print("\n[TEST] Verifying input validation in PDF worker...")

    pdf_worker_path = Path("apps/pdf_worker/main.py")
    if not pdf_worker_path.exists():
        print("❌ FAIL: PDF worker not found")
        return False

    content = pdf_worker_path.read_text()

    required_validations = [
        ("PDF magic bytes", "b'%PDF-'", "AC1 - Magic byte validation"),
        ("Size limit", "MAX_BYTES", "AC6 - File size limit"),
        ("Page limit", "MAX_PAGES", "AC6 - Page count limit"),
    ]

    missing = []
    for name, pattern, ac in required_validations:
        if pattern not in content:
            missing.append(f"{name} ({ac})")

    if missing:
        print(f"❌ FAIL: Missing validations: {', '.join(missing)}")
        return False

    print("✅ PASS: All input validations present")
    return True


def test_text_validation_in_file_processor():
    """Verify text file validation (AC3)."""
    print("\n[TEST] Verifying text file validation in file_processor...")

    file_processor_path = Path("apps/chatbot/src/file_processor.py")
    if not file_processor_path.exists():
        print("❌ FAIL: file_processor.py not found")
        return False

    content = file_processor_path.read_text()

    required_validations = [
        ("NUL byte rejection", "b'\\x00'", "AC3 - Binary rejection"),
        ("Printable ratio check", "printable", "AC3 - Text validation"),
        ("UTF-8 validation", "utf-8", "AC3 - Encoding check"),
        ("Character truncation", "1_000_000", "AC3 - Size limit"),
    ]

    missing = []
    for name, pattern, ac in required_validations:
        if pattern not in content:
            missing.append(f"{name} ({ac})")

    if missing:
        print(f"❌ FAIL: Missing text validations: {', '.join(missing)}")
        return False

    print("✅ PASS: All text validations present")
    return True


def test_oidc_authentication_implemented():
    """Verify OIDC authentication is implemented (AC5)."""
    print("\n[TEST] Verifying OIDC authentication implementation...")

    file_processor_path = Path("apps/chatbot/src/file_processor.py")
    if not file_processor_path.exists():
        print("❌ FAIL: file_processor.py not found")
        return False

    content = file_processor_path.read_text()

    required_components = [
        ("google.auth import", "google.auth", "AC5 - Auth library"),
        ("IDTokenCredentials", "IDTokenCredentials", "AC5 - OIDC tokens"),
        ("get_oidc_token method", "async def get_oidc_token", "AC5 - Token fetching"),
        ("Authorization header", "Authorization", "AC5 - Token usage"),
    ]

    missing = []
    for name, pattern, ac in required_components:
        if pattern not in content:
            missing.append(f"{name} ({ac})")

    if missing:
        print(f"❌ FAIL: Missing OIDC components: {', '.join(missing)}")
        return False

    print("✅ PASS: OIDC authentication implemented")
    return True


def test_security_headers_in_pdf_worker():
    """Verify security headers are set (AC8)."""
    print("\n[TEST] Verifying security headers in PDF worker...")

    pdf_worker_path = Path("apps/pdf_worker/main.py")
    if not pdf_worker_path.exists():
        print("❌ FAIL: PDF worker not found")
        return False

    content = pdf_worker_path.read_text()

    required_headers = [
        ("X-Content-Type-Options", "X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "Referrer-Policy", "no-referrer"),
        ("X-Frame-Options", "X-Frame-Options", "DENY"),
    ]

    missing = []
    for name, header, value in required_headers:
        if header not in content or value not in content:
            missing.append(f"{name}: {value}")

    if missing:
        print(f"❌ FAIL: Missing security headers: {', '.join(missing)}")
        return False

    # Verify headers are set via after_request decorator
    if "@app.after_request" not in content:
        print("❌ FAIL: Security headers not set via after_request decorator")
        return False

    print("✅ PASS: All security headers configured")
    return True


def test_error_taxonomy_stable_codes():
    """Verify stable error codes are defined (AC7)."""
    print("\n[TEST] Verifying stable error taxonomy...")

    file_processor_path = Path("apps/chatbot/src/file_processor.py")
    if not file_processor_path.exists():
        print("❌ FAIL: file_processor.py not found")
        return False

    content = file_processor_path.read_text()

    # Check for get_friendly_error method
    if "def get_friendly_error" not in content:
        print("❌ FAIL: get_friendly_error method not found")
        return False

    # Check for key error codes
    required_error_codes = [
        "too_large",
        "pdf_magic_missing",
        "encrypted_pdf_unsupported",
        "binary_text_rejected",
        "worker_unavailable",
    ]

    missing_codes = []
    for code in required_error_codes:
        if f"'{code}'" not in content and f'"{code}"' not in content:
            missing_codes.append(code)

    if missing_codes:
        print(f"❌ FAIL: Missing error codes: {', '.join(missing_codes)}")
        return False

    print("✅ PASS: Error taxonomy with stable codes implemented")
    return True


def test_no_command_injection_vulnerabilities():
    """Verify no command injection vulnerabilities exist."""
    print("\n[TEST] Verifying no command injection vulnerabilities...")

    paths_to_check = [
        Path("apps/pdf_worker/main.py"),
        Path("apps/chatbot/src/file_processor.py"),
    ]

    forbidden_patterns = [
        ("os.system", "Command injection risk"),
        ("subprocess.shell=True", "Shell injection risk"),
        ("eval(", "Code injection risk"),
        ("exec(", "Code injection risk"),
    ]

    violations = []
    for path in paths_to_check:
        if not path.exists():
            continue

        content = path.read_text()
        for pattern, reason in forbidden_patterns:
            if pattern in content:
                # Check if it's in a comment
                lines = [line for line in content.split('\n') if pattern in line]
                for line in lines:
                    if not line.strip().startswith('#'):
                        violations.append(f"{path}: {reason} - {pattern}")

    if violations:
        print(f"❌ FAIL: Command injection vulnerabilities detected")
        for v in violations:
            print(f"  - {v}")
        return False

    print("✅ PASS: No command injection vulnerabilities")
    return True


def test_dependencies_updated():
    """Verify required dependencies are in requirements.txt."""
    print("\n[TEST] Verifying dependencies updated...")

    requirements_path = Path("apps/chatbot/requirements.txt")
    if not requirements_path.exists():
        print("❌ FAIL: requirements.txt not found")
        return False

    content = requirements_path.read_text()

    required_deps = [
        ("google-auth", "OIDC authentication"),
        ("httpx", "Async HTTP client"),
        ("chardet", "Encoding detection"),
    ]

    missing = []
    for dep, purpose in required_deps:
        if dep not in content:
            missing.append(f"{dep} ({purpose})")

    if missing:
        print(f"❌ FAIL: Missing dependencies: {', '.join(missing)}")
        return False

    print("✅ PASS: All required dependencies present")
    return True


def main():
    """Run all security tests for Story 4.3."""
    print("=" * 60)
    print("Security Verification Tests - Story 4.3")
    print("Ephemeral PDF Extraction System")
    print("=" * 60)

    # Change to project root
    project_root = Path(__file__).parent.parent.parent
    os.chdir(project_root)

    tests = [
        test_no_disk_writes_in_pdf_worker,
        test_input_validation_in_pdf_worker,
        test_text_validation_in_file_processor,
        test_oidc_authentication_implemented,
        test_security_headers_in_pdf_worker,
        test_error_taxonomy_stable_codes,
        test_no_command_injection_vulnerabilities,
        test_dependencies_updated,
    ]

    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"❌ ERROR in {test.__name__}: {e}")
            results.append(False)

    print("\n" + "=" * 60)
    print(f"Results: {sum(results)}/{len(results)} tests passed")
    print("=" * 60)

    if all(results):
        print("\n✅ All security tests PASSED")
        return 0
    else:
        print("\n❌ Some security tests FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
