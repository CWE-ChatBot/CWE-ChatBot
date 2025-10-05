#!/usr/bin/env python3
"""Test PDF worker with local OIDC tokens"""
import subprocess
import requests
import json
from pathlib import Path

FUNCTION_URL = "https://pdf-worker-bmgj6wj65a-uc.a.run.app"
SA = "cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com"
FIXTURES_DIR = Path(__file__).parent / "tests" / "fixtures"

def get_token():
    """Get OIDC token via service account impersonation"""
    result = subprocess.run(
        [
            "gcloud", "auth", "print-identity-token",
            f"--impersonate-service-account={SA}",
            f"--audiences={FUNCTION_URL}"
        ],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"STDERR: {result.stderr}")
        print(f"STDOUT: {result.stdout}")
        raise RuntimeError(f"Failed to get token: {result.stderr}")

    # Return only the token (skip WARNING lines)
    return [line for line in result.stdout.strip().split('\n') if line.startswith('eyJ')][0]

def test_unauthenticated():
    """Test 1: Unauthenticated request (expect 403)"""
    print("=== Test 1: Unauthenticated request (expect 403) ===")
    resp = requests.get(FUNCTION_URL)
    print(f"Status: {resp.status_code}")
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"
    print("✅ PASS\n")

def test_get_with_auth(token):
    """Test 2: GET with auth (expect 405 Method Not Allowed)"""
    print("=== Test 2: GET with auth (expect 405 Method Not Allowed) ===")
    resp = requests.get(
        FUNCTION_URL,
        headers={"Authorization": f"Bearer {token}"}
    )
    print(f"Status: {resp.status_code}")
    assert resp.status_code == 405, f"Expected 405, got {resp.status_code}"
    print("✅ PASS\n")

def test_sample_pdf(token):
    """Test 3: POST with sample.pdf (expect 200 with JSON)"""
    print("=== Test 3: POST with sample.pdf (expect 200 with JSON) ===")
    pdf_path = FIXTURES_DIR / "sample.pdf"
    with open(pdf_path, 'rb') as f:
        resp = requests.post(
            FUNCTION_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/pdf"
            },
            data=f.read()
        )
    print(f"Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        print(f"Response: {json.dumps(data, indent=2)[:200]}...")
        assert "text" in data, "Missing 'text' field"
        assert "pages" in data, "Missing 'pages' field"
        assert "sanitized" in data, "Missing 'sanitized' field"
        assert data["pages"] == 2, f"Expected 2 pages, got {data['pages']}"
        print("✅ PASS\n")
    else:
        print(f"Response: {resp.text[:200]}")
        raise AssertionError(f"Expected 200, got {resp.status_code}")

def test_encrypted_pdf(token):
    """Test 4: POST with encrypted.pdf (expect 422)"""
    print("=== Test 4: POST with encrypted.pdf (expect 422) ===")
    pdf_path = FIXTURES_DIR / "encrypted.pdf"
    with open(pdf_path, 'rb') as f:
        resp = requests.post(
            FUNCTION_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/pdf"
            },
            data=f.read()
        )
    print(f"Status: {resp.status_code}")
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}"
    print("✅ PASS\n")

def test_scanned_pdf(token):
    """Test 5: POST with scanned.pdf (expect 422 or 200 with empty/minimal text)"""
    print("=== Test 5: POST with scanned.pdf (expect 422 or 200) ===")
    pdf_path = FIXTURES_DIR / "scanned.pdf"
    with open(pdf_path, 'rb') as f:
        resp = requests.post(
            FUNCTION_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/pdf"
            },
            data=f.read()
        )
    print(f"Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        print(f"Extracted text length: {len(data.get('text', ''))}")
        print("✅ PASS (200 with minimal text is acceptable)\n")
    elif resp.status_code == 422:
        print("✅ PASS (422 for image-only PDF is acceptable)\n")
    else:
        raise AssertionError(f"Expected 200 or 422, got {resp.status_code}")

if __name__ == "__main__":
    try:
        # Test 1: Unauthenticated
        test_unauthenticated()

        # Get token for remaining tests
        print("Getting OIDC token via service account impersonation...")
        token = get_token()
        print(f"Token: {token[:50]}...\n")

        # Test 2-5: Authenticated requests
        test_get_with_auth(token)
        test_sample_pdf(token)
        test_encrypted_pdf(token)
        test_scanned_pdf(token)

        print("="*60)
        print("ALL TESTS PASSED ✅")
        print("="*60)

    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        raise
