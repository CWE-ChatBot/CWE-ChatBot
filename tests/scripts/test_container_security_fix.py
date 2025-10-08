#!/usr/bin/env python3
"""
Test to verify that the container image pinning security fix is working correctly.
This test validates that Dockerfile uses SHA256-pinned base images.
"""

import re
import sys
from pathlib import Path


def test_dockerfile_image_pinning():
    """Test that the Dockerfile uses SHA256-pinned base images."""
    print("🔒 Testing Container Image Pinning Fix...")

    dockerfile_path = Path("apps/chatbot/Dockerfile")
    if not dockerfile_path.exists():
        print(f"❌ Dockerfile not found at {dockerfile_path}")
        return False

    with open(dockerfile_path, "r") as f:
        content = f.read()

    # Pattern to match SHA256-pinned images
    sha256_pattern = r"FROM\s+[\w\-./]+:[\w.-]+@sha256:[a-f0-9]{64}"

    # Find all FROM instructions
    from_lines = []
    for i, line in enumerate(content.split("\n"), 1):
        if line.strip().startswith("FROM "):
            from_lines.append((i, line.strip()))

    if not from_lines:
        print("❌ No FROM instructions found in Dockerfile")
        return False

    pinned_count = 0
    total_count = len(from_lines)

    print(f"📋 Found {total_count} FROM instruction(s):")

    for line_num, from_line in from_lines:
        print(f"   Line {line_num}: {from_line}")

        if re.search(sha256_pattern, from_line):
            print("   ✅ SHA256-pinned image detected")
            pinned_count += 1
        else:
            print("   ❌ Image NOT pinned with SHA256 digest")

    if pinned_count == total_count:
        print("\n✅ Container security fix verified:")
        print(f"   ✅ All {total_count} base images are SHA256-pinned")
        print("   ✅ Supply chain attack protection enabled")
        print("   ✅ Immutable image references established")
        return True
    else:
        print("\n❌ Container security issue detected:")
        print(
            f"   ❌ {total_count - pinned_count} of {total_count} images are NOT pinned"
        )
        print("   ⚠️  Supply chain attack vulnerability remains")
        return False


def test_specific_python_image_pin():
    """Test that the Python base image uses the expected SHA256 digest."""
    print("\n🐍 Verifying Python Base Image SHA256 Digest...")

    dockerfile_path = Path("apps/chatbot/Dockerfile")
    with open(dockerfile_path, "r") as f:
        content = f.read()

    # Expected digest for python:3.11-slim (current as of Aug 2025)
    expected_digest = (
        "sha256:8df0e8faf75b3c17ac33dc90d76787bbbcae142679e11da8c6f16afae5605ea7"
    )

    if expected_digest in content:
        print(f"✅ Expected Python image digest found: {expected_digest}")
        return True
    else:
        print("❌ Expected digest not found in Dockerfile")
        print(f"   Expected: {expected_digest}")
        return False


def main():
    """Run all container security tests."""
    print("🐳 Container Image Security Fix Verification")
    print("=" * 50)

    test1_passed = test_dockerfile_image_pinning()
    test2_passed = test_specific_python_image_pin()

    print("\n" + "=" * 50)
    if test1_passed and test2_passed:
        print("🎉 ALL CONTAINER SECURITY TESTS PASSED!")
        print("✅ Medium vulnerability MED-001 has been successfully fixed")
        print("✅ Base images are now SHA256-pinned for supply chain security")
        print("✅ CVSS 5.9 vulnerability eliminated")
        return 0
    else:
        print("❌ SOME CONTAINER SECURITY TESTS FAILED!")
        print("⚠️  Container image pinning vulnerability may still exist")
        return 1


if __name__ == "__main__":
    sys.exit(main())
