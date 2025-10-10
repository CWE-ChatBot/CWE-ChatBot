"""
Integration tests for per-IP rate limiting (Story S-1).

Tests verify that Cloud Armor enforces 300 RPM per IP address as baseline DDoS protection.

Test Environment:
- Cloud Armor policy: cwe-chatbot-armor
- Priority 1300: Per-IP rate limiting
- Rate limit: 300 requests/minute per IP
- Ban threshold: 600 requests/minute
- Ban duration: 600 seconds (10 minutes)

Prerequisites:
- Service must be publicly accessible at https://cwe.crashedmind.com
- Cloud Armor policy must be attached to load balancer
- Rule at priority 1300 must be deployed
"""

import os
import time
from typing import Dict, List, Tuple

import pytest
import requests


# ============================================================================
# Configuration
# ============================================================================

SERVICE_URL = os.getenv("SERVICE_URL", "https://cwe.crashedmind.com")
RATE_LIMIT_RPM = 300  # Requests per minute per IP
RATE_LIMIT_WINDOW = 60  # Seconds
BAN_THRESHOLD = 600  # Requests to trigger ban
BAN_DURATION = 600  # Ban duration in seconds


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def validate_env():
    """Validate test environment before running tests."""
    assert SERVICE_URL.startswith("https://"), "SERVICE_URL must be HTTPS"

    # Verify service is accessible
    try:
        response = requests.get(SERVICE_URL, timeout=10)
        assert response.status_code in (200, 401, 403, 404), \
            f"Service not accessible: {response.status_code}"
    except requests.exceptions.RequestException as e:
        pytest.fail(f"Cannot reach service at {SERVICE_URL}: {e}")

    return True


def make_request(url: str, headers: Dict[str, str] = None) -> requests.Response:
    """Make HTTP request with error handling."""
    try:
        return requests.get(url, headers=headers or {}, timeout=10)
    except requests.exceptions.Timeout:
        pytest.fail(f"Request timeout to {url}")
    except requests.exceptions.RequestException as e:
        pytest.fail(f"Request failed: {e}")


def make_burst_requests(
    url: str,
    count: int,
    headers: Dict[str, str] = None,
    delay: float = 0.0
) -> List[Tuple[int, float]]:
    """
    Make burst of requests and return status codes with timestamps.

    Returns:
        List of (status_code, timestamp) tuples
    """
    results = []
    start_time = time.time()

    for i in range(count):
        response = make_request(url, headers)
        elapsed = time.time() - start_time
        results.append((response.status_code, elapsed))

        if delay > 0:
            time.sleep(delay)

    return results


# ============================================================================
# Per-IP Rate Limiting Tests
# ============================================================================

def test_per_ip_rate_limit_under_threshold(validate_env):
    """
    Test that requests under 300 RPM per IP are allowed.

    Expected: All requests return 200 (or non-429 status)
    """
    # Send 50 requests (well under 300 RPM threshold)
    results = make_burst_requests(SERVICE_URL, count=50, delay=0.1)

    status_codes = [status for status, _ in results]
    rate_limited_count = sum(1 for status in status_codes if status == 429)

    assert rate_limited_count == 0, \
        f"Expected no rate limiting under threshold, got {rate_limited_count} 429s"

    print(f"✅ Sent 50 requests, 0 rate limited")


def test_per_ip_rate_limit_exceed_threshold(validate_env):
    """
    Test that exceeding 300 RPM per IP triggers rate limiting.

    Expected: After ~300 requests in 60 seconds, subsequent requests get 429
    """
    # Calculate request rate to exceed 300 RPM
    target_requests = 350  # Exceed 300 RPM threshold
    request_interval = RATE_LIMIT_WINDOW / target_requests  # ~0.17 seconds

    print(f"Sending {target_requests} requests over ~{RATE_LIMIT_WINDOW}s "
          f"(interval: {request_interval:.3f}s)")

    results = make_burst_requests(
        SERVICE_URL,
        count=target_requests,
        delay=request_interval
    )

    status_codes = [status for status, _ in results]
    rate_limited_count = sum(1 for status in status_codes if status == 429)

    # Expect rate limiting to kick in after ~300 requests
    assert rate_limited_count > 0, \
        f"Expected rate limiting after {target_requests} requests, got 0 429s"

    # Find when rate limiting started
    first_429_index = next(
        (i for i, status in enumerate(status_codes) if status == 429),
        None
    )

    assert first_429_index is not None, "No 429 responses found"
    assert first_429_index >= 250, \
        f"Rate limiting triggered too early at request {first_429_index}"

    print(f"✅ Rate limiting triggered after {first_429_index} requests")
    print(f"   Total rate limited: {rate_limited_count}/{target_requests}")


def test_per_ip_rate_limit_sliding_window(validate_env):
    """
    Test that rate limiting uses a sliding 60-second window.

    Expected:
    1. Burst of 320 requests triggers rate limiting
    2. After waiting 60+ seconds, requests are allowed again
    """
    print("Phase 1: Triggering rate limit with burst...")

    # Burst 320 requests quickly (exceed 300 RPM)
    burst_results = make_burst_requests(SERVICE_URL, count=320, delay=0.05)

    burst_status_codes = [status for status, _ in burst_results]
    burst_429_count = sum(1 for status in burst_status_codes if status == 429)

    assert burst_429_count > 0, "Expected rate limiting from burst"
    print(f"✅ Burst triggered rate limiting: {burst_429_count} 429s")

    print("\nPhase 2: Waiting for sliding window to expire...")
    time.sleep(65)  # Wait for 60-second window to expire

    print("Phase 3: Testing if requests are allowed after window...")
    recovery_results = make_burst_requests(SERVICE_URL, count=10, delay=0.5)

    recovery_status_codes = [status for status, _ in recovery_results]
    recovery_429_count = sum(1 for status in recovery_status_codes if status == 429)

    # After window expires, new requests should be allowed
    assert recovery_429_count == 0, \
        f"Expected no rate limiting after window expiry, got {recovery_429_count} 429s"

    print(f"✅ Requests allowed after sliding window expired")


@pytest.mark.slow
def test_per_ip_ban_after_sustained_abuse(validate_env):
    """
    Test that sustained abuse (600 requests in 60s) triggers IP ban.

    Expected:
    1. After 600 requests in 60 seconds, IP is banned
    2. All subsequent requests return 429 for 10 minutes

    Warning: This test triggers an IP ban and takes 10+ minutes to complete.
    """
    print("⚠️  WARNING: This test will ban your IP for 10 minutes!")
    print("Phase 1: Triggering IP ban with sustained high volume...")

    # Send 650 requests to exceed ban threshold (600)
    ban_trigger_interval = RATE_LIMIT_WINDOW / 650  # ~0.092 seconds

    ban_results = make_burst_requests(
        SERVICE_URL,
        count=650,
        delay=ban_trigger_interval
    )

    ban_status_codes = [status for status, _ in ban_results]
    ban_429_count = sum(1 for status in ban_status_codes if status == 429)

    assert ban_429_count > 0, "Expected rate limiting from abuse"
    print(f"✅ Triggered rate limiting: {ban_429_count} 429s")

    print("\nPhase 2: Verifying IP ban is active...")
    time.sleep(5)  # Brief pause

    # All requests should now return 429 (IP banned)
    banned_results = make_burst_requests(SERVICE_URL, count=10, delay=1.0)
    banned_status_codes = [status for status, _ in banned_results]

    all_banned = all(status == 429 for status in banned_status_codes)
    assert all_banned, \
        f"Expected all 429s during ban, got {banned_status_codes}"

    print(f"✅ IP ban confirmed: all requests return 429")
    print(f"\n⏰ Waiting {BAN_DURATION} seconds for ban to expire...")

    time.sleep(BAN_DURATION + 10)  # Wait for ban + buffer

    print("Phase 3: Verifying IP ban has expired...")
    recovery_results = make_burst_requests(SERVICE_URL, count=10, delay=1.0)
    recovery_status_codes = [status for status, _ in recovery_results]
    recovery_429_count = sum(1 for status in recovery_status_codes if status == 429)

    assert recovery_429_count == 0, \
        f"Expected no rate limiting after ban expiry, got {recovery_429_count} 429s"

    print(f"✅ IP ban expired successfully, requests allowed")


# ============================================================================
# Rule Ordering Tests
# ============================================================================

def test_rate_limit_evaluated_after_websocket_rules(validate_env):
    """
    Test that per-IP rate limiting (priority 1300) is evaluated AFTER
    WebSocket security rules (priorities 1000-1200).

    Expected: WebSocket upgrade requests hit WebSocket rules, not rate limiter
    """
    # WebSocket upgrade request
    ws_headers = {
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Origin": "https://cwe.crashedmind.com"
    }

    response = make_request(SERVICE_URL, headers=ws_headers)

    # Should get WebSocket-specific response, not rate limit
    # (101 Switching Protocols, or 403 if not properly configured)
    assert response.status_code in (101, 200, 403, 404), \
        f"WebSocket request got unexpected status: {response.status_code}"

    assert response.status_code != 429, \
        "WebSocket requests should not be rate limited (wrong rule order)"

    print(f"✅ WebSocket request handled by WebSocket rules (status: {response.status_code})")


def test_rate_limit_applies_to_regular_http(validate_env):
    """
    Test that per-IP rate limiting applies to regular HTTP requests.

    Expected: Regular HTTP requests are subject to 300 RPM limit
    """
    # Send burst of regular HTTP requests
    results = make_burst_requests(SERVICE_URL, count=350, delay=0.15)

    status_codes = [status for status, _ in results]
    rate_limited_count = sum(1 for status in status_codes if status == 429)

    assert rate_limited_count > 0, \
        "Expected rate limiting for regular HTTP requests"

    print(f"✅ Regular HTTP requests rate limited: {rate_limited_count}/350")


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
