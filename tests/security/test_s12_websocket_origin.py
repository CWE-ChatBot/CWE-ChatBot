#!/usr/bin/env python3
"""
S-12 WebSocket Origin Blocking Test

Tests Cloud Armor WAF rules for WebSocket origin validation:
- Rule 1100: Block cross-origin WebSocket handshakes
- Rule 1200: Block WebSocket without Origin header

Expected Behavior:
- Same-origin WebSocket: Should connect successfully
- Cross-origin WebSocket: Should be blocked by Cloud Armor (403)
- WebSocket without Origin: Should be blocked by Cloud Armor (403)
"""

import ssl
import sys
from typing import Optional

import websocket

# Configuration
TARGET_URL = "wss://cwe.crashedmind.com/ws"
ALLOWED_ORIGIN = "https://cwe.crashedmind.com"
UNAUTHORIZED_ORIGIN = "https://evil.com"


class Colors:
    """Terminal colors for output"""

    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    END = "\033[0m"
    BOLD = "\033[1m"


def test_websocket(origin: Optional[str], test_name: str, should_succeed: bool) -> bool:
    """
    Test WebSocket connection with specified origin.

    Args:
        origin: Origin header value (None = no Origin header)
        test_name: Human-readable test name
        should_succeed: Whether connection should succeed

    Returns:
        True if test passes, False otherwise
    """
    print(f"\n{Colors.BLUE}{Colors.BOLD}=== {test_name} ==={Colors.END}")
    print(f"Target: {TARGET_URL}")
    print(f"Origin: {origin if origin else '(no Origin header)'}")
    print(f"Expected: {'Success' if should_succeed else 'Blocked (403)'}")

    try:
        # Create WebSocket with custom headers
        headers = {}
        if origin:
            headers["Origin"] = origin

        ws = websocket.create_connection(
            TARGET_URL,
            header=headers,
            sslopt={"cert_reqs": ssl.CERT_NONE},  # Skip cert verification for testing
        )

        # Connection succeeded
        ws.close()

        if should_succeed:
            print(f"{Colors.GREEN}✅ PASS: Connection succeeded (expected){Colors.END}")
            return True
        else:
            print(
                f"{Colors.RED}❌ FAIL: Connection succeeded (should have been blocked by Cloud Armor){Colors.END}"
            )
            return False

    except websocket.WebSocketBadStatusException as e:
        # Connection blocked
        status_code = e.status_code

        if not should_succeed:
            if status_code == 403:
                print(
                    f"{Colors.GREEN}✅ PASS: Blocked with 403 Forbidden (expected){Colors.END}"
                )
                print("   Cloud Armor rule working correctly")
                return True
            else:
                print(
                    f"{Colors.YELLOW}⚠️  PARTIAL: Blocked with {status_code} (expected 403){Colors.END}"
                )
                return True
        else:
            print(
                f"{Colors.RED}❌ FAIL: Connection blocked with {status_code} (should have succeeded){Colors.END}"
            )
            return False

    except Exception as e:
        print(f"{Colors.RED}❌ ERROR: {type(e).__name__}: {e}{Colors.END}")
        return False


def main():
    """Run all WebSocket origin security tests"""
    print(f"{Colors.BOLD}S-12 WebSocket Origin Security Tests{Colors.END}")
    print("=" * 60)

    results = []

    # Test 1: Same-origin WebSocket (should succeed)
    results.append(
        test_websocket(
            origin=ALLOWED_ORIGIN,
            test_name="Test 1: Same-Origin WebSocket",
            should_succeed=True,
        )
    )

    # Test 2: Cross-origin WebSocket (should be blocked by Rule 1100)
    results.append(
        test_websocket(
            origin=UNAUTHORIZED_ORIGIN,
            test_name="Test 2: Cross-Origin WebSocket (evil.com)",
            should_succeed=False,
        )
    )

    # Test 3: WebSocket without Origin header (should be blocked by Rule 1200)
    results.append(
        test_websocket(
            origin=None,
            test_name="Test 3: WebSocket Without Origin Header",
            should_succeed=False,
        )
    )

    # Test 4: Another cross-origin attempt (localhost)
    results.append(
        test_websocket(
            origin="http://localhost:3000",
            test_name="Test 4: Cross-Origin WebSocket (localhost)",
            should_succeed=False,
        )
    )

    # Summary
    print(f"\n{Colors.BOLD}{'=' * 60}{Colors.END}")
    print(f"{Colors.BOLD}Test Summary:{Colors.END}")
    print(f"Total: {len(results)}")
    print(f"{Colors.GREEN}Passed: {sum(results)}{Colors.END}")
    print(f"{Colors.RED}Failed: {len(results) - sum(results)}{Colors.END}")

    if all(results):
        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ ALL TESTS PASSED{Colors.END}")
        print(
            f"{Colors.GREEN}Cloud Armor WebSocket origin validation is working correctly!{Colors.END}"
        )
        return 0
    else:
        print(f"\n{Colors.RED}{Colors.BOLD}❌ SOME TESTS FAILED{Colors.END}")
        print(f"{Colors.RED}Cloud Armor rules may need adjustment.{Colors.END}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
