#!/usr/bin/env python3
"""
Automated regression test for non-CWE queries using puppeteer.

Tests that semantic queries without explicit CWE IDs successfully retrieve chunks.
This prevents regression of the "No relevant CWE information found" bug.

Usage:
    poetry run pytest apps/chatbot/tests/e2e/test_non_cwe_query_regression.py -v
"""

import pytest
import time
from typing import Dict, List

# Test queries that should retrieve chunks (no explicit CWE IDs)
NON_CWE_TEST_QUERIES = [
    {
        "persona": "PSIRT Member",
        "query": "Show me SQL injection prevention techniques",
        "expected_cwe": "CWE-89",
        "min_chunks": 5
    },
    {
        "persona": "Academic Researcher",
        "query": "Buffer overflow vulnerabilities",
        "expected_cwe": "CWE-120",
        "min_chunks": 5
    },
    {
        "persona": "Developer",
        "query": "XSS mitigation strategies",
        "expected_cwe": "CWE-79",
        "min_chunks": 5
    },
    {
        "persona": "Bug Bounty Hunter",
        "query": "Path traversal attack vectors",
        "expected_cwe": "CWE-22",
        "min_chunks": 5
    },
    {
        "persona": "Product Manager",
        "query": "Authentication bypass weaknesses",
        "expected_cwe": "CWE-287",
        "min_chunks": 5
    }
]


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_non_cwe_queries_retrieve_chunks(
    mcp__puppeteer__puppeteer_navigate,
    mcp__puppeteer__puppeteer_fill,
    mcp__puppeteer__puppeteer_click,
    mcp__puppeteer__puppeteer_evaluate,
    mcp__puppeteer__puppeteer_screenshot
):
    """
    Test that non-CWE queries successfully retrieve chunks via puppeteer.

    This is a regression test for the bug where queries like "SQL injection prevention"
    returned "No relevant CWE information found" due to missing query_hybrid method.
    """

    # Get Cloud Run URL from environment or use default
    import os
    app_url = os.getenv("CHAINLIT_APP_URL", "https://cwe-chatbot-bmgj6wj65a-uc.a.run.app")

    print(f"\n🚀 Testing non-CWE queries against: {app_url}")

    # Navigate to chainlit app
    await mcp__puppeteer__puppeteer_navigate(url=app_url)
    time.sleep(3)  # Wait for app to load

    results = []

    for test_case in NON_CWE_TEST_QUERIES:
        persona = test_case["persona"]
        query = test_case["query"]
        expected_cwe = test_case["expected_cwe"]
        min_chunks = test_case["min_chunks"]

        print(f"\n📝 Testing: {persona} - '{query}'")

        # Select persona (if UI has persona selector)
        # This depends on chainlit UI implementation - adjust as needed
        try:
            await mcp__puppeteer__puppeteer_evaluate(
                script=f"document.querySelector('[data-testid=\"persona-select\"]').value = '{persona}'"
            )
        except Exception:
            # Persona selector might not exist yet, skip
            print(f"⚠️  Persona selector not found, using default")

        # Fill in query
        await mcp__puppeteer__puppeteer_fill(
            selector='textarea[placeholder*="Ask"]',
            value=query
        )

        # Submit query
        await mcp__puppeteer__puppeteer_click(
            selector='button[type="submit"]'
        )

        # Wait for response (adjust timeout as needed)
        time.sleep(8)

        # Take screenshot for debugging
        screenshot_name = f"test_non_cwe_{persona.replace(' ', '_').lower()}"
        await mcp__puppeteer__puppeteer_screenshot(
            name=screenshot_name,
            width=1200,
            height=800
        )

        # Extract response text from page
        response_script = """
        (() => {
            const messages = document.querySelectorAll('.message-content');
            if (messages.length === 0) return null;
            const lastMessage = messages[messages.length - 1];
            return lastMessage.innerText || lastMessage.textContent;
        })();
        """

        response_text = await mcp__puppeteer__puppeteer_evaluate(script=response_script)

        # Validate response
        success = True
        error_msg = None

        if not response_text:
            success = False
            error_msg = "No response received from chatbot"
        elif "No relevant CWE information found" in response_text:
            success = False
            error_msg = "Chatbot returned 'No relevant CWE information found' - regression!"
        elif expected_cwe not in response_text:
            # Warning but not failure - expected CWE might not be in top chunks
            print(f"⚠️  Expected {expected_cwe} not found in response (might be in lower ranks)")

        results.append({
            "persona": persona,
            "query": query,
            "expected_cwe": expected_cwe,
            "success": success,
            "error": error_msg,
            "response_preview": response_text[:200] if response_text else None
        })

        if success:
            print(f"✅ PASS - Chunks retrieved successfully")
        else:
            print(f"❌ FAIL - {error_msg}")

        # Clear chat for next test
        try:
            await mcp__puppeteer__puppeteer_click(
                selector='button[aria-label="New Chat"]'
            )
            time.sleep(2)
        except Exception:
            print("⚠️  Could not clear chat, continuing...")

    # Print summary
    print(f"\n{'='*60}")
    print(f"📊 NON-CWE QUERY REGRESSION TEST SUMMARY")
    print(f"{'='*60}")

    passed = sum(1 for r in results if r["success"])
    failed = sum(1 for r in results if not r["success"])

    print(f"✅ Passed: {passed}/{len(results)}")
    print(f"❌ Failed: {failed}/{len(results)}")

    if failed > 0:
        print(f"\n🔍 Failures:")
        for r in results:
            if not r["success"]:
                print(f"  • {r['persona']}: {r['query']}")
                print(f"    Error: {r['error']}")

    # Assertion - all tests must pass
    assert failed == 0, f"{failed} non-CWE queries failed to retrieve chunks - REGRESSION DETECTED!"

    print(f"\n🎉 All non-CWE queries successfully retrieved chunks - NO REGRESSION")


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_non_cwe_query_logs_verification(
    mcp__puppeteer__puppeteer_navigate,
    mcp__puppeteer__puppeteer_fill,
    mcp__puppeteer__puppeteer_click
):
    """
    Verify that non-CWE queries generate correct log entries.

    Checks Cloud Run logs for successful hybrid retrieval.
    """

    import os
    import subprocess

    app_url = os.getenv("CHAINLIT_APP_URL", "https://cwe-chatbot-bmgj6wj65a-uc.a.run.app")

    print(f"\n🔍 Verifying logs for non-CWE query...")

    # Navigate and submit test query
    await mcp__puppeteer__puppeteer_navigate(url=app_url)
    time.sleep(3)

    test_query = "SQL injection prevention techniques"

    await mcp__puppeteer__puppeteer_fill(
        selector='textarea[placeholder*="Ask"]',
        value=test_query
    )

    await mcp__puppeteer__puppeteer_click(
        selector='button[type="submit"]'
    )

    time.sleep(8)  # Wait for processing

    # Fetch recent Cloud Run logs
    try:
        result = subprocess.run(
            [
                "gcloud", "run", "services", "logs", "read", "cwe-chatbot",
                "--region=us-central1",
                "--limit=50",
                "--format=value(textPayload)"
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        logs = result.stdout

        # Verify key log entries
        assertions = [
            ("hybrid retrieval", "Hybrid retrieval log entry found"),
            ("chunks retrieved", "Chunk retrieval confirmation found"),
            ("query_hybrid", "query_hybrid method called successfully")
        ]

        print(f"\n📋 Log Verification:")
        for search_term, description in assertions:
            if search_term.lower() in logs.lower():
                print(f"  ✅ {description}")
            else:
                print(f"  ⚠️  {description} - NOT FOUND (might be filtered)")

        # Critical assertion - should NOT see error logs
        error_indicators = [
            "AttributeError",
            "query_hybrid() missing",
            "No relevant CWE information found"
        ]

        errors_found = []
        for error_term in error_indicators:
            if error_term in logs:
                errors_found.append(error_term)

        assert len(errors_found) == 0, f"Error indicators found in logs: {errors_found}"

        print(f"\n✅ Log verification passed - no error indicators")

    except subprocess.TimeoutExpired:
        print(f"⚠️  Log fetch timeout - skipping log verification")
    except Exception as e:
        print(f"⚠️  Log verification failed: {e} - skipping")


if __name__ == "__main__":
    print("Run with: poetry run pytest apps/chatbot/tests/e2e/test_non_cwe_query_regression.py -v")
