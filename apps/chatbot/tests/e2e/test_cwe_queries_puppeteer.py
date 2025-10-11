#!/usr/bin/env python3
"""
End-to-end tests for CWE chatbot using Puppeteer/Playwright.

These tests interact with the actual deployed chatbot through a browser
to verify:
1. Specific CWE ID queries return correct information
2. Semantic queries retrieve relevant CWEs
3. Response contains expected content
4. No OAuth required (anonymous/guest mode or test service account)

Prerequisites:
- Chatbot deployed and accessible at URL
- Anonymous access enabled OR test service account configured
- Playwright installed: poetry add playwright && poetry run playwright install

Environment variables:
- CHATBOT_URL: URL of deployed chatbot (default: http://localhost:8000)
- TEST_EMAIL: Email for test account (if using OAuth)
- TEST_PASSWORD: Password for test account (if using OAuth)
"""
import os
import re

import pytest
from playwright.async_api import Page, expect


CHATBOT_URL = os.getenv("CHATBOT_URL", "http://localhost:8000")
USE_AUTH = os.getenv("USE_AUTH", "false").lower() == "true"
TEST_EMAIL = os.getenv("TEST_EMAIL", "test@example.com")
TEST_PASSWORD = os.getenv("TEST_PASSWORD")


@pytest.mark.e2e
@pytest.mark.skip(
    reason="E2E test - requires chatbot deployed and Playwright installed"
)
class TestCWEQueriesE2E:
    """End-to-end tests for CWE queries using Playwright."""

    @pytest.fixture(scope="class")
    async def browser_context(self, playwright):
        """Create browser context with optional authentication."""
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context()

        # Optional: Handle OAuth login if required
        if USE_AUTH and TEST_EMAIL and TEST_PASSWORD:
            page = await context.new_page()
            await page.goto(CHATBOT_URL)

            # TODO: Implement OAuth login flow
            # Example for Google OAuth:
            # await page.click('button:has-text("Sign in with Google")')
            # await page.fill('input[type="email"]', TEST_EMAIL)
            # await page.click('button:has-text("Next")')
            # await page.fill('input[type="password"]', TEST_PASSWORD)
            # await page.click('button:has-text("Sign in")')
            # await page.wait_for_url(CHATBOT_URL)

            await page.close()

        yield context
        await context.close()
        await browser.close()

    @pytest.fixture
    async def page(self, browser_context):
        """Create a new page for each test."""
        page = await browser_context.new_page()
        await page.goto(CHATBOT_URL)

        # Wait for chat interface to load
        await page.wait_for_selector("#chat-input", state="visible", timeout=10000)

        yield page
        await page.close()

    async def send_message_and_wait_for_response(
        self, page: Page, message: str, timeout: int = 30000
    ) -> str:
        """
        Send a message and wait for the chatbot response.

        Args:
            page: Playwright page object
            message: Message to send
            timeout: Timeout in milliseconds

        Returns:
            Response text from chatbot
        """
        # Get current message count
        messages_before = await page.locator(".message").count()

        # Type message and send
        await page.fill("#chat-input", message)
        await page.click("#send-button")

        # Wait for new message to appear
        await page.wait_for_function(
            f"document.querySelectorAll('.message').length > {messages_before}",
            timeout=timeout,
        )

        # Get the latest response (last message)
        latest_message = page.locator(".message").last
        response_text = await latest_message.text_content()

        return response_text or ""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "cwe_id,expected_keywords",
        [
            (
                "CWE-79",
                ["XSS", "cross-site scripting", "script", "injection"],
            ),  # High priority
            (
                "CWE-89",
                ["SQL injection", "database", "query"],
            ),  # High priority
            ("CWE-78", ["command injection", "OS", "shell"]),  # High priority
            (
                "CWE-82",
                ["IMG", "image", "attribute", "XSS", "script"],
            ),  # The original bug!
            ("CWE-22", ["path traversal", "directory", "file"]),  # High priority
        ],
    )
    async def test_cwe_id_query_returns_correct_info(
        self, page, cwe_id, expected_keywords
    ):
        """Test that querying a specific CWE ID returns correct information."""
        # Send query
        query = f"What is {cwe_id}?"
        response = await self.send_message_and_wait_for_response(page, query)

        # Verify CWE ID mentioned in response
        assert cwe_id in response, f"Response should mention {cwe_id}"

        # Verify at least one expected keyword present (case-insensitive)
        response_lower = response.lower()
        found_keywords = [kw for kw in expected_keywords if kw.lower() in response_lower]
        assert (
            len(found_keywords) > 0
        ), f"Response should contain at least one of {expected_keywords}, got: {response[:200]}"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "query,expected_cwe",
        [
            ("How do I prevent SQL injection?", "CWE-89"),
            ("What is cross-site scripting?", "CWE-79"),
            ("Explain path traversal vulnerabilities", "CWE-22"),
            ("Tell me about command injection", "CWE-78"),
        ],
    )
    async def test_semantic_query_retrieves_relevant_cwe(
        self, page, query, expected_cwe
    ):
        """Test that semantic queries retrieve relevant CWEs."""
        response = await self.send_message_and_wait_for_response(page, query)

        # Verify expected CWE mentioned
        assert (
            expected_cwe in response
        ), f"Response should mention {expected_cwe} for query '{query}'"

    @pytest.mark.asyncio
    async def test_invalid_cwe_id_returns_helpful_message(self, page):
        """Test that invalid CWE IDs return helpful error messages."""
        query = "What is CWE-99999?"
        response = await self.send_message_and_wait_for_response(page, query)

        # Should indicate CWE not found or doesn't exist
        response_lower = response.lower()
        helpful_indicators = [
            "not found",
            "does not exist",
            "invalid",
            "no information",
            "no documentation",
        ]

        found = any(indicator in response_lower for indicator in helpful_indicators)
        assert (
            found
        ), f"Invalid CWE should return helpful message, got: {response[:200]}"

    @pytest.mark.asyncio
    async def test_multiple_cwe_comparison_query(self, page):
        """Test querying about multiple CWEs in one message."""
        query = "Compare CWE-79 and CWE-89"
        response = await self.send_message_and_wait_for_response(page, query)

        # Should mention both CWEs
        assert "CWE-79" in response, "Should mention CWE-79"
        assert "CWE-89" in response, "Should mention CWE-89"

        # Should have some comparison content
        comparison_indicators = [
            "both",
            "difference",
            "similar",
            "whereas",
            "while",
            "contrast",
            "compare",
        ]
        response_lower = response.lower()
        found = any(indicator in response_lower for indicator in comparison_indicators)
        assert found, f"Should include comparison content, got: {response[:200]}"

    @pytest.mark.asyncio
    async def test_response_formatting_includes_structure(self, page):
        """Test that responses are well-formatted with structure."""
        query = "What is CWE-79?"
        response = await self.send_message_and_wait_for_response(page, query)

        # Verify response has reasonable length (not too short)
        assert (
            len(response) > 50
        ), "Response should be more than just a few words"

        # Optionally verify markdown formatting if chatbot uses it
        # (sections, bullet points, code blocks, etc.)

    @pytest.mark.asyncio
    async def test_chatbot_handles_follow_up_questions(self, page):
        """Test that chatbot can handle follow-up questions."""
        # Initial query
        response1 = await self.send_message_and_wait_for_response(
            page, "What is CWE-79?"
        )
        assert "CWE-79" in response1

        # Follow-up question
        response2 = await self.send_message_and_wait_for_response(
            page, "How do I prevent it?"
        )

        # Follow-up should reference XSS or mitigation
        response2_lower = response2.lower()
        follow_up_keywords = [
            "prevent",
            "mitigate",
            "sanitize",
            "encode",
            "escape",
            "validate",
        ]
        found = any(kw in response2_lower for kw in follow_up_keywords)
        assert found, f"Follow-up should discuss prevention, got: {response2[:200]}"

    @pytest.mark.asyncio
    async def test_cwe_82_force_injection_fix_works_e2e(self, page):
        """
        End-to-end verification that CWE-82 force-injection fix works.

        This is the specific test case for ISSUE-CWE-82-NOT-FOUND.md.
        """
        query = "what is cwe-82?"
        response = await self.send_message_and_wait_for_response(page, query)

        # Verify CWE-82 mentioned
        assert "CWE-82" in response or "82" in response, "Should mention CWE-82"

        # Verify correct CWE (IMG tags, XSS, attributes)
        response_lower = response.lower()
        correct_keywords = ["img", "image", "attribute", "tag", "xss", "script"]
        found_keywords = [kw for kw in correct_keywords if kw in response_lower]

        assert (
            len(found_keywords) >= 2
        ), f"Should describe CWE-82 (IMG tag XSS), found keywords: {found_keywords}, response: {response[:200]}"

        # Verify NOT returning wrong CWEs (like CWE-1264 from the bug)
        wrong_cwes = ["CWE-1264", "CWE-191", "CWE-572"]
        for wrong_cwe in wrong_cwes:
            assert (
                wrong_cwe not in response
            ), f"Should NOT mention wrong CWE {wrong_cwe}"


@pytest.mark.e2e
@pytest.mark.skip(reason="E2E test - manual test suite for comprehensive coverage")
class TestCWEQueriesManualVerification:
    """
    Manual test suite for comprehensive CWE query testing.

    Run this suite manually when doing QA or release testing.
    """

    # List of test cases for manual verification
    MANUAL_TEST_CASES = [
        {
            "query": "What is CWE-79?",
            "expected_cwe": "CWE-79",
            "expected_keywords": ["XSS", "cross-site scripting"],
            "description": "High-priority CWE (OWASP Top 10)",
        },
        {
            "query": "what is cwe-82?",
            "expected_cwe": "CWE-82",
            "expected_keywords": ["IMG", "image", "attribute"],
            "description": "Original bug - force-injection fix verification",
        },
        {
            "query": "How do I prevent SQL injection?",
            "expected_cwe": "CWE-89",
            "expected_keywords": ["parameterized", "prepared statement"],
            "description": "Semantic query for prevention guidance",
        },
        {
            "query": "Compare CWE-79 and CWE-89",
            "expected_cwe": "CWE-79, CWE-89",
            "expected_keywords": ["both", "difference", "XSS", "SQL"],
            "description": "Multi-CWE comparison query",
        },
        {
            "query": "What is CWE-99999?",
            "expected_cwe": None,
            "expected_keywords": ["not found", "does not exist"],
            "description": "Invalid CWE ID - error handling",
        },
    ]

    def print_manual_test_instructions(self):
        """Print instructions for manual testing."""
        print("\n" + "=" * 70)
        print("MANUAL CWE QUERY TEST SUITE")
        print("=" * 70)
        print(f"\n1. Open chatbot at: {CHATBOT_URL}")
        print("2. For each test case below, verify the response:\n")

        for i, test_case in enumerate(self.MANUAL_TEST_CASES, 1):
            print(f"\n--- Test Case {i}: {test_case['description']} ---")
            print(f"Query: '{test_case['query']}'")
            print(f"Expected CWE: {test_case['expected_cwe']}")
            print(f"Expected Keywords: {test_case['expected_keywords']}")
            print()


if __name__ == "__main__":
    # Print manual test instructions
    manual_tests = TestCWEQueriesManualVerification()
    manual_tests.print_manual_test_instructions()
