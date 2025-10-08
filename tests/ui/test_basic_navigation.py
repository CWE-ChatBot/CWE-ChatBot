"""
Basic navigation and application loading tests.
Tests fundamental UI functionality and application startup.
"""

import asyncio

import pytest
from fixtures.ui_scenarios import ScenarioExecutor, get_scenario
from playwright.async_api import Page, expect
from utils.chainlit_helpers import setup_test_environment
from utils.screenshot_helpers import take_test_screenshot


class TestBasicNavigation:
    """Test basic navigation and application loading functionality."""

    @pytest.mark.asyncio
    async def test_application_loads_successfully(
        self, page: Page, chainlit_base_url: str
    ):
        """Test that the Chainlit application loads without errors."""
        # Navigate to the application
        await page.goto(chainlit_base_url)

        # Wait for the page to load
        await page.wait_for_load_state("networkidle")

        # Check that we get a successful response
        expect(page).to_have_url(chainlit_base_url)

        # Verify the page title is set (will update when we know the actual title)
        title = await page.title()
        assert len(title) > 0, "Page title should be set"

        # Take a screenshot for visual verification
        await take_test_screenshot(page, "application_loaded")

    @pytest.mark.asyncio
    async def test_chainlit_interface_elements_present(
        self, page: Page, chainlit_base_url: str
    ):
        """Test that basic Chainlit interface elements are present."""
        helper = await setup_test_environment(page, chainlit_base_url)

        # Look for common Chainlit elements
        # Note: These selectors may need adjustment based on actual Chainlit implementation
        possible_selectors = [
            "[data-testid='chainlit-app']",
            "[data-testid='message-input']",
            "input[placeholder*='message']",
            "input[placeholder*='question']",
            "textarea",
            ".chainlit-app",
            "#root",
        ]

        # At least one of these should be present
        element_found = False
        for selector in possible_selectors:
            try:
                element = page.locator(selector).first
                if await element.is_visible():
                    element_found = True
                    break
            except:
                continue

        assert (
            element_found
        ), f"No Chainlit interface elements found. Tried selectors: {possible_selectors}"

        # Take screenshot of the interface
        await take_test_screenshot(page, "chainlit_interface_loaded")

    @pytest.mark.asyncio
    async def test_application_responsive_design(
        self, page: Page, chainlit_base_url: str
    ):
        """Test that the application is responsive across different viewport sizes."""
        # Test different viewport sizes
        viewports = [
            {"width": 1920, "height": 1080},  # Desktop
            {"width": 1280, "height": 720},  # Laptop
            {"width": 768, "height": 1024},  # Tablet
            {"width": 375, "height": 667},  # Mobile
        ]

        for viewport in viewports:
            # Set viewport size
            await page.set_viewport_size(viewport["width"], viewport["height"])

            # Navigate to application
            await page.goto(chainlit_base_url)
            await page.wait_for_load_state("networkidle")

            # Verify the page still loads and is usable
            # Basic check that body is visible
            body = page.locator("body")
            await expect(body).to_be_visible()

            # Take screenshot for visual verification
            viewport_name = f"{viewport['width']}x{viewport['height']}"
            await take_test_screenshot(page, f"responsive_design_{viewport_name}")

    @pytest.mark.asyncio
    async def test_page_load_performance(self, page: Page, chainlit_base_url: str):
        """Test that the application loads within acceptable time limits."""
        import time

        # Measure page load time
        start_time = time.time()

        await page.goto(chainlit_base_url)
        await page.wait_for_load_state("networkidle")

        load_time = time.time() - start_time

        # Assert load time is reasonable (under 10 seconds for development)
        assert (
            load_time < 10.0
        ), f"Page load time {load_time:.2f}s exceeds 10 second limit"

        print(f"Page loaded in {load_time:.2f} seconds")

    @pytest.mark.asyncio
    async def test_no_console_errors_on_load(self, page: Page, chainlit_base_url: str):
        """Test that no critical JavaScript errors occur during page load."""
        errors = []

        # Listen for console errors
        def handle_console_msg(msg):
            if msg.type == "error":
                errors.append(msg.text)

        page.on("console", handle_console_msg)

        # Navigate and load the application
        await page.goto(chainlit_base_url)
        await page.wait_for_load_state("networkidle")

        # Wait a bit more for any async JavaScript to complete
        await asyncio.sleep(2)

        # Filter out acceptable errors (adjust as needed based on known issues)
        critical_errors = [
            error
            for error in errors
            if not any(
                acceptable in error.lower()
                for acceptable in [
                    "favicon",
                    "404",
                    "websocket",
                    "development",
                    "warning",
                ]
            )
        ]

        assert (
            len(critical_errors) == 0
        ), f"Critical JavaScript errors found: {critical_errors}"

    @pytest.mark.asyncio
    async def test_using_scenario_executor(self, page: Page, chainlit_base_url: str):
        """Test using the scenario executor for basic navigation."""
        # Get the basic navigation scenario
        scenario = get_scenario("basic_navigation")
        assert scenario is not None, "Basic navigation scenario should be available"

        # Execute the scenario
        executor = ScenarioExecutor(page)
        result = await executor.execute_scenario(
            scenario, {"base_url": chainlit_base_url}
        )

        # Verify scenario executed successfully
        assert result["success"], f"Navigation scenario failed: {result['errors']}"
        assert (
            result["actions_completed"] > 0
        ), "At least one action should have completed"

        print(f"Scenario completed in {result['execution_time']:.2f} seconds")


@pytest.mark.asyncio
class TestErrorHandling:
    """Test error handling and edge cases."""

    async def test_invalid_url_handling(self, page: Page):
        """Test behavior when accessing invalid URLs."""
        # Try to access a non-existent path
        invalid_url = "http://localhost:8000/nonexistent-page"

        try:
            response = await page.goto(invalid_url)
            # Should either get 404 or be redirected to main page
            assert response.status in [
                404,
                200,
            ], f"Unexpected status code: {response.status}"
        except Exception as e:
            # Connection refused is acceptable if server isn't running
            assert "ECONNREFUSED" in str(e) or "net::ERR_CONNECTION_REFUSED" in str(e)

    async def test_application_offline_behavior(
        self, page: Page, chainlit_base_url: str
    ):
        """Test application behavior when network is simulated as offline."""
        # Set offline mode
        await page.context.set_offline(True)

        try:
            await page.goto(chainlit_base_url, timeout=5000)
        except Exception as e:
            # This is expected - the page should not load when offline
            assert any(
                keyword in str(e).lower()
                for keyword in ["timeout", "offline", "connection"]
            ), f"Unexpected error when offline: {e}"

        # Restore online mode
        await page.context.set_offline(False)


# Utility test for debugging purposes
@pytest.mark.skip(reason="Utility test for manual debugging")
@pytest.mark.asyncio
async def test_debug_page_content(page: Page, chainlit_base_url: str):
    """Debug utility to examine page content - skip by default."""
    await page.goto(chainlit_base_url)
    await page.wait_for_load_state("networkidle")

    # Print page content for debugging
    content = await page.content()
    print("Page HTML content:")
    print(content[:1000])  # First 1000 characters

    # Print page title
    title = await page.title()
    print(f"Page title: {title}")

    # Print console messages
    console_messages = []
    page.on("console", lambda msg: console_messages.append(f"{msg.type}: {msg.text}"))

    await asyncio.sleep(2)  # Wait for console messages

    if console_messages:
        print("Console messages:")
        for msg in console_messages[-10:]:  # Last 10 messages
            print(f"  {msg}")

    # Take debugging screenshot
    await take_test_screenshot(page, "debug_page_content")
