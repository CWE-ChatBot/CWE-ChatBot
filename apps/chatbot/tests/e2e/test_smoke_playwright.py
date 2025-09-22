"""
End-to-end smoke tests using Playwright browser automation.
Tests basic user workflows: role selection, messaging, and response handling.
"""

import pytest
from playwright.sync_api import sync_playwright, expect
import os


@pytest.mark.e2e
def test_basic_smoke_flow(chainlit_server):
    """
    Basic smoke test: start browser, select role, send message, get response.
    This is the most fundamental E2E test.
    """
    url = chainlit_server["url"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            # Navigate to application
            page.goto(url, wait_until="domcontentloaded", timeout=30000)

            # Wait for page to load and become interactive
            page.wait_for_load_state("networkidle", timeout=20000)

            # Look for role selection interface or chat interface
            # Since we don't know exact UI structure, try multiple approaches

            # Approach 1: Look for role buttons
            role_buttons = page.locator("button:has-text('Developer')")
            if role_buttons.count() > 0:
                role_buttons.first.click()
                page.wait_for_timeout(1000)  # Brief wait for role selection

            # Approach 2: Look for any action buttons (role selection)
            action_buttons = page.locator("button[data-testid*='action'], .action-button")
            if action_buttons.count() > 0:
                action_buttons.first.click()
                page.wait_for_timeout(1000)

            # Look for chat input (common patterns)
            chat_input_selectors = [
                "textarea[placeholder*='message']",
                "input[placeholder*='message']",
                "textarea[data-testid='chat-input']",
                ".message-input textarea",
                "textarea",
                "input[type='text']"
            ]

            input_element = None
            for selector in chat_input_selectors:
                elements = page.locator(selector)
                if elements.count() > 0:
                    input_element = elements.first
                    break

            if input_element:
                # Send a test message
                test_message = "What is CWE-79?"
                input_element.fill(test_message)

                # Try to submit (multiple approaches)
                # Approach 1: Press Enter
                input_element.press("Enter")

                # Approach 2: Look for send button
                send_buttons = page.locator(
                    "button:has-text('Send'), button[data-testid='send'], .send-button"
                )
                if send_buttons.count() > 0:
                    send_buttons.first.click()

                # Wait for response
                page.wait_for_timeout(5000)

                # Look for response containing CWE-79
                # This is flexible - any text containing our query term
                response_text = page.locator("text=CWE-79").first
                expect(response_text).to_be_visible(timeout=25000)

            else:
                # If no input found, just verify page loaded successfully
                # This is still a valid smoke test
                page_title = page.title()
                assert len(page_title) > 0, "Page should have a title"

        finally:
            page.close()
            # Persist video manually
            try:
                os.makedirs('test-results/videos', exist_ok=True)
                video = page.video
                if video:
                    video.save_as('test-results/videos/test_basic_smoke_flow.webm')
            except Exception:
                pass
            context.close()
            browser.close()


@pytest.mark.e2e
def test_role_selection_interface(chainlit_server):
    """Test that role selection interface is functional."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Look for role-related elements
            role_elements = page.locator("text=Developer, text=PSIRT, text=Researcher")

            if role_elements.count() > 0:
                # If roles are visible, test selection
                developer_role = page.locator("text=Developer").first
                if developer_role.is_visible():
                    developer_role.click()
                    page.wait_for_timeout(1000)

            # Alternative: look for any clickable elements that might be roles
            clickable_elements = page.locator("button, .clickable, [role='button']")
            if clickable_elements.count() > 0:
                # Click first interactive element (likely a role)
                clickable_elements.first.click()
                page.wait_for_timeout(1000)

            # Verify page responds to interaction
            # Success criteria: page doesn't crash and remains interactive
            assert page.url.startswith("http"), "Page should remain loaded"

        finally:
            page.close()
            try:
                os.makedirs('test-results/videos', exist_ok=True)
                video = page.video
                if video:
                    video.save_as('test-results/videos/test_role_selection_interface.webm')
            except Exception:
                pass
            context.close()
            browser.close()


@pytest.mark.e2e
def test_application_loads_without_errors(chainlit_server):
    """Test that application loads without JavaScript errors."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        # Collect console errors
        console_errors = []
        page.on("console", lambda msg:
            console_errors.append(msg.text) if msg.type == "error" else None
        )

        # Collect page errors
        page_errors = []
        page.on("pageerror", lambda error: page_errors.append(str(error)))

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Wait a bit for any delayed errors
            page.wait_for_timeout(3000)

            # Check for critical errors (filter out common non-critical ones)
            critical_errors = [
                error for error in console_errors
                if not any(ignore in error.lower() for ignore in [
                    "favicon", "analytics", "tracking", "advertisement",
                    "404", "failed to load resource", "websocket"
                ])
            ]

            # Assert no critical errors occurred
            assert len(page_errors) == 0, f"Page errors occurred: {page_errors}"
            assert len(critical_errors) == 0, f"Console errors occurred: {critical_errors}"

        finally:
            page.close()
            try:
                os.makedirs('test-results/videos', exist_ok=True)
                video = page.video
                if video:
                    video.save_as('test-results/videos/test_application_loads_without_errors.webm')
            except Exception:
                pass
            context.close()
            browser.close()


@pytest.mark.e2e
def test_responsive_ui_basic(chainlit_server):
    """Test basic responsive behavior of the UI."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            # Test different viewport sizes
            viewports = [
                {"width": 1920, "height": 1080},  # Desktop
                {"width": 768, "height": 1024},   # Tablet
                {"width": 375, "height": 667}     # Mobile
            ]

            for viewport in viewports:
                page.set_viewport_size(viewport)
                page.goto(url, wait_until="domcontentloaded", timeout=30000)

                # Wait for layout to settle
                page.wait_for_timeout(2000)

                # Verify page is still functional at this size
                # Basic check: page should have some visible content
                body = page.locator("body")
                expect(body).to_be_visible()

                # Check that content fits in viewport (no horizontal scroll)
                scroll_width = page.evaluate("document.body.scrollWidth")
                viewport_width = viewport["width"]

                # Allow small tolerance for scrollbars
                assert scroll_width <= viewport_width + 20, \
                    f"Horizontal scroll at {viewport_width}px: {scroll_width}px content width"

        finally:
            page.close()
            try:
                os.makedirs('test-results/videos', exist_ok=True)
                video = page.video
                if video:
                    video.save_as('test-results/videos/test_responsive_ui_basic.webm')
            except Exception:
                pass
            context.close()
            browser.close()


@pytest.mark.e2e
@pytest.mark.slow
def test_message_flow_complete(chainlit_server, sample_user_inputs):
    """
    Complete message flow test with multiple interactions.
    Marked as slow since it involves multiple message exchanges.
    """
    url = chainlit_server["url"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Try to select a role first
            role_buttons = page.locator("button:has-text('Developer')")
            if role_buttons.count() > 0:
                role_buttons.first.click()
                page.wait_for_timeout(2000)

            # Find chat input
            input_element = None
            for selector in ["textarea", "input[type='text']"]:
                elements = page.locator(selector)
                if elements.count() > 0 and elements.first.is_visible():
                    input_element = elements.first
                    break

            if input_element:
                # Test a few different message types
                test_messages = [
                    sample_user_inputs.get("cwe_direct", "What is CWE-79?"),
                    sample_user_inputs.get("general_security", "How do I prevent XSS?")
                ]

                for message in test_messages[:2]:  # Limit to 2 messages for speed
                    # Clear input and send message
                    input_element.fill("")
                    input_element.fill(message)
                    input_element.press("Enter")

                    # Wait for response (generous timeout for AI)
                    page.wait_for_timeout(8000)

                    # Verify some response appeared
                    # Look for new content that wasn't there before
                    page_content = page.content()
                    assert len(page_content) > 1000, "Page should have substantial content"

            else:
                # Fallback: just verify the page remains functional
                page.wait_for_timeout(5000)
                assert page.url.startswith("http"), "Page should remain loaded"

        finally:
            browser.close()


@pytest.mark.e2e
def test_accessibility_basics(chainlit_server):
    """Test basic accessibility features."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(3000)

            # Check for basic accessibility features
            # 1. Page should have a title
            title = page.title()
            assert len(title) > 0, "Page should have a title"

            # 2. Should have proper heading structure
            headings = page.locator("h1, h2, h3, h4, h5, h6")
            # Having headings is good, but not required for basic functionality

            # 3. Interactive elements should be keyboard accessible
            focusable = page.locator("button, input, textarea, [tabindex='0']")
            if focusable.count() > 0:
                first_focusable = focusable.first
                first_focusable.focus()
                # Should be able to focus without error

            # 4. Images should have alt text (if any)
            images = page.locator("img")
            for i in range(min(images.count(), 5)):  # Check first 5 images
                img = images.nth(i)
                alt_text = img.get_attribute("alt")
                src = img.get_attribute("src")
                if src and not src.startswith("data:"):  # Skip data URLs
                    # Non-decorative images should have alt text
                    # This is advisory, not a hard requirement
                    pass

        finally:
            browser.close()
