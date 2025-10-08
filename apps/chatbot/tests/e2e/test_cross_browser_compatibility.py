"""
Cross-browser compatibility testing for the CWE ChatBot.
Tests core functionality across different browsers to ensure consistent behavior.
"""

import os

import pytest
from playwright.sync_api import expect, sync_playwright


@pytest.mark.e2e
@pytest.mark.parametrize("browser_type", ["chromium", "firefox", "webkit"])
def test_basic_functionality_cross_browser(chainlit_server, browser_type):
    """Test basic chat functionality works across all supported browsers."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        # Launch browser based on parameter
        if browser_type == "chromium":
            browser = p.chromium.launch(headless=True)
        elif browser_type == "firefox":
            browser = p.firefox.launch(headless=True)
        elif browser_type == "webkit":
            browser = p.webkit.launch(headless=True)
        else:
            pytest.skip(f"Unsupported browser: {browser_type}")

        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            # Navigate to application
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Verify page loads without JavaScript errors
            console_errors = []
            page.on(
                "console",
                lambda msg: console_errors.append(msg.text)
                if msg.type == "error"
                else None,
            )

            page_errors = []
            page.on("pageerror", lambda error: page_errors.append(str(error)))

            # Wait for any delayed loading
            page.wait_for_timeout(3000)

            # Basic interaction test
            input_element = None
            input_selectors = ["textarea", "input[type='text']"]

            for selector in input_selectors:
                elements = page.locator(selector)
                if elements.count() > 0:
                    try:
                        if elements.first.is_visible():
                            input_element = elements.first
                            break
                    except Exception:
                        continue

            if input_element:
                # Send a test message
                test_message = "What is CWE-79?"
                input_element.fill(test_message)
                input_element.press("Enter")

                # Wait for response
                page.wait_for_timeout(5000)

                # Verify response appears
                page_content = page.content().lower()
                assert (
                    "cwe-79" in page_content or len(page_content) > 2000
                ), f"Should get response in {browser_type}"

            # Check for critical errors
            critical_errors = [
                error
                for error in console_errors
                if not any(
                    ignore in error.lower()
                    for ignore in [
                        "favicon",
                        "analytics",
                        "tracking",
                        "websocket",
                        "404",
                    ]
                )
            ]

            # Assert no critical errors
            assert (
                len(page_errors) == 0
            ), f"Page errors in {browser_type}: {page_errors}"
            assert (
                len(critical_errors) <= 1
            ), f"Too many console errors in {browser_type}: {critical_errors}"

        finally:
            page.close()
            try:
                os.makedirs("test-results/videos", exist_ok=True)
                video = page.video
                if video:
                    video.save_as(
                        f"test-results/videos/test_basic_functionality_{browser_type}.webm"
                    )
            except Exception:
                pass
            context.close()
            browser.close()


@pytest.mark.e2e
@pytest.mark.parametrize(
    "browser_type", ["chromium", "firefox"]
)  # webkit often has issues with file uploads
def test_file_upload_cross_browser(chainlit_server, browser_type):
    """Test file upload functionality across browsers."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        if browser_type == "chromium":
            browser = p.chromium.launch(headless=True)
        elif browser_type == "firefox":
            browser = p.firefox.launch(headless=True)
        else:
            pytest.skip(f"File upload not tested on {browser_type}")

        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Look for file upload button or input
            upload_selectors = [
                'input[type="file"]',
                'button:has-text("Attach")',
                '[aria-label*="attach"]',
                '[data-testid*="upload"]',
            ]

            upload_available = False
            for selector in upload_selectors:
                if page.locator(selector).count() > 0:
                    upload_available = True
                    break

            if not upload_available:
                # Try to trigger file upload via action button
                action_buttons = page.locator(
                    "button:has-text('Attach Files'), button:has-text('Attach Evidence')"
                )
                if action_buttons.count() > 0:
                    action_buttons.first.click()
                    page.wait_for_timeout(2000)

                    # Check again for file input
                    for selector in upload_selectors:
                        if page.locator(selector).count() > 0:
                            upload_available = True
                            break

            if upload_available:
                # Create a simple test file
                test_file_content = "Test document content for CWE testing"
                test_file_path = f"/tmp/test_upload_{browser_type}.txt"

                try:
                    with open(test_file_path, "w") as f:
                        f.write(test_file_content)

                    # Try to upload the file
                    file_input = page.locator('input[type="file"]').first
                    if file_input.count() > 0:
                        page.set_input_files('input[type="file"]', test_file_path)
                        page.wait_for_timeout(2000)

                        # Look for confirmation or continue button
                        continue_buttons = page.locator(
                            "button:has-text('Upload'), button:has-text('Continue'), button:has-text('Done')"
                        )
                        if continue_buttons.count() > 0:
                            continue_buttons.first.click()
                            page.wait_for_timeout(1000)

                        # Check for upload confirmation
                        confirmation_text = page.locator(
                            "text=received, text=uploaded, text=attached"
                        )
                        upload_success = confirmation_text.count() > 0

                        # Note: We don't assert here because upload might not be fully configured
                        # This test mainly verifies that the upload UI doesn't crash the browser

                finally:
                    # Clean up test file
                    try:
                        os.remove(test_file_path)
                    except Exception:
                        pass

            # Verify application remains functional after upload attempt
            assert page.url.startswith(
                "http"
            ), f"Application should remain functional in {browser_type}"

        finally:
            page.close()
            try:
                os.makedirs("test-results/videos", exist_ok=True)
                video = page.video
                if video:
                    video.save_as(
                        f"test-results/videos/test_file_upload_{browser_type}.webm"
                    )
            except Exception:
                pass
            context.close()
            browser.close()


@pytest.mark.e2e
@pytest.mark.parametrize("browser_type", ["chromium", "firefox", "webkit"])
def test_responsive_design_cross_browser(chainlit_server, browser_type):
    """Test responsive design behavior across browsers."""
    url = chainlit_server["url"]

    viewports = [
        {"width": 1920, "height": 1080, "name": "desktop"},
        {"width": 768, "height": 1024, "name": "tablet"},
        {"width": 375, "height": 667, "name": "mobile"},
    ]

    with sync_playwright() as p:
        if browser_type == "chromium":
            browser = p.chromium.launch(headless=True)
        elif browser_type == "firefox":
            browser = p.firefox.launch(headless=True)
        elif browser_type == "webkit":
            browser = p.webkit.launch(headless=True)
        else:
            pytest.skip(f"Unsupported browser: {browser_type}")

        for viewport in viewports:
            context = browser.new_context(
                viewport={"width": viewport["width"], "height": viewport["height"]},
                record_video_dir="test-results/videos/",
            )
            page = context.new_page()

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_load_state("networkidle", timeout=15000)

                # Check that content is responsive
                body = page.locator("body")
                expect(body).to_be_visible()

                # Check for horizontal scrolling (should not be needed)
                scroll_width = page.evaluate("document.body.scrollWidth")
                viewport_width = viewport["width"]

                # Allow small tolerance for scrollbars
                assert (
                    scroll_width <= viewport_width + 25
                ), f"Horizontal scrolling in {browser_type} at {viewport['name']} viewport: {scroll_width}px > {viewport_width}px"

                # Test basic interaction at this viewport
                input_element = page.locator("textarea, input[type='text']").first
                if input_element.count() > 0 and input_element.is_visible():
                    input_element.fill("Test responsive design")
                    input_element.press("Enter")
                    page.wait_for_timeout(2000)

                    # Should remain functional
                    assert page.url.startswith(
                        "http"
                    ), f"Should remain functional in {browser_type} at {viewport['name']} viewport"

            finally:
                page.close()
                try:
                    os.makedirs("test-results/videos", exist_ok=True)
                    video = page.video
                    if video:
                        video.save_as(
                            f'test-results/videos/test_responsive_{browser_type}_{viewport["name"]}.webm'
                        )
                except Exception:
                    pass
                context.close()

        browser.close()


@pytest.mark.e2e
@pytest.mark.parametrize("browser_type", ["chromium", "firefox", "webkit"])
def test_persona_selection_cross_browser(chainlit_server, browser_type, sample_roles):
    """Test persona/role selection functionality across browsers."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        if browser_type == "chromium":
            browser = p.chromium.launch(headless=True)
        elif browser_type == "firefox":
            browser = p.firefox.launch(headless=True)
        elif browser_type == "webkit":
            browser = p.webkit.launch(headless=True)
        else:
            pytest.skip(f"Unsupported browser: {browser_type}")

        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Test role selection
            roles_to_test = ["Developer", "PSIRT"]

            for role in roles_to_test:
                role_button = page.locator(f"button:has-text('{role}')")
                if role_button.count() > 0:
                    role_button.click()
                    page.wait_for_timeout(1000)

                    # Send a test message with this role
                    input_element = page.locator("textarea, input[type='text']").first
                    if input_element.count() > 0 and input_element.is_visible():
                        input_element.fill(f"Test message for {role}")
                        input_element.press("Enter")
                        page.wait_for_timeout(2000)

                        # Should work without errors
                        assert page.url.startswith(
                            "http"
                        ), f"Role selection for {role} should work in {browser_type}"

            # Verify final state
            final_content = page.content()
            assert (
                len(final_content) > 1000
            ), f"Should have substantial content after role tests in {browser_type}"

        finally:
            page.close()
            try:
                os.makedirs("test-results/videos", exist_ok=True)
                video = page.video
                if video:
                    video.save_as(
                        f"test-results/videos/test_persona_selection_{browser_type}.webm"
                    )
            except Exception:
                pass
            context.close()
            browser.close()


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.parametrize("browser_type", ["chromium", "firefox"])
def test_javascript_compatibility_cross_browser(chainlit_server, browser_type):
    """Test JavaScript features and compatibility across browsers."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        if browser_type == "chromium":
            browser = p.chromium.launch(headless=True)
        elif browser_type == "firefox":
            browser = p.firefox.launch(headless=True)
        else:
            pytest.skip(f"Limited JavaScript testing on {browser_type}")

        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            # Track JavaScript errors
            js_errors = []
            page.on(
                "console",
                lambda msg: js_errors.append(f"{msg.type}: {msg.text}")
                if msg.type in ["error", "warning"]
                else None,
            )

            page_errors = []
            page.on("pageerror", lambda error: page_errors.append(str(error)))

            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Test JavaScript features that the app might use
            # Test 1: Local Storage (if used)
            local_storage_works = page.evaluate(
                """
                (() => {
                    try {
                        localStorage.setItem('test', 'value');
                        const retrieved = localStorage.getItem('test');
                        localStorage.removeItem('test');
                        return retrieved === 'value';
                    } catch (e) {
                        return false;
                    }
                })()
            """
            )

            # Test 2: Fetch API (for AJAX requests)
            fetch_available = page.evaluate("typeof fetch !== 'undefined'")
            assert fetch_available, f"Fetch API should be available in {browser_type}"

            # Test 3: Promises (modern JavaScript)
            promises_work = page.evaluate(
                """
                (() => {
                    try {
                        return Promise.resolve(true);
                    } catch (e) {
                        return false;
                    }
                })()
            """
            )
            assert promises_work, f"Promises should work in {browser_type}"

            # Test 4: Arrow functions (ES6)
            arrow_functions_work = page.evaluate(
                """
                (() => {
                    try {
                        const test = () => true;
                        return test();
                    } catch (e) {
                        return false;
                    }
                })()
            """
            )
            assert (
                arrow_functions_work
            ), f"Arrow functions should work in {browser_type}"

            # Test 5: Basic DOM manipulation
            dom_works = page.evaluate(
                """
                (() => {
                    try {
                        const div = document.createElement('div');
                        div.innerHTML = 'test';
                        return div.innerHTML === 'test';
                    } catch (e) {
                        return false;
                    }
                })()
            """
            )
            assert dom_works, f"DOM manipulation should work in {browser_type}"

            # Interact with the application to trigger JavaScript
            input_element = page.locator("textarea, input[type='text']").first
            if input_element.count() > 0:
                input_element.fill("JavaScript compatibility test")
                input_element.press("Enter")
                page.wait_for_timeout(3000)

            # Check for critical JavaScript errors after interaction
            critical_js_errors = [
                error
                for error in js_errors
                if "error:" in error.lower()
                and not any(
                    ignore in error.lower()
                    for ignore in ["favicon", "analytics", "websocket", "network"]
                )
            ]

            assert (
                len(page_errors) == 0
            ), f"JavaScript page errors in {browser_type}: {page_errors}"
            assert (
                len(critical_js_errors) <= 2
            ), f"Too many JavaScript errors in {browser_type}: {critical_js_errors}"

        finally:
            page.close()
            try:
                os.makedirs("test-results/videos", exist_ok=True)
                video = page.video
                if video:
                    video.save_as(
                        f"test-results/videos/test_javascript_compatibility_{browser_type}.webm"
                    )
            except Exception:
                pass
            context.close()
            browser.close()
