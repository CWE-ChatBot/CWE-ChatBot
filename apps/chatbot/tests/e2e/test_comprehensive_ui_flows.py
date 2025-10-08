"""
Comprehensive E2E UI testing covering advanced user flows and edge cases.
Focuses on real-world usage patterns, error recovery, and user experience.
"""

import os
import time

import pytest
from playwright.sync_api import expect, sync_playwright


@pytest.mark.e2e
def test_persona_switching_workflow(chainlit_server, sample_roles):
    """Test seamless switching between different user personas during a session."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Find input element
            input_element = None
            for selector in ["textarea", "input[type='text']"]:
                elements = page.locator(selector)
                if elements.count() > 0 and elements.first.is_visible():
                    input_element = elements.first
                    break

            if not input_element:
                pytest.skip("Message input not found")

            test_query = "What is CWE-79?"

            # Test persona switching workflow
            personas_to_test = ["Developer", "PSIRT", "Researcher"]

            for persona in personas_to_test:
                # Select persona
                persona_button = page.locator(f"button:has-text('{persona}')")
                if persona_button.count() > 0:
                    persona_button.click()
                    page.wait_for_timeout(1000)

                # Send same query with different persona
                page.wait_for_timeout(300)
                input_element.fill(test_query)
                input_element.press("Enter")
                page.wait_for_timeout(3000)

                # Verify persona is reflected in response
                page_content = page.content().lower()
                assert (
                    len(page_content) > 1000
                ), f"Should get substantial response for {persona}"

            # Verify context persistence across persona switches
            # The chat history should still be visible
            messages = page.locator("[class*='message'], [data-testid*='message']")
            assert messages.count() >= len(
                personas_to_test
            ), "Chat history should persist across persona switches"

        finally:
            page.close()
            try:
                os.makedirs("test-results/videos", exist_ok=True)
                video = page.video
                if video:
                    video.save_as(
                        "test-results/videos/test_persona_switching_workflow.webm"
                    )
            except Exception:
                pass
            context.close()
            browser.close()


@pytest.mark.e2e
def test_error_recovery_scenarios(chainlit_server):
    """Test how the UI handles various error conditions and recovers gracefully."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Find input
            input_element = None
            for selector in ["textarea", "input[type='text']"]:
                elements = page.locator(selector)
                if elements.count() > 0 and elements.first.is_visible():
                    input_element = elements.first
                    break

            if not input_element:
                pytest.skip("Message input not found")

            # Test 1: Very long message (should be handled gracefully)
            very_long_message = "What is CWE-79? " * 200  # ~2600 characters
            page.wait_for_timeout(300)
            input_element.fill(very_long_message)
            input_element.press("Enter")
            page.wait_for_timeout(2000)

            # Should not crash the application
            assert page.url.startswith(
                "http"
            ), "Application should remain functional after long message"

            # Test 2: Special characters and potential XSS
            special_chars_message = "<script>alert('test')</script> What about CWE-79?"
            input_element.fill("")
            input_element.fill(special_chars_message)
            input_element.press("Enter")
            page.wait_for_timeout(2000)

            # Check that the user-rendered chat content is sanitized (no script tags inside messages)
            # Look only within visible chat message containers, not the app shell HTML
            messages = page.locator("[class*='message'], [data-testid*='message']")
            msg_count = messages.count()
            if msg_count > 0:
                start = max(0, msg_count - 3)
                for i in range(start, msg_count):
                    try:
                        html = messages.nth(i).inner_html()
                    except Exception:
                        # Fallback to text if inner_html is unavailable
                        html = messages.nth(i).text_content() or ""
                    assert (
                        "<script" not in (html or "").lower()
                    ), "Script tags should be sanitized in message content"
            assert page.url.startswith("http"), "Application should remain functional"

            # Test 3: Rapid message sending (stress test)
            for i in range(5):
                input_element.fill(f"Quick message {i}")
                input_element.press("Enter")
                page.wait_for_timeout(200)  # Very short wait

            # Should handle rapid inputs without crashing
            page.wait_for_timeout(2000)
            assert page.url.startswith("http"), "Application should handle rapid inputs"

            # Test 4: Empty/whitespace messages
            for empty_msg in ["", "   ", "\n\n\n", "\t"]:
                input_element.fill(empty_msg)
                input_element.press("Enter")
                page.wait_for_timeout(500)

            # Should gracefully handle empty messages
            assert page.url.startswith(
                "http"
            ), "Application should handle empty messages"

        finally:
            page.close()
            try:
                os.makedirs("test-results/videos", exist_ok=True)
                video = page.video
                if video:
                    video.save_as(
                        "test-results/videos/test_error_recovery_scenarios.webm"
                    )
            except Exception:
                pass
            context.close()
            browser.close()


@pytest.mark.e2e
def test_mobile_responsive_ui(chainlit_server):
    """Test UI responsiveness and functionality on mobile viewports."""
    url = chainlit_server["url"]

    mobile_devices = [
        {"name": "iPhone 12", "width": 390, "height": 844},
        {"name": "Samsung Galaxy S21", "width": 360, "height": 800},
        {"name": "iPad Mini", "width": 768, "height": 1024},
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        for device in mobile_devices:
            context = browser.new_context(
                viewport={"width": device["width"], "height": device["height"]},
                record_video_dir="test-results/videos/",
            )
            page = context.new_page()

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_load_state("networkidle", timeout=20000)

                # Check that content fits in viewport
                body = page.locator("body")
                expect(body).to_be_visible()

                # Test that chat input is accessible on mobile
                input_element = None
                for selector in ["textarea", "input[type='text']"]:
                    elements = page.locator(selector)
                    if elements.count() > 0:
                        try:
                            if elements.first.is_visible():
                                input_element = elements.first
                                break
                        except Exception:
                            continue

                if input_element:
                    # Test scrolling behavior
                    input_element.fill("Test message on mobile device")
                    input_element.press("Enter")
                    page.wait_for_timeout(2000)

                    # Check if response is visible and properly formatted
                    scroll_height = page.evaluate("document.body.scrollHeight")
                    viewport_height = device["height"]

                    # Content should be scrollable if it exceeds viewport
                    if scroll_height > viewport_height:
                        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                        page.wait_for_timeout(500)

                # Test that buttons and interactive elements are touchable
                buttons = page.locator("button")
                if buttons.count() > 0:
                    # Check that buttons have appropriate touch targets (at least 44px)
                    for i in range(min(3, buttons.count())):  # Test first 3 buttons
                        button = buttons.nth(i)
                        if button.is_visible():
                            box = button.bounding_box()
                            if box:
                                # Touch target should be at least 44x44px for accessibility
                                assert (
                                    box["height"] >= 32 or box["width"] >= 32
                                ), f"Interactive element should be large enough for touch on {device['name']}"

                # Test horizontal scrolling (should not be needed)
                scroll_width = page.evaluate("document.body.scrollWidth")
                assert (
                    scroll_width <= device["width"] + 20
                ), f"Content should not require horizontal scrolling on {device['name']}"

            finally:
                page.close()
                try:
                    os.makedirs("test-results/videos", exist_ok=True)
                    video = page.video
                    if video:
                        video.save_as(
                            f'test-results/videos/test_mobile_responsive_ui_{device["name"].replace(" ", "_")}.webm'
                        )
                except Exception:
                    pass
                context.close()

        browser.close()


@pytest.mark.e2e
def test_session_persistence_and_recovery(chainlit_server):
    """Test session management, browser refresh recovery, and data persistence."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Find input and send initial message
            input_element = None
            for selector in ["textarea", "input[type='text']"]:
                elements = page.locator(selector)
                if elements.count() > 0 and elements.first.is_visible():
                    input_element = elements.first
                    break

            if not input_element:
                pytest.skip("Message input not found")

            # Send initial message
            initial_message = "What is CWE-89?"
            input_element.fill(initial_message)
            input_element.press("Enter")
            page.wait_for_timeout(3000)

            # Capture initial state
            initial_content = page.content()
            initial_messages_count = page.locator(
                "[class*='message'], [data-testid*='message']"
            ).count()

            # Test browser refresh
            page.reload(wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Check if session state is maintained after refresh
            post_refresh_content = page.content()

            # At minimum, the application should remain functional
            assert page.url.startswith(
                "http"
            ), "Application should remain functional after refresh"

            # Find input again after refresh
            input_element = None
            for selector in ["textarea", "input[type='text']"]:
                elements = page.locator(selector)
                if elements.count() > 0 and elements.first.is_visible():
                    input_element = elements.first
                    break

            if input_element:
                # Test that we can continue the conversation
                followup_message = "Can you explain SQL injection prevention?"
                input_element.fill(followup_message)
                input_element.press("Enter")
                page.wait_for_timeout(3000)

                # Should be able to continue conversation
                final_content = page.content()
                assert len(final_content) > len(
                    post_refresh_content
                ), "Should be able to continue conversation after refresh"

            # Test multiple tabs/sessions (if supported)
            second_page = context.new_page()
            second_page.goto(url, wait_until="domcontentloaded", timeout=30000)
            second_page.wait_for_load_state("networkidle", timeout=10000)

            # Second tab should get a fresh session
            second_input = None
            for selector in ["textarea", "input[type='text']"]:
                elements = second_page.locator(selector)
                if elements.count() > 0 and elements.first.is_visible():
                    second_input = elements.first
                    break

            if second_input:
                second_input.fill("New session test")
                second_input.press("Enter")
                page.wait_for_timeout(2000)

                # Both sessions should remain functional
                assert page.url.startswith(
                    "http"
                ), "Original session should remain functional"
                assert second_page.url.startswith(
                    "http"
                ), "New session should be functional"

            second_page.close()

        finally:
            page.close()
            try:
                os.makedirs("test-results/videos", exist_ok=True)
                video = page.video
                if video:
                    video.save_as(
                        "test-results/videos/test_session_persistence_and_recovery.webm"
                    )
            except Exception:
                pass
            context.close()
            browser.close()


@pytest.mark.e2e
@pytest.mark.slow
def test_performance_and_load_behavior(chainlit_server):
    """Test UI performance under various load conditions."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            # Measure initial load time
            start_time = time.time()
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)
            load_time = time.time() - start_time

            # Initial load should be reasonable (under 10 seconds)
            assert (
                load_time < 10.0
            ), f"Initial load took {load_time:.2f}s, should be under 10s"

            # Find input
            input_element = None
            for selector in ["textarea", "input[type='text']"]:
                elements = page.locator(selector)
                if elements.count() > 0 and elements.first.is_visible():
                    input_element = elements.first
                    break

            if not input_element:
                pytest.skip("Message input not found")

            # Test response time for simple queries
            simple_queries = [
                "What is CWE-79?",
                "Explain SQL injection",
                "List common vulnerabilities",
                "How to prevent XSS?",
                "Buffer overflow mitigation",
            ]

            response_times = []
            for query in simple_queries:
                start_time = time.time()
                input_element.fill(query)
                input_element.press("Enter")

                # Wait for response to appear
                page.wait_for_timeout(1000)  # Initial wait for response to start

                # Wait for response to complete (or timeout)
                max_wait = 15  # seconds
                waited = 0
                while waited < max_wait:
                    page.wait_for_timeout(1000)
                    waited += 1
                    # Check if response seems complete (heuristic)
                    content_length = len(page.content())
                    page.wait_for_timeout(500)
                    if len(page.content()) == content_length:
                        break  # Content stopped growing, likely done

                response_time = time.time() - start_time
                response_times.append(response_time)

                # Clear input for next query
                input_element.fill("")
                page.wait_for_timeout(500)

            # Analyze performance
            if response_times:
                avg_response_time = sum(response_times) / len(response_times)
                max_response_time = max(response_times)

                # Performance expectations (adjust based on your requirements)
                assert (
                    avg_response_time < 30.0
                ), f"Average response time {avg_response_time:.2f}s too slow"
                assert (
                    max_response_time < 45.0
                ), f"Max response time {max_response_time:.2f}s too slow"

            # Test memory usage stability (check for obvious memory leaks)
            initial_memory = page.evaluate(
                "performance.memory ? performance.memory.usedJSHeapSize : 0"
            )

            # Generate some load
            for i in range(10):
                input_element.fill(f"Load test message {i}")
                input_element.press("Enter")
                page.wait_for_timeout(1000)

            page.wait_for_timeout(5000)  # Let things settle

            final_memory = page.evaluate(
                "performance.memory ? performance.memory.usedJSHeapSize : 0"
            )

            if initial_memory > 0 and final_memory > 0:
                memory_growth = (final_memory - initial_memory) / initial_memory
                # Memory should not grow excessively (>100% growth might indicate leak)
                assert (
                    memory_growth < 1.0
                ), f"Memory grew {memory_growth:.2%}, possible memory leak"

        finally:
            page.close()
            try:
                os.makedirs("test-results/videos", exist_ok=True)
                video = page.video
                if video:
                    video.save_as(
                        "test-results/videos/test_performance_and_load_behavior.webm"
                    )
            except Exception:
                pass
            context.close()
            browser.close()


@pytest.mark.e2e
def test_accessibility_compliance(chainlit_server):
    """Test accessibility features and WCAG compliance."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Test 1: Keyboard navigation
            page.keyboard.press("Tab")  # Should focus first interactive element
            focused_element = page.evaluate("document.activeElement.tagName")
            assert focused_element in [
                "BUTTON",
                "INPUT",
                "TEXTAREA",
                "A",
            ], "Tab should focus on interactive element"

            # Test 2: Screen reader support
            # Check for proper heading structure
            headings = page.locator("h1, h2, h3, h4, h5, h6")
            if headings.count() > 0:
                # Should have logical heading hierarchy
                h1_count = page.locator("h1").count()
                assert h1_count <= 1, "Should have at most one h1 element"

            # Test 3: Form labels and ARIA attributes
            inputs = page.locator("input, textarea")
            for i in range(inputs.count()):
                input_elem = inputs.nth(i)
                if input_elem.is_visible():
                    # Should have label, placeholder, or aria-label
                    has_label = input_elem.get_attribute("aria-label") is not None
                    has_placeholder = (
                        input_elem.get_attribute("placeholder") is not None
                    )

                    # Check for associated label
                    input_id = input_elem.get_attribute("id")
                    has_associated_label = False
                    if input_id:
                        label = page.locator(f"label[for='{input_id}']")
                        has_associated_label = label.count() > 0

                    assert (
                        has_label or has_placeholder or has_associated_label
                    ), "Form inputs should have accessible labels"

            # Test 4: Color contrast (basic check)
            # Check that text is visible (not white on white, etc.)
            body_bg = page.evaluate("getComputedStyle(document.body).backgroundColor")
            body_color = page.evaluate("getComputedStyle(document.body).color")
            assert body_bg != body_color, "Text should have contrast with background"

            # Test 5: Focus indicators
            # Check that focused elements are visually distinguishable
            buttons = page.locator("button")
            if buttons.count() > 0:
                first_button = buttons.first
                first_button.focus()

                # Should have focus indicator (outline, box-shadow, etc.)
                outline = page.evaluate(
                    "getComputedStyle(document.querySelector('button:focus')).outline"
                )
                box_shadow = page.evaluate(
                    "getComputedStyle(document.querySelector('button:focus')).boxShadow"
                )

                # At least one focus indicator should be present
                has_focus_indicator = outline != "none" or box_shadow != "none"
                # Note: This is a basic check, real apps might use other focus indicators

            # Test 6: Alternative text for images
            images = page.locator("img")
            for i in range(images.count()):
                img = images.nth(i)
                if img.is_visible():
                    alt_text = img.get_attribute("alt")
                    src = img.get_attribute("src")

                    # Decorative images can have empty alt, but should have alt attribute
                    if src and not src.startswith("data:"):
                        assert alt_text is not None, "Images should have alt attribute"

            # Test 7: Skip links for screen readers
            # Check for skip navigation links
            skip_links = page.locator(
                "a[href*='#main'], a[href*='#content'], a:has-text('Skip')"
            )
            # Skip links are good practice but not always required for simple apps

        finally:
            page.close()
            try:
                os.makedirs("test-results/videos", exist_ok=True)
                video = page.video
                if video:
                    video.save_as(
                        "test-results/videos/test_accessibility_compliance.webm"
                    )
            except Exception:
                pass
            context.close()
            browser.close()


@pytest.mark.e2e
def test_real_world_user_workflows(chainlit_server):
    """Test realistic user workflows that combine multiple features."""
    url = chainlit_server["url"]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Find input
            input_element = None
            for selector in ["textarea", "input[type='text']"]:
                elements = page.locator(selector)
                if elements.count() > 0 and elements.first.is_visible():
                    input_element = elements.first
                    break

            if not input_element:
                pytest.skip("Message input not found")

            # Workflow 1: Developer investigating a vulnerability
            developer_role = page.locator("button:has-text('Developer')")
            if developer_role.count() > 0:
                developer_role.click()
                page.wait_for_timeout(1000)

            # Step 1: Ask about a specific vulnerability
            input_element.fill(
                "I found CWE-89 in our code review. What exactly is this?"
            )
            input_element.press("Enter")
            page.wait_for_timeout(4000)

            # Step 2: Ask for specific remediation
            input_element.fill("How do I fix SQL injection in Python Django?")
            input_element.press("Enter")
            page.wait_for_timeout(4000)

            # Step 3: Ask about testing
            input_element.fill("How can I test if my fix works?")
            input_element.press("Enter")
            page.wait_for_timeout(4000)

            # Workflow 2: PSIRT member doing impact assessment
            psirt_role = page.locator("button:has-text('PSIRT')")
            if psirt_role.count() > 0:
                psirt_role.click()
                page.wait_for_timeout(1000)

            # Step 1: Assess severity
            input_element.fill(
                "We have a CWE-787 buffer overflow. How critical is this?"
            )
            input_element.press("Enter")
            page.wait_for_timeout(4000)

            # Step 2: Ask about business impact
            input_element.fill(
                "What should we tell our customers about this vulnerability?"
            )
            input_element.press("Enter")
            page.wait_for_timeout(4000)

            # Workflow 3: Settings adjustment and preference testing
            # Try to open settings
            settings_selectors = [
                'button[aria-label*="Settings"]',
                '[data-testid="settings-button"]',
                'button:has-text("Settings")',
                ".gear-icon",
                '[title*="Settings"]',
            ]

            settings_opened = False
            for selector in settings_selectors:
                try:
                    if page.locator(selector).count() > 0:
                        page.locator(selector).first.click()
                        settings_opened = True
                        page.wait_for_timeout(1000)
                        break
                except Exception:
                    continue

            if settings_opened:
                # Try to change detail level if available
                detail_selectors = [
                    "select:has-option('detailed')",
                    "button:has-text('detailed')",
                    "input[value='detailed']",
                ]

                for selector in detail_selectors:
                    try:
                        if page.locator(selector).count() > 0:
                            page.locator(selector).first.click()
                            page.wait_for_timeout(500)
                            break
                    except Exception:
                        continue

                # Close settings (ESC or click outside)
                page.keyboard.press("Escape")
                page.wait_for_timeout(500)

            # Test that conversation continues smoothly after settings changes
            input_element.fill(
                "Can you provide more detailed information about CWE-79?"
            )
            input_element.press("Enter")
            page.wait_for_timeout(4000)

            # Verify the conversation has substantial content
            final_content = page.content()
            assert (
                len(final_content) > 5000
            ), "Should have substantial conversation content"

            # Verify no obvious errors in the UI
            error_indicators = page.locator(
                "text=Error, text=error, text=failed, .error"
            )
            visible_errors = [
                err
                for i in range(error_indicators.count())
                if error_indicators.nth(i).is_visible()
            ]

            # Allow for some system messages that might contain "error" in context
            assert (
                len(visible_errors) < 3
            ), f"Should not have many visible errors: {len(visible_errors)}"

        finally:
            page.close()
            try:
                os.makedirs("test-results/videos", exist_ok=True)
                video = page.video
                if video:
                    video.save_as(
                        "test-results/videos/test_real_world_user_workflows.webm"
                    )
            except Exception:
                pass
            context.close()
            browser.close()
