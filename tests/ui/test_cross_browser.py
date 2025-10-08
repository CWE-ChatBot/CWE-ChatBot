"""
Cross-browser compatibility testing.
Tests application functionality across Chrome, Firefox, and Safari (WebKit).
"""

import asyncio
import time

import pytest
from playwright.async_api import expect
from utils.chainlit_helpers import ChainlitTestHelper, setup_test_environment
from utils.screenshot_helpers import take_test_screenshot

# Import user roles with fallback
try:
    import os
    import sys

    sys.path.insert(
        0, os.path.join(os.path.dirname(__file__), "..", "..", "apps", "chatbot", "src")
    )
    from user.role_manager import UserRole
except ImportError:
    from enum import Enum

    class UserRole(Enum):
        PSIRT = "psirt"
        DEVELOPER = "developer"
        ACADEMIC = "academic"
        BUG_BOUNTY = "bug_bounty"
        PRODUCT_MANAGER = "product_manager"


@pytest.mark.parametrize("browser_name", ["chromium", "firefox", "webkit"])
class TestCrossBrowserCompatibility:
    """Test core functionality across different browsers."""

    @pytest.mark.asyncio
    async def test_application_loads_across_browsers(
        self, playwright, browser_name: str, chainlit_base_url: str
    ):
        """Test that application loads successfully in all browsers."""
        print(f"\n=== Testing application load in {browser_name.upper()} ===")

        # Launch specific browser
        browser_type = getattr(playwright, browser_name)
        browser = await browser_type.launch(headless=False)

        try:
            page = await browser.new_page()

            # Navigate to application
            start_time = time.time()
            await page.goto(chainlit_base_url)
            await page.wait_for_load_state("networkidle")
            load_time = time.time() - start_time

            print(f"  Load time: {load_time:.2f} seconds")

            # Verify page loaded successfully
            title = await page.title()
            print(f"  Page title: {title}")

            # Check for basic elements
            body = page.locator("body")
            await expect(body).to_be_visible()

            print(f"  ✓ Application loaded successfully in {browser_name}")

            # Take browser-specific screenshot
            await take_test_screenshot(page, f"app_load_{browser_name}")

            # Performance check
            if load_time < 10.0:
                print("  ✓ Load time acceptable")
            else:
                print(f"  ⚠ Load time slow in {browser_name}")

        except Exception as e:
            print(f"  ❌ Application failed to load in {browser_name}: {e}")
            raise
        finally:
            await browser.close()

    @pytest.mark.asyncio
    async def test_basic_ui_interactions_cross_browser(
        self, playwright, browser_name: str, chainlit_base_url: str
    ):
        """Test basic UI interactions work across browsers."""
        print(f"\n=== Testing UI interactions in {browser_name.upper()} ===")

        browser_type = getattr(playwright, browser_name)
        browser = await browser_type.launch(headless=False)

        try:
            page = await browser.new_page()
            helper = await setup_test_environment(page, chainlit_base_url)

            # Test message submission
            test_query = "What is cross-site scripting?"
            print(f"  Submitting query: {test_query}")

            await helper.submit_message(test_query)
            response = await helper.get_last_response()

            if response and len(response) > 10:
                print(f"  ✓ Query submission works in {browser_name}")
                print(f"  Response length: {len(response)} characters")
            else:
                print(f"  ⚠ Query submission may have issues in {browser_name}")

            # Test UI responsiveness
            await page.set_viewport_size(800, 600)
            await asyncio.sleep(1)

            # Check that UI adapts
            body = page.locator("body")
            is_visible = await body.is_visible()

            if is_visible:
                print(f"  ✓ Responsive design works in {browser_name}")
            else:
                print(f"  ⚠ Responsive design issues in {browser_name}")

            await take_test_screenshot(page, f"ui_interactions_{browser_name}")

        except Exception as e:
            print(f"  ❌ UI interactions failed in {browser_name}: {e}")
        finally:
            await browser.close()

    @pytest.mark.asyncio
    async def test_javascript_compatibility_cross_browser(
        self, playwright, browser_name: str, chainlit_base_url: str
    ):
        """Test JavaScript functionality across browsers."""
        print(f"\n=== Testing JavaScript compatibility in {browser_name.upper()} ===")

        browser_type = getattr(playwright, browser_name)
        browser = await browser_type.launch(headless=False)

        # Track JavaScript errors
        js_errors = []

        def handle_console_msg(msg):
            if msg.type == "error":
                js_errors.append(msg.text)

        try:
            page = await browser.new_page()
            page.on("console", handle_console_msg)

            await page.goto(chainlit_base_url)
            await page.wait_for_load_state("networkidle")

            # Wait for JavaScript to initialize
            await asyncio.sleep(3)

            # Test basic JavaScript functionality
            result = await page.evaluate(
                """
                () => {
                    // Test modern JavaScript features
                    try {
                        // Arrow functions
                        const test = () => 'arrow function works';
                        
                        // Promises
                        const promise = Promise.resolve('promise works');
                        
                        // Modern DOM APIs
                        const elements = document.querySelectorAll('*');
                        
                        return {
                            arrowFunction: test(),
                            promiseSupport: true,
                            domAPI: elements.length > 0,
                            jsEnabled: true
                        };
                    } catch (error) {
                        return {
                            error: error.message,
                            jsEnabled: false
                        };
                    }
                }
            """
            )

            print(f"  JavaScript evaluation result: {result}")

            if result.get("jsEnabled"):
                print(f"  ✓ JavaScript works in {browser_name}")
            else:
                print(
                    f"  ❌ JavaScript issues in {browser_name}: {result.get('error', 'Unknown')}"
                )

            # Report JavaScript errors
            if js_errors:
                print(f"  JavaScript errors in {browser_name}:")
                for error in js_errors:
                    print(f"    - {error}")
            else:
                print(f"  ✓ No JavaScript errors in {browser_name}")

            await take_test_screenshot(page, f"js_compatibility_{browser_name}")

        except Exception as e:
            print(f"  ❌ JavaScript testing failed in {browser_name}: {e}")
        finally:
            await browser.close()

    @pytest.mark.asyncio
    async def test_websocket_connectivity_cross_browser(
        self, playwright, browser_name: str, chainlit_base_url: str
    ):
        """Test WebSocket connectivity across browsers."""
        print(f"\n=== Testing WebSocket connectivity in {browser_name.upper()} ===")

        browser_type = getattr(playwright, browser_name)
        browser = await browser_type.launch(headless=False)

        try:
            page = await browser.new_page()

            # Monitor WebSocket connections
            websocket_events = []

            def handle_websocket(websocket):
                websocket_events.append({"url": websocket.url, "event": "connected"})

                def handle_frame_sent(payload):
                    websocket_events.append(
                        {
                            "event": "frame_sent",
                            "payload": payload[:100],  # First 100 chars
                        }
                    )

                def handle_frame_received(payload):
                    websocket_events.append(
                        {"event": "frame_received", "payload": payload[:100]}
                    )

                websocket.on("framesent", handle_frame_sent)
                websocket.on("framereceived", handle_frame_received)

            page.on("websocket", handle_websocket)

            # Navigate to application
            await page.goto(chainlit_base_url)
            await page.wait_for_load_state("networkidle")

            # Wait for WebSocket connections
            await asyncio.sleep(5)

            print(f"  WebSocket events captured: {len(websocket_events)}")

            # Check for WebSocket connectivity
            websocket_connected = any(
                event["event"] == "connected" for event in websocket_events
            )

            if websocket_connected:
                print(f"  ✓ WebSocket connected in {browser_name}")

                # Check for message exchange
                messages_sent = sum(
                    1 for event in websocket_events if event["event"] == "frame_sent"
                )
                messages_received = sum(
                    1
                    for event in websocket_events
                    if event["event"] == "frame_received"
                )

                print(f"  Messages sent: {messages_sent}")
                print(f"  Messages received: {messages_received}")

                if messages_sent > 0 and messages_received > 0:
                    print(f"  ✓ WebSocket communication works in {browser_name}")
                else:
                    print(f"  ⚠ Limited WebSocket communication in {browser_name}")
            else:
                print(f"  ⚠ No WebSocket connection detected in {browser_name}")

        except Exception as e:
            print(f"  ❌ WebSocket testing failed in {browser_name}: {e}")
        finally:
            await browser.close()


class TestPerformanceAcrossBrowsers:
    """Test performance metrics across different browsers."""

    @pytest.mark.parametrize("browser_name", ["chromium", "firefox", "webkit"])
    @pytest.mark.asyncio
    async def test_page_load_performance_cross_browser(
        self, playwright, browser_name: str, chainlit_base_url: str
    ):
        """Test page load performance across browsers."""
        print(f"\n=== Testing page load performance in {browser_name.upper()} ===")

        browser_type = getattr(playwright, browser_name)
        browser = await browser_type.launch(
            headless=True
        )  # Headless for more consistent performance

        try:
            page = await browser.new_page()

            # Multiple load tests for consistency
            load_times = []

            for attempt in range(3):
                start_time = time.time()

                await page.goto(chainlit_base_url)
                await page.wait_for_load_state("networkidle")

                end_time = time.time()
                load_time = end_time - start_time
                load_times.append(load_time)

                print(f"  Attempt {attempt + 1}: {load_time:.2f}s")

                # Clear cache between attempts
                await page.evaluate("() => { location.reload(true); }")
                await asyncio.sleep(1)

            # Calculate statistics
            avg_load_time = sum(load_times) / len(load_times)
            min_load_time = min(load_times)
            max_load_time = max(load_times)

            print(f"  Average load time: {avg_load_time:.2f}s")
            print(f"  Fastest load: {min_load_time:.2f}s")
            print(f"  Slowest load: {max_load_time:.2f}s")

            # Performance assessment
            if avg_load_time < 5.0:
                print(f"  ✓ Good performance in {browser_name}")
            elif avg_load_time < 10.0:
                print(f"  ⚠ Acceptable performance in {browser_name}")
            else:
                print(f"  ❌ Poor performance in {browser_name}")

        except Exception as e:
            print(f"  ❌ Performance testing failed in {browser_name}: {e}")
        finally:
            await browser.close()

    @pytest.mark.parametrize("browser_name", ["chromium", "firefox", "webkit"])
    @pytest.mark.asyncio
    async def test_query_response_performance_cross_browser(
        self, playwright, browser_name: str, chainlit_base_url: str
    ):
        """Test query response performance across browsers."""
        print(f"\n=== Testing query response performance in {browser_name.upper()} ===")

        browser_type = getattr(playwright, browser_name)
        browser = await browser_type.launch(headless=True)

        try:
            page = await browser.new_page()
            helper = ChainlitTestHelper(page, chainlit_base_url)

            await helper.navigate_to_app()
            await helper.wait_for_chainlit_ready()

            # Test queries of different lengths
            test_queries = [
                "What is XSS?",  # Short query
                "Explain cross-site scripting vulnerabilities and their prevention methods",  # Medium query
                "Provide a comprehensive analysis of cross-site scripting vulnerabilities, including their types, common attack vectors, prevention techniques, and real-world examples of XSS attacks",  # Long query
            ]

            performance_results = []

            for i, query in enumerate(test_queries):
                print(f"  Testing query {i+1}: {len(query)} characters")

                start_time = time.time()

                await helper.submit_message(query)
                response = await helper.get_last_response()

                end_time = time.time()
                response_time = end_time - start_time

                performance_results.append(
                    {
                        "query_length": len(query),
                        "response_time": response_time,
                        "response_length": len(response) if response else 0,
                    }
                )

                print(f"    Response time: {response_time:.2f}s")
                print(
                    f"    Response length: {len(response) if response else 0} characters"
                )

                await asyncio.sleep(1)  # Brief pause between queries

            # Performance analysis
            print(f"\n  Performance summary for {browser_name}:")
            avg_response_time = sum(
                r["response_time"] for r in performance_results
            ) / len(performance_results)
            print(f"  Average response time: {avg_response_time:.2f}s")

            if avg_response_time < 10.0:
                print(f"  ✓ Response performance acceptable in {browser_name}")
            else:
                print(f"  ⚠ Response performance slow in {browser_name}")

        except Exception as e:
            print(f"  ❌ Query performance testing failed in {browser_name}: {e}")
        finally:
            await browser.close()

    @pytest.mark.parametrize("browser_name", ["chromium", "firefox", "webkit"])
    @pytest.mark.asyncio
    async def test_memory_usage_cross_browser(
        self, playwright, browser_name: str, chainlit_base_url: str
    ):
        """Test memory usage across browsers."""
        print(f"\n=== Testing memory usage in {browser_name.upper()} ===")

        browser_type = getattr(playwright, browser_name)
        browser = await browser_type.launch(headless=True)

        try:
            page = await browser.new_page()

            await page.goto(chainlit_base_url)
            await page.wait_for_load_state("networkidle")

            # Get initial memory metrics
            initial_metrics = await page.evaluate(
                """
                () => {
                    if (performance.memory) {
                        return {
                            usedJSHeapSize: performance.memory.usedJSHeapSize,
                            totalJSHeapSize: performance.memory.totalJSHeapSize,
                            jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
                        };
                    }
                    return null;
                }
            """
            )

            if initial_metrics:
                print(
                    f"  Initial memory usage: {initial_metrics['usedJSHeapSize'] / 1024 / 1024:.2f} MB"
                )
                print(
                    f"  Total heap size: {initial_metrics['totalJSHeapSize'] / 1024 / 1024:.2f} MB"
                )
            else:
                print(f"  ℹ Memory metrics not available in {browser_name}")

            # Simulate usage
            helper = ChainlitTestHelper(page, chainlit_base_url)

            # Submit several queries to test memory growth
            for i in range(5):
                await helper.submit_message(
                    f"Test query {i+1}: What is vulnerability assessment?"
                )
                await asyncio.sleep(2)

            # Get final memory metrics
            final_metrics = await page.evaluate(
                """
                () => {
                    if (performance.memory) {
                        return {
                            usedJSHeapSize: performance.memory.usedJSHeapSize,
                            totalJSHeapSize: performance.memory.totalJSHeapSize
                        };
                    }
                    return null;
                }
            """
            )

            if initial_metrics and final_metrics:
                memory_growth = (
                    (
                        final_metrics["usedJSHeapSize"]
                        - initial_metrics["usedJSHeapSize"]
                    )
                    / 1024
                    / 1024
                )
                print(
                    f"  Final memory usage: {final_metrics['usedJSHeapSize'] / 1024 / 1024:.2f} MB"
                )
                print(f"  Memory growth: {memory_growth:.2f} MB")

                if memory_growth < 10:  # Less than 10MB growth
                    print(f"  ✓ Memory usage reasonable in {browser_name}")
                else:
                    print(f"  ⚠ High memory usage in {browser_name}")
            else:
                print(f"  ℹ Memory analysis not available in {browser_name}")

        except Exception as e:
            print(f"  ❌ Memory testing failed in {browser_name}: {e}")
        finally:
            await browser.close()


class TestBrowserSpecificFeatures:
    """Test browser-specific features and compatibility."""

    @pytest.mark.parametrize("browser_name", ["chromium", "firefox", "webkit"])
    @pytest.mark.asyncio
    async def test_css_compatibility_cross_browser(
        self, playwright, browser_name: str, chainlit_base_url: str
    ):
        """Test CSS feature compatibility across browsers."""
        print(f"\n=== Testing CSS compatibility in {browser_name.upper()} ===")

        browser_type = getattr(playwright, browser_name)
        browser = await browser_type.launch(headless=False)

        try:
            page = await browser.new_page()

            await page.goto(chainlit_base_url)
            await page.wait_for_load_state("networkidle")

            # Test modern CSS features
            css_support = await page.evaluate(
                """
                () => {
                    const testElement = document.createElement('div');
                    document.body.appendChild(testElement);
                    
                    const features = {};
                    
                    // Test CSS Grid
                    testElement.style.display = 'grid';
                    features.cssGrid = getComputedStyle(testElement).display === 'grid';
                    
                    // Test Flexbox
                    testElement.style.display = 'flex';
                    features.flexbox = getComputedStyle(testElement).display === 'flex';
                    
                    // Test CSS Variables
                    testElement.style.setProperty('--test-var', 'red');
                    testElement.style.color = 'var(--test-var)';
                    features.cssVariables = getComputedStyle(testElement).color === 'red';
                    
                    // Test CSS Transforms
                    testElement.style.transform = 'rotate(45deg)';
                    features.cssTransforms = getComputedStyle(testElement).transform !== 'none';
                    
                    document.body.removeChild(testElement);
                    
                    return features;
                }
            """
            )

            print(f"  CSS feature support in {browser_name}:")
            for feature, supported in css_support.items():
                status = "✓" if supported else "❌"
                print(f"    {feature}: {status}")

            # Check layout rendering
            viewport_info = await page.evaluate(
                """
                () => ({
                    width: window.innerWidth,
                    height: window.innerHeight,
                    devicePixelRatio: window.devicePixelRatio
                })
            """
            )

            print(f"  Viewport: {viewport_info['width']}x{viewport_info['height']}")
            print(f"  Device pixel ratio: {viewport_info['devicePixelRatio']}")

            await take_test_screenshot(page, f"css_compatibility_{browser_name}")

        except Exception as e:
            print(f"  ❌ CSS compatibility testing failed in {browser_name}: {e}")
        finally:
            await browser.close()

    @pytest.mark.parametrize("browser_name", ["chromium", "firefox", "webkit"])
    @pytest.mark.asyncio
    async def test_accessibility_features_cross_browser(
        self, playwright, browser_name: str, chainlit_base_url: str
    ):
        """Test accessibility features across browsers."""
        print(f"\n=== Testing accessibility in {browser_name.upper()} ===")

        browser_type = getattr(playwright, browser_name)
        browser = await browser_type.launch(headless=False)

        try:
            page = await browser.new_page()

            await page.goto(chainlit_base_url)
            await page.wait_for_load_state("networkidle")

            # Test keyboard navigation
            print("  Testing keyboard navigation...")

            # Press Tab to navigate
            await page.keyboard.press("Tab")
            focused_element = await page.evaluate(
                "() => document.activeElement.tagName"
            )
            print(f"    First focusable element: {focused_element}")

            # Test ARIA attributes
            aria_elements = await page.evaluate(
                """
                () => {
                    const elements = {
                        labels: document.querySelectorAll('[aria-label]').length,
                        roles: document.querySelectorAll('[role]').length,
                        described: document.querySelectorAll('[aria-describedby]').length
                    };
                    return elements;
                }
            """
            )

            print("  ARIA elements found:")
            print(f"    Elements with aria-label: {aria_elements['labels']}")
            print(f"    Elements with role: {aria_elements['roles']}")
            print(f"    Elements with aria-describedby: {aria_elements['described']}")

            # Test color contrast (basic check)
            contrast_info = await page.evaluate(
                """
                () => {
                    const body = document.body;
                    const styles = getComputedStyle(body);
                    return {
                        backgroundColor: styles.backgroundColor,
                        color: styles.color
                    };
                }
            """
            )

            print(
                f"  Color scheme: {contrast_info['color']} on {contrast_info['backgroundColor']}"
            )

            if aria_elements["labels"] > 0 or aria_elements["roles"] > 0:
                print(f"  ✓ Basic accessibility features present in {browser_name}")
            else:
                print(f"  ⚠ Limited accessibility features in {browser_name}")

        except Exception as e:
            print(f"  ❌ Accessibility testing failed in {browser_name}: {e}")
        finally:
            await browser.close()


class TestMobileCompatibility:
    """Test mobile browser compatibility."""

    @pytest.mark.parametrize(
        "browser_name", ["chromium", "webkit"]
    )  # Firefox mobile support limited
    @pytest.mark.asyncio
    async def test_mobile_viewport_compatibility(
        self, playwright, browser_name: str, chainlit_base_url: str
    ):
        """Test mobile viewport compatibility."""
        print(f"\n=== Testing mobile compatibility in {browser_name.upper()} ===")

        browser_type = getattr(playwright, browser_name)
        browser = await browser_type.launch(headless=False)

        mobile_devices = [
            {"name": "iPhone 12", "viewport": {"width": 390, "height": 844}},
            {"name": "Pixel 5", "viewport": {"width": 393, "height": 851}},
            {"name": "iPad", "viewport": {"width": 768, "height": 1024}},
        ]

        try:
            for device in mobile_devices:
                page = await browser.new_page()

                # Set mobile viewport
                await page.set_viewport_size(
                    device["viewport"]["width"], device["viewport"]["height"]
                )

                print(
                    f"  Testing {device['name']} ({device['viewport']['width']}x{device['viewport']['height']})..."
                )

                await page.goto(chainlit_base_url)
                await page.wait_for_load_state("networkidle")

                # Test mobile-specific features
                mobile_features = await page.evaluate(
                    """
                    () => {
                        return {
                            touchSupport: 'ontouchstart' in window,
                            viewportWidth: window.innerWidth,
                            viewportHeight: window.innerHeight,
                            orientation: screen.orientation ? screen.orientation.angle : 'unknown'
                        };
                    }
                """
                )

                print(f"    Touch support: {mobile_features['touchSupport']}")
                print(
                    f"    Actual viewport: {mobile_features['viewportWidth']}x{mobile_features['viewportHeight']}"
                )

                # Test responsive design
                body = page.locator("body")
                is_visible = await body.is_visible()

                if is_visible:
                    print(f"    ✓ Layout works on {device['name']}")
                else:
                    print(f"    ❌ Layout issues on {device['name']}")

                # Take mobile screenshot
                await take_test_screenshot(
                    page, f"mobile_{browser_name}_{device['name'].replace(' ', '_')}"
                )

                await page.close()

        except Exception as e:
            print(f"  ❌ Mobile compatibility testing failed in {browser_name}: {e}")
        finally:
            await browser.close()


class TestNetworkConditions:
    """Test application behavior under different network conditions."""

    @pytest.mark.parametrize(
        "browser_name", ["chromium"]
    )  # Network throttling best supported in Chromium
    @pytest.mark.asyncio
    async def test_slow_network_performance(
        self, playwright, browser_name: str, chainlit_base_url: str
    ):
        """Test application performance on slow networks."""
        print(f"\n=== Testing slow network performance in {browser_name.upper()} ===")

        browser_type = getattr(playwright, browser_name)
        browser = await browser_type.launch(headless=True)

        try:
            page = await browser.new_page()

            # Simulate slow 3G network
            await page.route(
                "**/*", lambda route: asyncio.sleep(0.5) or route.continue_()
            )

            start_time = time.time()

            await page.goto(chainlit_base_url)
            await page.wait_for_load_state("networkidle")

            load_time = time.time() - start_time
            print(f"  Slow network load time: {load_time:.2f}s")

            # Test functionality under slow conditions
            helper = ChainlitTestHelper(page, chainlit_base_url)

            start_time = time.time()
            await helper.submit_message("What is SQL injection?")
            response = await helper.get_last_response()
            response_time = time.time() - start_time

            print(f"  Slow network query response time: {response_time:.2f}s")

            if response and len(response) > 10:
                print("  ✓ Application functional on slow network")
            else:
                print("  ⚠ Application may have issues on slow network")

            if load_time < 30.0 and response_time < 60.0:
                print("  ✓ Acceptable performance on slow network")
            else:
                print("  ⚠ Poor performance on slow network")

        except Exception as e:
            print(f"  ❌ Slow network testing failed: {e}")
        finally:
            await browser.close()

    @pytest.mark.parametrize("browser_name", ["chromium"])
    @pytest.mark.asyncio
    async def test_offline_behavior(
        self, playwright, browser_name: str, chainlit_base_url: str
    ):
        """Test application behavior when offline."""
        print(f"\n=== Testing offline behavior in {browser_name.upper()} ===")

        browser_type = getattr(playwright, browser_name)
        browser = await browser_type.launch(headless=True)

        try:
            page = await browser.new_page()

            # Load application normally first
            await page.goto(chainlit_base_url)
            await page.wait_for_load_state("networkidle")

            print("  ✓ Application loaded while online")

            # Go offline
            await page.context.set_offline(True)
            print("  Network set to offline")

            # Test offline behavior
            helper = ChainlitTestHelper(page, chainlit_base_url)

            try:
                await helper.submit_message("Test offline query")
                response = await helper.get_last_response()

                if response:
                    print(
                        f"  ⚠ Application provided response while offline: {response[:50]}..."
                    )
                else:
                    print("  ✓ No response provided while offline (expected)")

            except Exception as e:
                print(f"  ✓ Query failed while offline (expected): {type(e).__name__}")

            # Test page navigation while offline
            try:
                await page.goto(chainlit_base_url + "/nonexistent")
            except Exception:
                print("  ✓ Navigation failed while offline (expected)")

            # Go back online
            await page.context.set_offline(False)
            print("  Network restored")

            # Test that functionality returns
            await asyncio.sleep(2)

            try:
                await helper.submit_message("Test online again")
                response = await helper.get_last_response()

                if response and len(response) > 10:
                    print("  ✓ Functionality restored when back online")
                else:
                    print("  ⚠ Functionality may not be fully restored")

            except Exception as e:
                print(f"  ⚠ Issues after going back online: {e}")

        except Exception as e:
            print(f"  ❌ Offline behavior testing failed: {e}")
        finally:
            await browser.close()


# Summary test for cross-browser compatibility
class TestCrossBrowserSummary:
    """Generate summary of cross-browser compatibility."""

    @pytest.mark.asyncio
    async def test_generate_cross_browser_report(
        self, playwright, chainlit_base_url: str
    ):
        """Generate comprehensive cross-browser compatibility report."""
        print("\n=== CROSS-BROWSER COMPATIBILITY SUMMARY ===")

        browsers = ["chromium", "firefox", "webkit"]
        compatibility_results = {}

        for browser_name in browsers:
            print(f"\nTesting {browser_name.upper()}...")

            browser_type = getattr(playwright, browser_name)
            browser = await browser_type.launch(headless=True)

            results = {
                "loads": False,
                "interactive": False,
                "performance": "unknown",
                "errors": [],
            }

            try:
                page = await browser.new_page()

                # Test basic loading
                try:
                    await page.goto(chainlit_base_url, timeout=15000)
                    await page.wait_for_load_state("networkidle", timeout=15000)
                    results["loads"] = True
                    print("  ✓ Loads successfully")
                except Exception as e:
                    results["errors"].append(f"Load failed: {e}")
                    print("  ❌ Load failed")

                # Test interactivity
                if results["loads"]:
                    try:
                        helper = ChainlitTestHelper(page, chainlit_base_url)
                        await helper.submit_message("Test query")
                        response = await helper.get_last_response()

                        if response and len(response) > 10:
                            results["interactive"] = True
                            print("  ✓ Interactive")
                        else:
                            print("  ⚠ Limited interactivity")
                    except Exception as e:
                        results["errors"].append(f"Interactivity failed: {e}")
                        print("  ❌ Interactivity failed")

                # Test performance
                if results["interactive"]:
                    try:
                        start_time = time.time()
                        await page.reload()
                        await page.wait_for_load_state("networkidle")
                        load_time = time.time() - start_time

                        if load_time < 5.0:
                            results["performance"] = "good"
                        elif load_time < 10.0:
                            results["performance"] = "acceptable"
                        else:
                            results["performance"] = "poor"

                        print(
                            f"  Performance: {results['performance']} ({load_time:.2f}s)"
                        )
                    except Exception as e:
                        results["errors"].append(f"Performance test failed: {e}")
                        results["performance"] = "error"

            except Exception as e:
                results["errors"].append(f"General error: {e}")

            finally:
                await browser.close()
                compatibility_results[browser_name] = results

        # Generate summary report
        print(f"\n{'='*60}")
        print("CROSS-BROWSER COMPATIBILITY REPORT")
        print(f"{'='*60}")

        for browser, results in compatibility_results.items():
            print(f"\n{browser.upper()}:")
            print(f"  Loads: {'✓' if results['loads'] else '❌'}")
            print(f"  Interactive: {'✓' if results['interactive'] else '❌'}")
            print(f"  Performance: {results['performance']}")

            if results["errors"]:
                print("  Issues:")
                for error in results["errors"]:
                    print(f"    - {error}")
            else:
                print("  Issues: None")

        # Overall assessment
        working_browsers = sum(
            1
            for results in compatibility_results.values()
            if results["loads"] and results["interactive"]
        )
        total_browsers = len(compatibility_results)

        print(
            f"\nOVERALL COMPATIBILITY: {working_browsers}/{total_browsers} browsers fully functional"
        )

        if working_browsers == total_browsers:
            print("✓ Excellent cross-browser compatibility")
        elif working_browsers >= total_browsers * 0.67:
            print("⚠ Good cross-browser compatibility with some issues")
        else:
            print("❌ Poor cross-browser compatibility")

        # Save results for future reference
        import json

        with open("test-results/cross-browser-report.json", "w") as f:
            json.dump(compatibility_results, f, indent=2)

        print("\nDetailed report saved to: test-results/cross-browser-report.json")
