"""
Pytest configuration and fixtures for Playwright UI testing.
Provides shared fixtures and configuration for UI test suite.
"""

import asyncio
import os
import sys
from typing import AsyncGenerator, Generator

import pytest
from playwright.async_api import Browser, BrowserContext, Page, async_playwright

# Add the source directory to the Python path for imports
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "..", "apps", "chatbot", "src")
)

# Import user personas for testing
try:
    from user_context import UserPersona

    # Create role mapping for backward compatibility
    class UserRole:
        PSIRT = UserPersona.PSIRT_MEMBER.value
        DEVELOPER = UserPersona.DEVELOPER.value
        ACADEMIC = UserPersona.ACADEMIC_RESEARCHER.value
        BUG_BOUNTY = UserPersona.BUG_BOUNTY_HUNTER.value
        PRODUCT_MANAGER = UserPersona.PRODUCT_MANAGER.value

except ImportError:
    # Fallback if user_context isn't available yet
    class UserRole:
        PSIRT = "PSIRT Member"
        DEVELOPER = "Developer"
        ACADEMIC = "Academic Researcher"
        BUG_BOUNTY = "Bug Bounty Hunter"
        PRODUCT_MANAGER = "Product Manager"


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def browser() -> AsyncGenerator[Browser, None]:
    """Create a browser instance for the test session."""
    async with async_playwright() as p:
        # Use chromium by default, but can be configured via environment
        browser_type = os.getenv("PLAYWRIGHT_BROWSER", "chromium")

        if browser_type == "firefox":
            browser = await p.firefox.launch(headless=False)
        elif browser_type == "webkit":
            browser = await p.webkit.launch(headless=False)
        else:
            browser = await p.chromium.launch(headless=False)

        yield browser
        await browser.close()


@pytest.fixture
async def context(browser: Browser) -> AsyncGenerator[BrowserContext, None]:
    """Create a new browser context for each test."""
    context = await browser.new_context(
        viewport={"width": 1280, "height": 720},
        # Enable recording for debugging
        record_video_dir="test-results/videos/" if os.getenv("RECORD_VIDEO") else None,
        record_har_path="test-results/har/" if os.getenv("RECORD_HAR") else None,
    )
    yield context
    await context.close()


@pytest.fixture
async def page(context: BrowserContext) -> AsyncGenerator[Page, None]:
    """Create a new page for each test."""
    page = await context.new_page()

    # Set up console logging for debugging
    def handle_console_msg(msg):
        print(f"Console {msg.type}: {msg.text}")

    page.on("console", handle_console_msg)

    # Handle page errors
    def handle_page_error(error):
        print(f"Page error: {error}")

    page.on("pageerror", handle_page_error)

    yield page
    await page.close()


@pytest.fixture
def chainlit_base_url() -> str:
    """Get the base URL for Chainlit application."""
    return os.getenv("CHAINLIT_BASE_URL", "http://localhost:8000")


@pytest.fixture
def test_user_roles():
    """Provide test user roles for parameterized testing."""
    return [
        UserRole.PSIRT,
        UserRole.DEVELOPER,
        UserRole.ACADEMIC,
        UserRole.BUG_BOUNTY,
        UserRole.PRODUCT_MANAGER,
    ]
