"""
R1 Screenshots Capture (Playwright)

Captures live screenshots from the running Chainlit app for the R1 progress report:
- Welcome screen
- Settings panel
- Example query with streamed response (and sources if present)

Usage:
- Ensure the app is running (e.g., apps/chatbot/start_chatbot.sh --with-db --headless)
- Run: poetry run pytest tests/ui/test_capture_r1_screenshots.py -q
Screenshots will be written under docs/stories/R1/screenshots/current/
"""

import asyncio
import os
from pathlib import Path
import pytest
from playwright.async_api import Page

import sys
from pathlib import Path as _P
_THIS_DIR = _P(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

from utils.chainlit_helpers import ChainlitTestHelper, setup_test_environment
from utils.screenshot_helpers import ScreenshotHelper


@pytest.mark.asyncio
async def test_capture_r1_screenshots(page: Page, chainlit_base_url: str):
    # Ensure output directory exists
    base_dir = Path("docs/stories/R1/screenshots")
    base_dir.mkdir(parents=True, exist_ok=True)

    # Use a screenshot helper that writes under docs/stories/R1/screenshots
    shots = ScreenshotHelper(base_screenshot_dir=str(base_dir))

    # Navigate and wait for app to be ready
    helper = await setup_test_environment(page, chainlit_base_url)

    # Capture welcome/landing
    await shots.capture_viewport_screenshot(page, "welcome")

    # Try to open the settings panel (best-effort across possible selectors)
    settings_selectors = [
        'button[aria-label*="Settings"]',
        '[data-testid="settings-button"]',
        'button:has-text("Settings")',
        'button[title*="Settings"]',
    ]
    opened = False
    for sel in settings_selectors:
        try:
            locator = page.locator(sel).first
            if await locator.is_visible():
                await locator.click()
                opened = True
                break
        except Exception:
            continue

    # Give the settings panel time to render if opened
    await asyncio.sleep(1 if opened else 0.2)

    # Capture settings panel state (full page for reliability)
    await shots.capture_screenshot(page, "settings_panel", full_page=True)

    # Submit a representative query and wait for streamed response
    await helper.submit_message("Explain CWE-79 for a developer", wait_for_response=True)

    # Allow a short time for sources/side elements to appear
    await asyncio.sleep(2)

    # Capture the resulting chat state
    await shots.capture_screenshot(page, "query_with_sources", full_page=True)

    # Optionally mark these as baseline for later comparisons
    shots.save_as_baseline("welcome")
    shots.save_as_baseline("settings_panel")
    shots.save_as_baseline("query_with_sources")
