#!/usr/bin/env python3
"""
Capture live Chainlit UI screenshots for R1 report.

Usage:
  poetry run python scripts/capture_r1_screenshots.py [BASE_URL]

Defaults BASE_URL to CHAINLIT_BASE_URL env or http://localhost:8000
Saves images under docs/stories/R1/screenshots/current/
"""

from pathlib import Path
import os
import sys
import time
from playwright.sync_api import sync_playwright


def main() -> int:
    base_url = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.getenv("CHAINLIT_BASE_URL", "http://localhost:8000")
    )

    out_dir = Path("docs/stories/R1/screenshots/current")
    out_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 800})
        page = context.new_page()

        # Navigate to app
        page.goto(base_url, timeout=30000)
        # Small settle delay
        time.sleep(1)
        page.screenshot(path=str(out_dir / "welcome.png"))

        # Try to open settings
        settings_selectors = [
            'button[aria-label*="Settings"]',
            '[data-testid="settings-button"]',
            'button:has-text("Settings")',
            'button[title*="Settings"]',
        ]
        for sel in settings_selectors:
            try:
                el = page.locator(sel).first
                if el.is_visible():
                    el.click()
                    break
            except Exception:
                continue
        time.sleep(1)
        page.screenshot(path=str(out_dir / "settings_panel.png"))

        # Submit example query
        input_selectors = [
            '[data-testid="message-input"]',
            '[placeholder*="message"], [placeholder*="question"], [placeholder*="query"]',
            'textarea',
            'input[type="text"]',
        ]
        for sel in input_selectors:
            try:
                el = page.locator(sel).first
                if el.is_visible():
                    el.fill("Explain CWE-79 for a developer")
                    el.press("Enter")
                    break
            except Exception:
                continue

        # Allow streaming
        time.sleep(3)
        page.screenshot(path=str(out_dir / "query_with_sources.png"))

        context.close()
        browser.close()

    print(f"Saved screenshots to: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

