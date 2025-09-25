"""
E2E test to verify exact CWE ID mention in the prompt prioritizes that CWE,
including flexible formats: "CWE-79", "cwe_123", "CWE 80", "cwe 33".
"""

import pytest
from playwright.sync_api import sync_playwright, expect


@pytest.mark.e2e
@pytest.mark.requires_secrets
def test_exact_cwe_id_priority(chainlit_server):
    url = chainlit_server["url"]

    scenarios = [
        ("CWE-79", "CWE-79"),
        ("cwe_123", "CWE-123"),
        ("CWE 80", "CWE-80"),
        ("cwe 33", "CWE-33"),
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Select Developer for determinism
            dev = page.locator("button:has-text('Developer')").first
            if dev.count() > 0:
                dev.click()
                page.wait_for_timeout(800)

            # Find input
            input_element = None
            for selector in ["textarea", "input[type='text']"]:
                elements = page.locator(selector)
                if elements.count() > 0 and elements.first.is_visible():
                    input_element = elements.first
                    break

            assert input_element is not None, "Chat input should be available"

            for phrase, expected in scenarios:
                # Small idle to avoid overlap
                page.wait_for_timeout(300)
                input_element.fill(f"Explain {phrase} in simple terms")
                input_element.press("Enter")
                page.wait_for_timeout(5000)

                # Prefer visible text lookup to accommodate SPA rendering
                expect(page.locator(f"text={expected}").first).to_be_visible(timeout=25000)

        finally:
            try:
                video = page.video
                if video:
                    video.save_as('test-results/videos/test_exact_cwe_id_priority.webm')
            except Exception:
                pass
            page.close()
            context.close()
            browser.close()
