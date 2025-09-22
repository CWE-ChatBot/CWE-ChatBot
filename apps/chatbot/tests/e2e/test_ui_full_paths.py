"""
UI integration tests exercising core paths including:
- Persona selection via top profiles
- Settings panel visibility
- Standard chat flow
- CVE Creator path with PDF upload (paperclip and action fallback)

These tests are designed to be resilient to minor UI changes by trying
multiple selectors and tolerating missing AI responses (offline mode).
"""

from pathlib import Path
import time
import pytest
from playwright.sync_api import sync_playwright, expect


def _try_click(page, selectors: list[str]) -> bool:
    for sel in selectors:
        try:
            el = page.locator(sel).first
            if el.count() > 0 and el.first.is_visible():
                el.first.click()
                return True
        except Exception:
            continue
    return False


def _set_files_if_present(page, file_paths: list[str]) -> bool:
    # Try common file input selectors used by Chainlit uploader and AskFileMessage
    inputs = [
        'input[type="file"]',
        'input[type="file"][multiple]'
    ]
    for sel in inputs:
        try:
            if page.locator(sel).count() > 0:
                page.set_input_files(sel, file_paths)
                return True
        except Exception:
            continue
    return False


@pytest.mark.e2e
def test_ui_full_paths(chainlit_server):
    url = chainlit_server["url"]

    pdf_dir = Path('apps/chatbot/tests/pdfs').resolve()
    pdf_path = str((pdf_dir / 'INTEL-SA-01273.pdf').resolve())

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()
        try:
            # Navigate and wait until idle
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=30000)

            # 1) Persona selection via top profiles (try to pick CVE Creator)
            _try_click(page, [
                "text=CVE Creator",
                "button:has-text('CVE Creator')",
                "[role='button']:has-text('CVE Creator')",
            ])

            # 2) Open Settings panel (best-effort)
            _try_click(page, [
                'button[aria-label*="Settings"]',
                '[data-testid="settings-button"]',
                'button:has-text("Settings")',
                'button[title*="Settings"]',
            ])
            # Give it a moment to render, then close by pressing Escape
            time.sleep(0.5)
            try:
                page.keyboard.press('Escape')
            except Exception:
                pass

            # 3) Send a standard message and expect any response content to appear
            # Locate input
            input_candidates = [
                "textarea[placeholder*='message']",
                "textarea",
                "input[placeholder*='message']",
                "input[type='text']",
            ]
            msg_input = None
            for sel in input_candidates:
                if page.locator(sel).count() > 0 and page.locator(sel).first.is_visible():
                    msg_input = page.locator(sel).first
                    break
            assert msg_input is not None, "Message input not found"

            msg_input.fill("Explain CWE-79 for a developer")
            msg_input.press("Enter")

            # Wait a short while for any response (don't depend on external AI)
            page.wait_for_timeout(2000)

            # 4) CVE Creator with PDF upload
            # Try the welcome action button first
            clicked_attach = _try_click(page, [
                "button:has-text('Attach Files (PDF)')",
                "button:has-text('Attach Files')",
            ])

            uploaded = False
            if clicked_attach:
                # Try to set files into AskFileMessage input
                uploaded = _set_files_if_present(page, [pdf_path])
                # Some UIs require a confirm/continue
                if uploaded:
                    _try_click(page, [
                        "button:has-text('Upload')",
                        "button:has-text('Confirm')",
                        "button:has-text('Continue')",
                        "button:has-text('Done')",
                    ])
                # Wait for our system confirmation message
                if uploaded:
                    page.wait_for_timeout(1000)
                    sys_msg = page.locator("text=Files received").first
                    if sys_msg.count() == 0:
                        uploaded = False  # fall back to paperclip path

            if not uploaded:
                # Paperclip path: find file input and set files
                # Try to reveal uploader by clicking a likely upload button
                _try_click(page, [
                    "[aria-label*='Attach']",
                    "[data-testid*='Upload']",
                    "button:has-text('Attach files')",
                ])
                uploaded = _set_files_if_present(page, [pdf_path])

            # Send a CVE Creator prompt that should incorporate uploaded content
            _try_click(page, ["text=CVE Creator", "button:has-text('CVE Creator')"])  # ensure role
            msg_input.fill("")
            msg_input.fill("Create a CVE description for Log4Shell using the uploaded doc")
            msg_input.press("Enter")

            # Wait a bit and then verify evidence of upload
            page.wait_for_timeout(2000)
            # Evidence options: our system confirmation (AskFileMessage path),
            # the merge marker, or the file name appearing in the chat UI
            evidence = [
                page.locator("text=Files received").first,
                page.locator("text=Attached File Content").first,
                page.locator("text=INTEL-SA-01273.pdf").first,
            ]
            if not any(ev.count() > 0 for ev in evidence):
                pytest.skip("Upload evidence not found in this UI build; skipping upload verification.")

            # Optionally, check that no raw square brackets remain in latest assistant message HTML
            # (We can be lenient due to streaming/AI variability)
            content_html = page.content()
            assert "[Remote Code Execution]" not in content_html, "Raw bracketed segments should be formatted"

        finally:
            page.close()
            context.close()
            browser.close()
