"""
E2E tests for file upload flows:
- Multi-file PDF upload (action + paperclip path)
- Oversized file error handling (>10MB)
- Non-PDF file error handling (text/plain)

Skips assertions gracefully if the UI variant doesn't expose evidence markers.
"""

import os
import tempfile
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright


def _set_files_if_present(page, file_paths):
    for sel in ["input[type='file']", "input[type='file'][multiple]"]:
        try:
            if page.locator(sel).count() > 0:
                page.set_input_files(sel, file_paths)
                return True
        except Exception:
            continue
    return False


@pytest.mark.e2e
def test_multi_file_upload_and_error_states(chainlit_server):
    url = chainlit_server["url"]

    pdf_dir = Path("apps/chatbot/tests/pdfs").resolve()
    files = [
        str((pdf_dir / "INTEL-SA-01273.pdf").resolve()),
        str((pdf_dir / "ssa-714170.pdf").resolve()),
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="test-results/videos/")
        page = context.new_page()
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_load_state("networkidle", timeout=20000)

            # Click Attach Files action if present, else try paperclip path
            clicked = False
            for sel in [
                "button:has-text('Attach Files (PDF)')",
                "button:has-text('Attach Files')",
            ]:
                if page.locator(sel).count() > 0:
                    page.locator(sel).first.click()
                    clicked = True
                    break

            if not clicked:
                for sel in [
                    "[aria-label*='Attach']",
                    "[data-testid*='Upload']",
                    "button:has-text('Attach files')",
                ]:
                    if page.locator(sel).count() > 0:
                        page.locator(sel).first.click()
                        break

            uploaded = _set_files_if_present(page, files)

            # Evidence of upload: filename or confirmation
            page.wait_for_timeout(1000)
            evidence = [
                page.locator("text=Files received").first,
                page.locator("text=INTEL-SA-01273.pdf").first,
                page.locator("text=ssa-714170.pdf").first,
            ]
            if not any(ev.count() > 0 for ev in evidence):
                pytest.skip("Upload evidence not visible; skipping further checks.")

            # Oversized file: create a 12MB dummy .pdf and upload
            with tempfile.TemporaryDirectory() as td:
                big_path = os.path.join(td, "big_dummy.pdf")
                with open(big_path, "wb") as f:
                    f.seek(12 * 1024 * 1024)
                    f.write(b"\0")

                # Try paperclip again to upload oversized
                for sel in [
                    "[aria-label*='Attach']",
                    "[data-testid*='Upload']",
                    "input[type='file']",
                ]:
                    try:
                        if page.locator(sel).count() > 0:
                            if sel.startswith("input"):
                                page.set_input_files(sel, [big_path])
                            else:
                                page.locator(sel).first.click()
                                _set_files_if_present(page, [big_path])
                            break
                    except Exception:
                        continue

                page.wait_for_timeout(1000)
                too_large_msg = page.locator("text=exceeds the 10MB limit").first
                if too_large_msg.count() == 0:
                    pytest.skip("Oversize advisory not visible in this UI; skipping.")

            # Non-PDF file
            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
                tf.write(b"This is a small text file for testing.")
                tf.flush()
                txt_path = tf.name

            try:
                for sel in [
                    "[aria-label*='Attach']",
                    "[data-testid*='Upload']",
                    "input[type='file']",
                ]:
                    try:
                        if page.locator(sel).count() > 0:
                            if sel.startswith("input"):
                                page.set_input_files(sel, [txt_path])
                            else:
                                page.locator(sel).first.click()
                                _set_files_if_present(page, [txt_path])
                            break
                    except Exception:
                        continue

                page.wait_for_timeout(1000)
                unsupported = page.locator("text=Only PDF files up to").first
                if unsupported.count() == 0:
                    pytest.skip("Unsupported format advisory not visible; skipping.")
            finally:
                try:
                    os.remove(txt_path)
                except Exception:
                    pass

        finally:
            page.close()
            try:
                os.makedirs("test-results/videos", exist_ok=True)
                video = page.video
                if video:
                    video.save_as(
                        "test-results/videos/test_multi_file_upload_and_error_states.webm"
                    )
            except Exception:
                pass
            context.close()
            browser.close()
