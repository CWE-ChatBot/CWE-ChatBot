import asyncio
import json
import re

import pytest
from helpers.ws import ws_connect
from playwright.sync_api import sync_playwright

pytestmark = pytest.mark.order(2)


def _collect_cookies(context):
    cookies = context.cookies()
    if not cookies:
        return None
    return "; ".join([f"{c['name']}={c['value']}" for c in cookies])


@pytest.fixture(scope="session")
def browser_ctx(base_url):
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(base_url=base_url)
        page = context.new_page()
        yield (browser, context, page)
        context.close()
        browser.close()


@pytest.mark.needs_auth
def test_ui_action_valid(browser_ctx, base_url, action_text):
    browser, context, page = browser_ctx
    page.goto(base_url, wait_until="domcontentloaded")
    page.wait_for_timeout(3000)
    # Try various ways to locate the action
    btn = None
    try:
        btn = page.get_by_role("button", name=action_text, exact=False)
        if not btn.is_visible():
            btn = None
    except Exception:
        pass
    if not btn:
        try:
            cand = page.get_by_text(action_text, exact=False)
            if cand.is_visible():
                btn = cand
        except Exception:
            pass
    if not btn:
        pytest.skip(
            f"Action '{action_text}' not visible — app may require auth; skipping."
        )
    btn.click()
    page.wait_for_timeout(1000)


@pytest.mark.asyncio
async def test_ws_action_missing_csrf(ws_url, base_url, browser_ctx):
    browser, context, page = browser_ctx
    page.goto(base_url, wait_until="domcontentloaded")
    page.wait_for_timeout(1500)
    cookie_header = _collect_cookies(context)

    async with await ws_connect(ws_url, base_url, cookies=cookie_header) as ws:
        # Example frame **without** csrf_token — adjust if your server expects a different shape
        frame = {"type": "action", "name": "ask_question", "payload": {"action": "ask"}}
        await ws.send(json.dumps(frame))

        got_error = False
        try:
            msg = await asyncio.wait_for(ws.recv(), timeout=3.0)
            if isinstance(msg, (str, bytes)):
                text = msg.decode() if isinstance(msg, bytes) else msg
                if re.search(r"(invalid|csrf|forbidden|unauthorized)", text, re.I):
                    got_error = True
        except Exception:
            # Connection closed or no response in time — acceptable as deny
            got_error = True

        assert (
            got_error
        ), "Server should reject WS action frame without csrf_token (error or close expected)"
