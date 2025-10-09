# Python Security Harness for Chainlit (Cloud Run + LB)

This harness provides **pytest** tests in Python to verify:
- WebSocket same-origin vs cross-origin handshake behavior (Cloud Armor / LB rules)
- Chainlit UI action flow in a real browser (Playwright for Python)
- CSRF enforcement for **server-received actions/messages** over WS
- Basic CSP header checks on initial HTML

## Prereqs

- Python 3.10+
- `pip install -r requirements.txt`
- Install browser engines for Playwright:
  ```bash
  python -m playwright install --with-deps
  ```

## Environment Variables

Create a `.env` (see `.env.example`) or export these variables:

- `BASE_URL`   — e.g., `https://cwe.crashedmind.com`
- `WS_URL`     — e.g., `wss://cwe.crashedmind.com/ws`
- `ACTION_TEXT`— visible label of your Chainlit action button (default: "Ask a Question")
- `OAUTH_EMAIL`/`OAUTH_PASS` — *optional mock creds if your app has a simple test login page; otherwise tests that require UI auth are skipped*

You can set them inline:
```bash
export BASE_URL="https://cwe.crashedmind.com"
export WS_URL="wss://cwe.crashedmind.com/ws"
export ACTION_TEXT="Ask a Question"
```

## Running

```bash
pip install -r requirements.txt
python -m playwright install --with-deps
pytest -v
# or headed
pytest -v --headed
```

## What the tests do

- **tests/test_ws.py**
  - `test_ws_same_origin_allows` — opens WS with `Origin: BASE_URL` → should connect.
  - `test_ws_cross_origin_denies` — opens WS with `Origin: https://evil.example` → should fail (403/handshake error).

- **tests/test_actions_csrf.py**
  - Browser clicks the visible action (valid, in-app path).
  - Opens a raw WS with same cookies and **sends an action frame without `csrf_token`** → expect server to close or send an error.

- **tests/test_csp_headers.py**
  - Fetches `GET /` and asserts CSP headers are present if you configured them at LB. Skips if header missing to avoid false negatives in early setup.

> Notes:
> - If OAuth screens appear, UI tests will **skip** unless you supply a way for non-interactive login.
> - Adjust `WS_FRAME_ACTION` shape to match your app’s expected WS message payload if needed.
