Robust pre-test helper (Python, with proper google-auth refresh)

Your conceptual snippet is close—creds.refresh() needs a Request object, and we should add solid error handling + CI-friendly output.

File: tools/pretest_get_id_token.py

#!/usr/bin/env python3
import os, sys, json
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError

def die(msg, code=1):
    print(json.dumps({"ok": False, "error": msg}), file=sys.stderr)
    sys.exit(code)

def main():
    try:
        CLIENT_ID = os.environ["GOOGLE_WEB_CLIENT_ID"]
        CLIENT_SECRET = os.environ["GOOGLE_WEB_CLIENT_SECRET"]
        REFRESH_TOKEN = os.environ["GOOGLE_REFRESH_TOKEN"]
    except KeyError as e:
        die(f"missing_env:{e.args[0]}")

    # Scopes include 'openid' to ensure Google returns an ID token
    creds = Credentials(
        token=None,
        refresh_token=REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scopes=["openid", "email", "profile"],
    )

    try:
        creds.refresh(Request())
    except RefreshError as e:
        # Common causes: revoked/expired refresh token, wrong client/secret
        die(f"refresh_error:{getattr(e, 'args', [''])[0]}")
    except Exception as e:
        die(f"unexpected:{e!r}")

    if not getattr(creds, "id_token", None):
        # Very rare, but be explicit so CI fails loudly if no ID token present
        die("no_id_token_returned")

    # Print in machine-readable way; do NOT log the token elsewhere
    # 1) Raw line, easy to capture: ID_TOKEN=...
    print(f"ID_TOKEN={creds.id_token}")

    # 2) Optional JSON output if you prefer parsing in CI:
    # print(json.dumps({"ok": True, "id_token": creds.id_token}))

if __name__ == "__main__":
    main()


Usage in Bash (generic CI):

# Secrets from your CI secret store:
export GOOGLE_WEB_CLIENT_ID=...
export GOOGLE_WEB_CLIENT_SECRET=...
export GOOGLE_REFRESH_TOKEN=...

ID_TOKEN="$(
  python3 tools/pretest_get_id_token.py | awk -F= '/^ID_TOKEN=/{print $2}'
)"
[ -n "$ID_TOKEN" ] || { echo "Failed to obtain ID token"; exit 1; }

# Mask in CI logs if supported (example: GitHub Actions)
echo "::add-mask::$ID_TOKEN" 2>/dev/null || true

# Use it
curl -s -X POST "https://staging-cwe.crashedmind.com/api/v1/query" \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"What is CWE-79?","persona":"DEVELOPER"}' | jq .


GitHub Actions snippet:

- name: Get Google ID token
  run: |
    echo "Fetching ID token..."
    ID_TOKEN=$(python3 tools/pretest_get_id_token.py | awk -F= '/^ID_TOKEN=/{print $2}')
    [ -n "$ID_TOKEN" ]
    echo "::add-mask::$ID_TOKEN"
    echo "ID_TOKEN=$ID_TOKEN" >> "$GITHUB_ENV"
  env:
    GOOGLE_WEB_CLIENT_ID: ${{ secrets.GOOGLE_WEB_CLIENT_ID }}
    GOOGLE_WEB_CLIENT_SECRET: ${{ secrets.GOOGLE_WEB_CLIENT_SECRET }}
    GOOGLE_REFRESH_TOKEN: ${{ secrets.GOOGLE_REFRESH_TOKEN }}

- name: Call API with Bearer token
  run: |
    curl -sS -X POST "$API_BASE/api/v1/query" \
      -H "Authorization: Bearer $ID_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"query":"What is CWE-79?"}' | jq .
  env:
    API_BASE: https://staging-cwe.crashedmind.com


Notes

The ID token appears because you originally consented with openid scope and received a refresh token tied to OIDC.

If you ever rotate the refresh token, update the secret; the script stays the same.

2) Lightweight back-end observability (fast win)

Add a tiny counter on ID-token verification failures so you immediately see CI breakage (revoked token, audience mismatch, etc.):

Log fields: event=auth_verify_failed, provider=google, reason=<…>, client_id=<last 6>, env=staging, path=/api/v1/query.

Optional metric: auth.verify_failures{provider="google",env="staging"}.

Consider a simple alert: spike over baseline in 5–10 minutes.

3) Safety guardrails recap

Don’t log tokens/device codes. Mask in CI where possible.

Enforce audience allow-list (your web client ID; include device client only if you still allow device flow).

Enforce iss in {"https://accounts.google.com","accounts.google.com"}, email_verified=true, and check exp.

Keep staging vs prod clients/tokens separate.

Rate-limit by sub (preferred) or verified email.

This keeps your “simple & same” story intact: every caller—browser or CI—presents Authorization: Bearer <id_token>, your Chainlit-mounted API verifies the same way, and tests are fully automated.