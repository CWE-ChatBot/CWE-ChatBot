#!/usr/bin/env python3
import os, sys, json, signal
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError

# Add timeout handler
def timeout_handler(signum, frame):
    print("ERROR: Token refresh timed out after 30 seconds", file=sys.stderr)
    print("This usually means:", file=sys.stderr)
    print("  1. Network connectivity issue", file=sys.stderr)
    print("  2. Google OAuth API is unreachable", file=sys.stderr)
    print("  3. Firewall blocking requests", file=sys.stderr)
    sys.exit(1)

def die(msg, code=1):
    print(json.dumps({"ok": False, "error": msg}), file=sys.stderr)
    sys.exit(code)

def main():
    try:
        print("DEBUG: Reading environment variables...", file=sys.stderr)
        CLIENT_ID = os.environ["GOOGLE_WEB_CLIENT_ID"]
        CLIENT_SECRET = os.environ["GOOGLE_WEB_CLIENT_SECRET"]
        REFRESH_TOKEN = os.environ["GOOGLE_REFRESH_TOKEN"]
        print(f"DEBUG: Got CLIENT_ID (length={len(CLIENT_ID)}), CLIENT_SECRET (length={len(CLIENT_SECRET)}), REFRESH_TOKEN (length={len(REFRESH_TOKEN)})", file=sys.stderr)
    except KeyError as e:
        die(f"missing_env:{e.args[0]}")

    # Scopes include 'openid' to ensure Google returns an ID token
    print("DEBUG: Creating Credentials object...", file=sys.stderr)
    creds = Credentials(
        token=None,
        refresh_token=REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scopes=["openid", "email", "profile"],
    )

    try:
        print("DEBUG: Attempting token refresh (calling Google OAuth API)...", file=sys.stderr)
        # Set 30 second timeout
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(30)

        creds.refresh(Request())

        # Cancel timeout
        signal.alarm(0)
        print("DEBUG: Token refresh successful!", file=sys.stderr)
    except RefreshError as e:
        signal.alarm(0)  # Cancel timeout
        # Common causes: revoked/expired refresh token, wrong client/secret
        die(f"refresh_error:{getattr(e, 'args', [''])[0]}")
    except Exception as e:
        signal.alarm(0)  # Cancel timeout
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
