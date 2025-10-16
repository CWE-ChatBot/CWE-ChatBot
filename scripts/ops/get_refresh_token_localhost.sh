#!/bin/bash
set -euo pipefail

# Kill any process using port 8080
lsof -ti:8080 | xargs kill -9 2>/dev/null || true

CLIENT_ID=$(gcloud secrets versions access latest --secret=oauth-google-client-id --project=cwechatbot)
CLIENT_SECRET=$(gcloud secrets versions access latest --secret=oauth-google-client-secret --project=cwechatbot)

# Start a simple HTTP server to catch the callback
python3 << 'PYTHON_EOF' &
import http.server
import urllib.parse
import sys

class CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if '?code=' in self.path:
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            code = params.get('code', [None])[0]

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<h1>Success!</h1><p>You can close this window.</p>')

            # Save code to file
            with open('/tmp/oauth_code.txt', 'w') as f:
                f.write(code)

            # Shutdown server
            import threading
            threading.Thread(target=self.server.shutdown).start()

    def log_message(self, format, *args):
        pass  # Suppress logs

server = http.server.HTTPServer(('localhost', 8080), CallbackHandler)
server.serve_forever()
PYTHON_EOF

SERVER_PID=$!
sleep 1

# Generate authorization URL
AUTH_URL="https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=$CLIENT_ID&redirect_uri=http://localhost:8080/&scope=openid%20email%20profile&access_type=offline&prompt=consent"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Get Google OAuth Refresh Token"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Opening browser for OAuth approval..."
echo ""
echo "If browser doesn't open, visit:"
echo "$AUTH_URL"
echo ""

# Open browser
xdg-open "$AUTH_URL" 2>/dev/null || open "$AUTH_URL" 2>/dev/null || echo "Please open the URL manually"

# Wait for callback (max 2 minutes)
echo "Waiting for OAuth approval..."
for i in {1..120}; do
    if [ -f /tmp/oauth_code.txt ]; then
        break
    fi
    sleep 1
done

# Kill server if still running
kill $SERVER_PID 2>/dev/null || true

if [ ! -f /tmp/oauth_code.txt ]; then
    echo ""
    echo "✗ Timeout waiting for OAuth approval"
    echo "Please try again"
    exit 1
fi

AUTH_CODE=$(cat /tmp/oauth_code.txt)
rm /tmp/oauth_code.txt

echo ""
echo "✓ Got authorization code"
echo "Exchanging for refresh token..."

RESPONSE=$(curl -s -X POST https://oauth2.googleapis.com/token \
  -d "code=$AUTH_CODE" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "redirect_uri=http://localhost:8080/" \
  -d "grant_type=authorization_code")

REFRESH_TOKEN=$(echo "$RESPONSE" | jq -r .refresh_token)

if [ "$REFRESH_TOKEN" != "null" ] && [ -n "$REFRESH_TOKEN" ]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  ✓ SUCCESS! Your Refresh Token:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "$REFRESH_TOKEN"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Export and test:"
    echo ""
    echo "  export GOOGLE_REFRESH_TOKEN='$REFRESH_TOKEN'"
    echo "  ./tools/test_staging_oauth.sh"
    echo ""
else
    echo ""
    echo "✗ Error getting refresh token:"
    echo "$RESPONSE" | jq .
fi
