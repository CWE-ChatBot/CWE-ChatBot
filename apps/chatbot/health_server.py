#!/usr/bin/env python3
"""
Simple health check server for Cloud Run health checks.
Runs alongside Chainlit on a different port to provide dedicated health endpoint.
"""

import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

# Import availability flag for optional app health integration
# Health detail integration flag
HEALTH_CHECK_AVAILABLE = True


class HealthHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler for health checks."""

    def do_GET(self):  # noqa: N802 (required by BaseHTTPRequestHandler)
        """Handle GET requests to health endpoint."""
        if self.path == "/health" or self.path == "/healthz":
            self.send_health_response()
        else:
            self.send_404()

    def send_health_response(self):
        """Send health check response."""
        try:
            health_data = {
                "status": "healthy",
                "timestamp": time.time(),
                "service": "cwe-chatbot",
            }

            # If we can access the conversation manager, get detailed health
            if HEALTH_CHECK_AVAILABLE and hasattr(self.server, "conversation_manager"):
                cm = self.server.conversation_manager  # type: ignore[attr-defined]
                if cm:
                    health_data.update(cm.get_system_health())

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(health_data).encode())

        except Exception:
            # If anything fails, still return a basic healthy response
            # Cloud Run health checks just need 200 status
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "healthy", "note": "basic check"}')

    def send_404(self):
        """Send 404 response."""
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        """Suppress default logging to avoid noise."""
        pass


def start_health_server(port=8081, conversation_manager=None):
    """Start health check server in background thread."""
    try:
        # Bind to 0.0.0.0 for Cloud Run container accessibility
        server = HTTPServer(("0.0.0.0", port), HealthHandler)  # nosec B104
        server.conversation_manager = conversation_manager  # type: ignore[attr-defined]

        def run_server():
            print(f"Health server starting on port {port}")
            server.serve_forever()

        thread = Thread(target=run_server, daemon=True)
        thread.start()
        return server
    except Exception as e:
        print(f"Failed to start health server: {e}")
        return None


if __name__ == "__main__":
    # For testing the health server standalone
    port = int(os.getenv("HEALTH_PORT", 8081))
    server = start_health_server(port)
    if server:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            server.shutdown()
