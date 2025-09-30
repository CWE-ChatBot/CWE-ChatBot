#!/usr/bin/env python3
"""
Secure health check script for CWE ChatBot
Provides safe health check without command injection risks
"""

import sys
import os
import urllib.request
import urllib.error

def main():
    """Perform health check on the Chainlit application."""
    try:
        # Chainlit doesn't have built-in /health endpoint, check root page
        port = os.getenv('CHAINLIT_PORT', '8080')
        url = f'http://localhost:{port}/'
        # Use localhost root endpoint with timeout
        with urllib.request.urlopen(url, timeout=5) as response:
            if response.status == 200:
                sys.exit(0)  # Healthy
            else:
                sys.exit(1)  # Unhealthy status code
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        # Any connection error indicates unhealthy service
        sys.exit(1)

if __name__ == "__main__":
    main()