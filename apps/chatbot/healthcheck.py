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
        # Configurable endpoint; default to Chainlit's 8000
        url = os.getenv('HEALTHCHECK_URL', 'http://localhost:8000/health')
        # Use localhost health endpoint with timeout
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