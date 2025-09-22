"""Test configuration for apps/tests.
Ensures local package imports (src.*) resolve without installation.
"""

import sys
from pathlib import Path


def pytest_sessionstart(session):
    # Add apps/chatbot to sys.path so that `src.*` imports resolve
    repo_root = Path(__file__).resolve().parents[2]
    chat_src = repo_root / "apps" / "chatbot"
    if str(chat_src) not in sys.path:
        sys.path.insert(0, str(chat_src))

