import os

import pytest
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.getcwd(), ".env"), override=True)


@pytest.fixture(scope="session")
def base_url():
    url = os.getenv("BASE_URL")
    if not url:
        pytest.skip("BASE_URL not set")
    return url.rstrip("/")


@pytest.fixture(scope="session")
def ws_url():
    url = os.getenv("WS_URL")
    if not url:
        pytest.skip("WS_URL not set")
    return url


@pytest.fixture(scope="session")
def action_text():
    return os.getenv("ACTION_TEXT", "Ask a Question")


@pytest.fixture(scope="session")
def evil_origin():
    return "https://evil.example"
