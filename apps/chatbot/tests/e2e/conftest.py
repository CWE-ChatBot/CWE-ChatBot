"""
Pytest configuration for E2E tests using puppeteer.

Provides fixtures for puppeteer MCP tools.
"""

import pytest
import asyncio


@pytest.fixture
def mcp__puppeteer__puppeteer_navigate():
    """Fixture for puppeteer navigate tool."""
    from mcp__puppeteer__puppeteer_navigate import navigate
    return navigate


@pytest.fixture
def mcp__puppeteer__puppeteer_screenshot():
    """Fixture for puppeteer screenshot tool."""
    from mcp__puppeteer__puppeteer_screenshot import screenshot
    return screenshot


@pytest.fixture
def mcp__puppeteer__puppeteer_click():
    """Fixture for puppeteer click tool."""
    from mcp__puppeteer__puppeteer_click import click
    return click


@pytest.fixture
def mcp__puppeteer__puppeteer_fill():
    """Fixture for puppeteer fill tool."""
    from mcp__puppeteer__puppeteer_fill import fill
    return fill


@pytest.fixture
def mcp__puppeteer__puppeteer_evaluate():
    """Fixture for puppeteer evaluate tool."""
    from mcp__puppeteer__puppeteer_evaluate import evaluate
    return evaluate


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
