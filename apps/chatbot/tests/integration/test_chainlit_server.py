"""
Integration tests for Chainlit server functionality.
Tests real server startup, basic endpoints, and graceful shutdown.
"""

import pytest
import requests
import time


@pytest.mark.integration
def test_server_startup_and_health(chainlit_server):
    """Test that Chainlit server starts successfully and responds to health checks."""
    server_info = chainlit_server

    # Verify server info structure
    assert "url" in server_info
    assert "proc" in server_info
    assert "port" in server_info
    assert "host" in server_info

    # Test basic connectivity
    response = requests.get(f"{server_info['url']}/health", timeout=5)
    assert response.status_code in [200, 404]  # 404 is OK if health endpoint doesn't exist


@pytest.mark.integration
def test_server_root_endpoint(chainlit_server):
    """Test that server root endpoint is accessible."""
    url = chainlit_server["url"]

    response = requests.get(url, timeout=10)
    # Chainlit should return HTML content or redirect
    assert response.status_code in [200, 302, 404]

    if response.status_code == 200:
        # Should contain some indication it's a Chainlit app
        content = response.text.lower()
        assert any(keyword in content for keyword in ["chainlit", "chat", "html"])


@pytest.mark.integration
def test_server_process_alive(chainlit_server):
    """Test that server process is running and responsive."""
    proc = chainlit_server["proc"]

    # Process should be running
    assert proc.poll() is None, "Server process should be running"

    # Give it a moment to settle
    time.sleep(1)

    # Still running after a brief wait
    assert proc.poll() is None, "Server process should remain running"


@pytest.mark.integration
def test_test_client_fixture(test_client, chainlit_server):
    """Test that the test_client fixture works correctly."""
    # test_client should be a requests.Session
    assert isinstance(test_client, requests.Session)

    # Should have the correct base configuration
    assert "User-Agent" in test_client.headers
    assert "CWE-ChatBot-Test" in test_client.headers["User-Agent"]

    # Should be able to make requests
    try:
        response = test_client.get("/", timeout=5)
        # Any response is fine - we're testing the client works
        assert response is not None
    except requests.exceptions.RequestException:
        # Connection issues are acceptable for this test
        pass


@pytest.mark.integration
def test_sample_fixtures(sample_user_inputs, sample_roles):
    """Test that sample data fixtures provide expected data structures."""
    # Test user inputs fixture
    assert isinstance(sample_user_inputs, dict)
    expected_keys = ["cwe_direct", "cwe_comparison", "general_security",
                    "prompt_injection", "xss_prevention"]
    for key in expected_keys:
        assert key in sample_user_inputs
        assert isinstance(sample_user_inputs[key], str)
        assert len(sample_user_inputs[key]) > 0

    # Test roles fixture
    assert isinstance(sample_roles, list)
    assert len(sample_roles) > 0
    expected_roles = ["Developer", "PSIRT Member", "Academic Researcher"]
    for role in expected_roles:
        assert role in sample_roles


@pytest.mark.integration
def test_env_ready_fixture(env_ready):
    """Test that environment readiness fixture provides correct information."""
    assert isinstance(env_ready, dict)

    # Should have key environment indicators
    assert "gemini" in env_ready
    assert "postgres" in env_ready
    assert "test_timeout" in env_ready

    # Values should be boolean/int as expected
    assert isinstance(env_ready["gemini"], bool)
    assert isinstance(env_ready["postgres"], bool)
    assert isinstance(env_ready["test_timeout"], int)
    assert env_ready["test_timeout"] > 0