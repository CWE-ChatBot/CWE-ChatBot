"""
Configuration validation tests.

Following TDD methodology - these tests define the required configuration
and should FAIL initially, then PASS after implementation.
"""

from pathlib import Path

import toml


def test_pyproject_toml_valid():
    """Test that pyproject.toml is valid TOML and has required sections."""
    pyproject_path = Path("pyproject.toml")
    assert pyproject_path.exists(), "pyproject.toml must exist"

    config = toml.load(pyproject_path)

    # Required sections
    assert "tool" in config
    assert "poetry" in config["tool"]
    assert "dependencies" in config["tool"]["poetry"]
    assert "python" in config["tool"]["poetry"]["dependencies"]

    # Python version requirement
    python_version = config["tool"]["poetry"]["dependencies"]["python"]
    assert "^3.10" in python_version or ">=3.10" in python_version


def test_pyproject_has_dev_dependencies():
    """Test that pyproject.toml has required development dependencies."""
    pyproject_path = Path("pyproject.toml")
    assert pyproject_path.exists(), "pyproject.toml must exist"

    config = toml.load(pyproject_path)

    # Required dev dependencies
    dev_deps = config["tool"]["poetry"]["group"]["dev"]["dependencies"]
    required_dev_deps = ["pytest", "black", "ruff", "mypy", "pytest-cov"]

    for dep in required_dev_deps:
        assert dep in dev_deps, f"Missing required dev dependency: {dep}"


def test_pyproject_has_monorepo_structure():
    """Test that pyproject.toml is configured for monorepo."""
    pyproject_path = Path("pyproject.toml")
    config = toml.load(pyproject_path)

    # Should have packages configuration for monorepo
    assert (
        "packages" in config["tool"]["poetry"]
    ), "Monorepo packages configuration required"

    # Project metadata
    assert "name" in config["tool"]["poetry"]
    assert "version" in config["tool"]["poetry"]
    assert "description" in config["tool"]["poetry"]


def test_tool_configurations_present():
    """Test that tool configurations are present."""
    pyproject_path = Path("pyproject.toml")
    config = toml.load(pyproject_path)

    # Required tool configurations
    required_tools = ["black", "ruff", "mypy", "pytest"]

    for tool in required_tools:
        assert tool in config["tool"], f"Missing tool configuration: {tool}"
