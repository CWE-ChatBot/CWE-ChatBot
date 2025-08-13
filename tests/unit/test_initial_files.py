"""
Initial files validation tests.

Following TDD methodology - these tests define the required initial files
and should FAIL initially, then PASS after implementation.
"""

from pathlib import Path


def test_gitignore_comprehensive():
    """Test that .gitignore covers all required patterns."""
    gitignore_path = Path(".gitignore")
    assert gitignore_path.exists(), ".gitignore must exist"
    
    content = gitignore_path.read_text()
    
    required_patterns = [
        "__pycache__/",
        "*.py[cod]",
        ".env",
        ".vscode/",
        "venv/",
        ".pytest_cache/",
        "htmlcov/",
        "*.egg-info/",
        "dist/",
        "build/",
        ".coverage"
    ]
    
    for pattern in required_patterns:
        assert pattern in content, f"Missing required .gitignore pattern: {pattern}"


def test_env_example_comprehensive():
    """Test that .env.example contains all required variables."""
    env_example_path = Path(".env.example")
    assert env_example_path.exists(), ".env.example must exist"
    
    content = env_example_path.read_text()
    
    required_vars = [
        "DATABASE_URL",
        "CHAINLIT_HOST",
        "CHAINLIT_PORT",
        "SECRET_KEY",
        "LOG_LEVEL",
        "OPENAI_API_KEY",
        "GOOGLE_CLOUD_PROJECT"
    ]
    
    for var in required_vars:
        assert var in content, f"Missing required environment variable: {var}"


def test_readme_exists_and_comprehensive():
    """Test that README.md exists and has required content."""
    readme_path = Path("README.md")
    assert readme_path.exists(), "README.md must exist"
    
    content = readme_path.read_text()
    
    # Required sections
    required_sections = [
        "# CWE ChatBot",
        "## Overview",
        "## Quick Start",
        "## Installation",
        "## Architecture",
        "## Development"
    ]
    
    for section in required_sections:
        assert section in content, f"Missing required README section: {section}"


def test_readme_has_setup_instructions():
    """Test that README has proper setup instructions."""
    readme_path = Path("README.md")
    content = readme_path.read_text()
    
    # Should mention key commands
    required_instructions = [
        "poetry install",
        "git clone",
        ".env.example",
        "pytest"
    ]
    
    for instruction in required_instructions:
        assert instruction in content, f"Missing setup instruction: {instruction}"