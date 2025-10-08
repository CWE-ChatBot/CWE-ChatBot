"""
Repository structure validation tests.

Following TDD methodology - these tests define the required repository structure
and should FAIL initially, then PASS after implementation.
"""

from pathlib import Path


def test_monorepo_structure_exists():
    """Test that all required directories exist."""
    required_dirs = [
        "apps/chatbot",
        "apps/chatbot/src",
        "apps/chatbot/tests",
        "shared/utils",
        "shared/tests",
        "docs/api",
        "scripts",
        ".github/workflows",
    ]

    for directory in required_dirs:
        assert Path(
            directory
        ).exists(), f"Required directory {directory} does not exist"


def test_test_structure_exists():
    """Test that test directories have __init__.py files."""
    test_init_files = [
        "tests/__init__.py",
        "tests/integration/__init__.py",
        "tests/unit/__init__.py",
        "apps/chatbot/tests/__init__.py",
        "shared/tests/__init__.py",
    ]

    for init_file in test_init_files:
        assert Path(
            init_file
        ).exists(), f"Required __init__.py file {init_file} does not exist"


def test_git_repository_initialized():
    """Test that Git repository is properly initialized."""
    assert Path(".git").exists(), "Git repository must be initialized"

    # Check for remote origin
    import subprocess

    result = subprocess.run(["git", "remote", "-v"], capture_output=True, text=True)
    assert "origin" in result.stdout, "Git remote 'origin' must be configured"


def test_current_directory_is_project_root():
    """Test that we're in the correct project directory."""
    # Should have key project files
    expected_files = ["CLAUDE.md", "docs/architecture.md", "docs/prd.md"]

    for file_path in expected_files:
        assert Path(file_path).exists(), f"Expected project file {file_path} not found"
