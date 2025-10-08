"""
Security configuration tests.

Following TDD methodology - these tests validate security controls
are properly configured for the repository.
"""

from pathlib import Path


def test_env_file_not_committed():
    """Test that .env file is not committed."""
    assert (
        not Path(".env").exists() or Path(".env").stat().st_size == 0
    ), ".env file should not be committed or should be empty"


def test_gitignore_prevents_secrets():
    """Test that .gitignore prevents common secret files."""
    gitignore_content = Path(".gitignore").read_text()
    secret_patterns = [".env", "*.key", "*.pem", "secrets/"]

    for pattern in secret_patterns:
        assert (
            pattern in gitignore_content
        ), f"Missing .gitignore pattern for secrets: {pattern}"


def test_security_documentation_exists():
    """Test that security documentation is present."""
    readme_content = Path("README.md").read_text()
    assert (
        "security" in readme_content.lower()
    ), "Security documentation should be present"

    # Verify security practices are documented
    security_terms = ["security testing", "code reviews", "validation"]
    has_security_practices = any(
        term in readme_content.lower() for term in security_terms
    )
    assert has_security_practices, "Security practices should be documented"
