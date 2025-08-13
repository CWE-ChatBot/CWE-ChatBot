"""
Security configuration tests.

Following TDD methodology - these tests validate security controls
are properly configured for the repository.
"""

from pathlib import Path


def test_no_secrets_in_code():
    """Test that no secrets are committed to the repository."""
    # This test will run after initial commit
    dangerous_patterns = [
        "api_key",
        "secret_key", 
        "password",
        "token",
        "sk-",  # OpenAI API key prefix
        "xoxb-", # Slack token prefix
    ]
    
    # Check all Python files for dangerous patterns
    python_files = list(Path(".").rglob("*.py"))
    
    for file_path in python_files:
        if ".venv" in str(file_path) or "__pycache__" in str(file_path):
            continue
            
        content = file_path.read_text().lower()
        for pattern in dangerous_patterns:
            assert f'"{pattern}"' not in content and f"'{pattern}'" not in content, \
                f"Potential secret found in {file_path}: {pattern}"


def test_env_file_not_committed():
    """Test that .env file is not committed."""
    assert not Path(".env").exists() or Path(".env").stat().st_size == 0, \
        ".env file should not be committed or should be empty"


def test_gitignore_prevents_secrets():
    """Test that .gitignore prevents common secret files."""
    gitignore_content = Path(".gitignore").read_text()
    secret_patterns = [".env", "*.key", "*.pem", "secrets/"]
    
    for pattern in secret_patterns:
        assert pattern in gitignore_content, f"Missing .gitignore pattern for secrets: {pattern}"


def test_pyproject_toml_has_no_secrets():
    """Test that pyproject.toml doesn't contain hardcoded secrets."""
    pyproject_path = Path("pyproject.toml")
    if pyproject_path.exists():
        content = pyproject_path.read_text().lower()
        dangerous_patterns = ["password", "secret", "api_key", "token"]
        
        for pattern in dangerous_patterns:
            assert pattern not in content, f"Potential secret found in pyproject.toml: {pattern}"


def test_security_documentation_exists():
    """Test that security documentation is present."""
    readme_content = Path("README.md").read_text()
    assert "security" in readme_content.lower(), "Security documentation should be present"
    
    # Verify security practices are documented
    security_terms = ["security testing", "code reviews", "validation"]
    has_security_practices = any(term in readme_content.lower() for term in security_terms)
    assert has_security_practices, "Security practices should be documented"
