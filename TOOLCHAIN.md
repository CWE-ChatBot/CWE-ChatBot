# Python Toolchain

This document describes the Python development toolchain used in the CWE ChatBot project, including versions and configurations.

## Overview

The project uses a modern Python toolchain optimized for code quality, type safety, and developer productivity:

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.12.3 | Runtime and development |
| Poetry | 1.8.2 | Dependency management and packaging |
| pip | 24.0 | Package installer (used by Poetry) |
| Ruff | 0.6.9 | Fast linting and code formatting (Rust-based) |
| Black | 23.12.1 | Opinionated code formatter |
| Mypy | 1.17.1 | Static type checking |
| Pydantic | 2.11.7 | Data validation and settings management |

## Tool Purposes

### Python 3.12.3
**Purpose**: Language runtime and standard library

**Key Features Used**:
- Type hints with generics (PEP 585)
- Structural pattern matching
- Dataclasses for configuration
- AsyncIO for concurrent operations
- Context managers for resource management

**Installation**:
```bash
# Ubuntu/Debian
sudo apt install python3.12 python3.12-venv python3.12-dev

# Verify
python3 --version
```

### Poetry 1.8.2
**Purpose**: Dependency management, virtual environment management, and packaging

**Why Poetry**:
- Deterministic builds with poetry.lock
- Simpler dependency resolution than pip
- Built-in virtual environment management
- pyproject.toml standard configuration
- Workspace support for monorepos

**Installation**:
```bash
curl -sSL https://install.python-poetry.org | python3 -

# Verify
poetry --version
```

**Key Commands**:
```bash
# Install dependencies
poetry install

# Run command in virtual environment
poetry run python script.py
poetry run pytest
poetry run chainlit run apps/chatbot/main.py

# Add dependency
poetry add package-name

# Update dependencies
poetry update

# Show installed packages
poetry show --tree
```

**Configuration** (pyproject.toml):
```toml
[tool.poetry]
name = "cwe-chatbot"
version = "1.0.0"
description = "AI-powered CWE analysis chatbot"
python = "^3.10"

[tool.poetry.dependencies]
python = "^3.10"
pydantic = "^2.11.7"
# ... other dependencies

[tool.poetry.group.dev.dependencies]
ruff = "^0.6.9"
black = "^23.12.1"
mypy = "^1.17.1"
pytest = "^7.4.4"
```

### Ruff 0.6.9
**Purpose**: Extremely fast Python linter and code formatter (Rust-based)

**Why Ruff**:
- 10-100x faster than other Python linters
- Replaces Flake8, isort, pydocstyle, and more
- Built-in auto-fix for many rules
- Can also format code (alternative to Black)
- Native type-aware linting

**Key Features**:
- Linting: Enforces code style rules
- Formatting: Fast code formatter (Black-compatible)
- Import sorting: Organizes imports
- Error codes: Pyflakes (F), pycodestyle (E/W), isort (I), etc.

**Usage**:
```bash
# Lint code
poetry run ruff check .

# Auto-fix issues
poetry run ruff check --fix .

# Format code (alternative to Black)
poetry run ruff format .

# Check specific directory
poetry run ruff check apps/chatbot/src/
```

**Configuration** (pyproject.toml or ruff.toml):
```toml
[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = [
    "E",   # pycodestyle errors
    "W",   # pycodestyle warnings
    "F",   # pyflakes
    "I",   # isort
    "B",   # flake8-bugbear
    "S",   # flake8-bandit (security)
    "C4",  # flake8-comprehensions
]
ignore = [
    "E501",  # line too long (handled by formatter)
]

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S101"]  # Allow assert in tests
```

### Black 23.12.1
**Purpose**: Opinionated code formatter ("The Uncompromising Code Formatter")

**Why Black**:
- Zero configuration philosophy
- Consistent formatting across projects
- Eliminates formatting debates
- Fast and deterministic
- Industry standard

**Key Features**:
- Formats code to consistent style
- Line length: 88 characters (default)
- PEP 8 compliant with some opinions
- Preserves AST (code semantics unchanged)

**Usage**:
```bash
# Format code
poetry run black .

# Check without modifying
poetry run black --check .

# Format specific files
poetry run black apps/chatbot/src/
```

**Configuration** (pyproject.toml):
```toml
[tool.black]
line-length = 88
target-version = ['py312']
include = '\.pyi?$'
extend-exclude = '''
/(
  # Exclude directories
  \.git
  | \.venv
  | build
  | dist
)/
'''
```

**Note**: Ruff's formatter can replace Black. Choose one:
- **Black**: More mature, zero config philosophy
- **Ruff format**: Faster, Black-compatible, integrated with linting

### Mypy 1.17.1
**Purpose**: Static type checker for Python

**Why Mypy**:
- Catches type errors before runtime
- Improves code documentation via types
- Better IDE autocomplete and refactoring
- Industry standard for Python type checking
- Gradual typing (can adopt incrementally)

**Key Features**:
- Static analysis of type hints
- Detects type mismatches
- Validates function signatures
- Checks generic types
- Plugin system (e.g., Pydantic plugin)

**Usage**:
```bash
# Type check entire project
poetry run mypy .

# Check specific files
poetry run mypy apps/chatbot/src/

# Generate HTML report
poetry run mypy --html-report mypy-report .
```

**Configuration** (pyproject.toml or mypy.ini):
```toml
[tool.mypy]
python_version = "3.12"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_any_unimported = false
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_no_return = true
check_untyped_defs = true
plugins = ["pydantic.mypy"]

[[tool.mypy.overrides]]
module = "tests.*"
disallow_untyped_defs = false
```

### Pydantic 2.11.7
**Purpose**: Data validation and settings management using Python type hints

**Why Pydantic**:
- Runtime validation of data structures
- Type-safe configuration management
- JSON Schema generation
- Fast performance (Rust core)
- Excellent error messages

**Key Features**:
- BaseModel for data classes with validation
- Settings management from environment variables
- Automatic type coercion
- Custom validators
- JSON serialization/deserialization

**Usage Example**:
```python
from pydantic import BaseModel, Field, validator

class Config(BaseModel):
    """Application configuration."""

    pg_host: str = Field(default="localhost")
    pg_port: int = Field(default=5432, ge=1, le=65535)
    max_instances: int = Field(default=10, ge=1)

    @validator('pg_host')
    def validate_host(cls, v):
        if not v:
            raise ValueError('Host cannot be empty')
        return v

# Usage
config = Config(pg_host="10.43.0.3", pg_port=5432)
print(config.pg_host)  # Type-safe access
```

**Settings Management**:
```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """Load settings from environment variables."""

    postgres_host: str
    postgres_port: int = 5432
    gemini_api_key: str

    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()  # Loads from .env automatically
```

## Tool Integration Workflow

### 1. Three-Tool Approach (Recommended)

Use all three tools for maximum code quality:

```bash
# 1. Format code (Black)
poetry run black .

# 2. Lint and auto-fix (Ruff)
poetry run ruff check --fix .

# 3. Type check (Mypy)
poetry run mypy .
```

**Why all three?**
- **Ruff**: Fast linting, catches common code issues, import sorting
- **Black**: Consistent formatting (or use `ruff format` instead)
- **Mypy**: Type safety, catches type-related bugs

### 2. Alternative: Ruff-Only Formatting

Use Ruff for both linting and formatting:

```bash
# 1. Format code (Ruff)
poetry run ruff format .

# 2. Lint and auto-fix (Ruff)
poetry run ruff check --fix .

# 3. Type check (Mypy)
poetry run mypy .
```

**Advantage**: One less tool, slightly faster

### 3. Pre-commit Hook Integration

Automate quality checks with git hooks:

```bash
# .git/hooks/pre-commit
#!/bin/bash
set -e

echo "Running code quality checks..."

# Format
poetry run black . || exit 1

# Lint
poetry run ruff check --fix . || exit 1

# Type check
poetry run mypy . || exit 1

echo "✓ All checks passed"
```

Make executable:
```bash
chmod +x .git/hooks/pre-commit
```

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Code Quality

on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'

      - name: Install Poetry
        run: curl -sSL https://install.python-poetry.org | python3 -

      - name: Install dependencies
        run: poetry install

      - name: Check formatting (Black)
        run: poetry run black --check .

      - name: Lint (Ruff)
        run: poetry run ruff check .

      - name: Type check (Mypy)
        run: poetry run mypy .

      - name: Run tests
        run: poetry run pytest
```

## Development Workflow

### Daily Development
```bash
# 1. Make code changes
vim apps/chatbot/src/secrets.py

# 2. Format
poetry run black apps/chatbot/src/secrets.py

# 3. Lint
poetry run ruff check --fix apps/chatbot/src/secrets.py

# 4. Type check
poetry run mypy apps/chatbot/src/secrets.py

# 5. Test
poetry run pytest apps/chatbot/tests/unit/test_secrets.py

# 6. Commit
git add apps/chatbot/src/secrets.py
git commit -m "Add Secret Manager integration"
```

### IDE Integration

**VS Code** (settings.json):
```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.ruffEnabled": true,
  "python.linting.mypyEnabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  }
}
```

**PyCharm**:
- Settings → Tools → Black → Enable
- Settings → Tools → External Tools → Add Ruff
- Settings → Python Integrated Tools → Type Checker: Mypy

## Upgrade Strategy

### Check for Updates
```bash
# Show outdated packages
poetry show --outdated

# Check specific tool
poetry show ruff
```

### Upgrade Tools
```bash
# Upgrade specific tool
poetry update ruff

# Upgrade all dev dependencies
poetry update --only dev

# Upgrade Poetry itself
poetry self update
```

### Breaking Changes to Watch

**Ruff 1.0** (upcoming):
- API changes in configuration format
- New default rules

**Pydantic 2.x** (current):
- Different from Pydantic 1.x API
- Rust core for performance
- Settings moved to pydantic-settings package

**Mypy**:
- Stricter type checking in newer versions
- May require additional type annotations

## Troubleshooting

### Common Issues

**Poetry not found**:
```bash
# Add Poetry to PATH
export PATH="$HOME/.local/bin:$PATH"
```

**Ruff/Black conflict**:
```bash
# Ensure line-length matches
[tool.ruff]
line-length = 88  # Match Black's default

[tool.black]
line-length = 88
```

**Mypy cache issues**:
```bash
# Clear cache
poetry run mypy --clear-cache .
```

**Type stub missing**:
```bash
# Install type stubs
poetry add --group dev types-requests
```

## Best Practices

1. **Run tools in order**: Format → Lint → Type check
2. **Fix type errors immediately**: Don't accumulate technical debt
3. **Use strict mode**: Enable strict Mypy checking for new code
4. **Review Ruff output**: Don't blindly accept auto-fixes
5. **Keep tools updated**: Check monthly for updates
6. **Configure in pyproject.toml**: Single source of configuration
7. **Document deviations**: If you ignore a rule, comment why

## Resources

- **Python**: https://docs.python.org/3.12/
- **Poetry**: https://python-poetry.org/docs/
- **Ruff**: https://docs.astral.sh/ruff/
- **Black**: https://black.readthedocs.io/
- **Mypy**: https://mypy.readthedocs.io/
- **Pydantic**: https://docs.pydantic.dev/

## Project-Specific Notes

### Current Setup
- No pyproject.toml in project root (yet)
- Tools installed via Poetry in virtual environment
- Configuration currently implicit (using defaults)

### TODO
- [ ] Create pyproject.toml with tool configurations
- [ ] Add pre-commit hooks
- [ ] Configure CI/CD pipeline with quality checks
- [ ] Document project-specific Ruff/Mypy rules
