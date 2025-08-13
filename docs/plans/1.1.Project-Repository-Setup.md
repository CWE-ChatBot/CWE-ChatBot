# Epic 1.1 Implementation Plan: Project Repository Setup

## Overview
This plan outlines the step-by-step implementation of the foundational repository structure for the CWE ChatBot project. This is a critical first step that will enable all subsequent development work.

## Pre-Implementation Checklist
- [ ] Verify access to CWE-ChatBot GitHub organization
- [ ] Confirm repository naming conventions with team
- [ ] Review monorepo strategy with architecture team
- [ ] Ensure development tools are installed (Python 3.10+, Poetry/PDM, Git)

## Implementation Steps

### Phase 1: Repository Initialization (Estimated: 30 minutes)

#### Step 1.1: Create Repository Structure
```bash
# Create new repository on GitHub (if not already created)
# Repository: CWE-ChatBot/CWE-ChatBot (already exists)

# Clone and set up local development
git clone git@github.com:CWE-ChatBot/CWE-ChatBot.git
cd CWE-ChatBot
```

#### Step 1.2: Initialize Monorepo Structure
```bash
# Create monorepo directory structure
mkdir -p apps/chatbot
mkdir -p apps/chatbot/src
mkdir -p apps/chatbot/tests
mkdir -p shared/utils
mkdir -p docs/api
mkdir -p scripts
```

### Phase 2: Configuration Files (Estimated: 45 minutes)

#### Step 2.1: Create pyproject.toml (Root Level)
```toml
[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"

[tool.poetry]
name = "cwe-chatbot"
version = "0.1.0"
description = "CWE ChatBot - Conversational AI for Common Weakness Enumeration"
authors = ["CWE-ChatBot Team"]
packages = [
    {include = "chatbot", from = "apps/chatbot/src"},
    {include = "shared", from = "."},
]

[tool.poetry.dependencies]
python = "^3.10"
# Core dependencies will be added in subsequent stories

[tool.poetry.group.dev.dependencies]
pytest = "^7.4.0"
pytest-cov = "^4.1.0"
black = "^23.0.0"
ruff = "^0.0.284"
mypy = "^1.5.0"

[tool.black]
line-length = 88
target-version = ['py310']

[tool.ruff]
select = ["E", "F", "I", "N", "W"]
ignore = []
line-length = 88
target-version = "py310"

[tool.mypy]
python_version = "3.10"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true

[tool.pytest.ini_options]
testpaths = ["apps/chatbot/tests", "shared/tests"]
python_files = ["test_*.py", "*_test.py"]
addopts = "--cov=apps/chatbot/src --cov=shared --cov-report=html --cov-report=term"
```

#### Step 2.2: Create Comprehensive .gitignore
```gitignore
# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# PyInstaller
*.manifest
*.spec

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
.hypothesis/
.pytest_cache/

# Virtual environments
venv/
env/
ENV/

# Environment variables
.env
.env.local
.env.*.local

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Logs
logs/
*.log

# Temporary files
tmp/
temp/
.tmp/

# Docker
.dockerignore

# Cloud deployment
.gcloudignore

# Application specific
data/
models/
embeddings/
vector_db/
```

#### Step 2.3: Create .env.example
```bash
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/cwe_chatbot
VECTOR_DB_URL=
VECTOR_DB_API_KEY=

# LLM Configuration
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GOOGLE_AI_API_KEY=

# Application Configuration
CHAINLIT_HOST=0.0.0.0
CHAINLIT_PORT=8000
LOG_LEVEL=INFO

# Security
SECRET_KEY=
OAUTH_CLIENT_ID=
OAUTH_CLIENT_SECRET=

# Cloud Configuration (GCP)
GOOGLE_CLOUD_PROJECT=
GCP_SERVICE_ACCOUNT_KEY=

# Monitoring
SENTRY_DSN=
```

### Phase 3: Documentation (Estimated: 30 minutes)

#### Step 3.1: Create Comprehensive README.md
```markdown
# CWE ChatBot

A conversational AI application designed to revolutionize interaction with the MITRE Common Weakness Enumeration (CWE) corpus.

## Overview

The CWE ChatBot enables cybersecurity professionals to interact with CWE data through natural language conversations, providing contextual, role-based responses for vulnerability analysis and prevention.

## Quick Start

### Prerequisites
- Python 3.10 or higher
- Poetry (recommended) or pip
- Git

### Installation

1. Clone the repository:
   ```bash
   git clone git@github.com:CWE-ChatBot/CWE-ChatBot.git
   cd CWE-ChatBot
   ```

2. Install dependencies:
   ```bash
   poetry install
   ```

3. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. Run the application (when available):
   ```bash
   poetry run chainlit run apps/chatbot/main.py
   ```

## Architecture

This project uses a monorepo structure:

```
CWE-ChatBot/
├── apps/
│   └── chatbot/           # Main Chainlit application
│       ├── src/
│       └── tests/
├── shared/                # Shared utilities and libraries
├── docs/                  # Project documentation
├── scripts/               # Utility scripts
├── pyproject.toml         # Project configuration
└── README.md
```

## Development

### Code Quality
- **Formatting**: Black (line length: 88)
- **Linting**: Ruff
- **Type Checking**: MyPy
- **Testing**: Pytest with coverage

### Running Tests
```bash
poetry run pytest
```

### Code Formatting
```bash
poetry run black .
poetry run ruff check .
```

## Security

This project implements security-first development practices:
- Branch protection on main branch
- Required code reviews
- Comprehensive security testing
- Input validation and sanitization

## Contributing

1. Create a feature branch from `main`
2. Make your changes following our code standards
3. Add tests for new functionality
4. Submit a pull request

## Project Status

🚧 **In Development** - Foundation phase

## License

[License information to be added]

## Contact

[Contact information to be added]
```

### Phase 4: Security Configuration (Estimated: 15 minutes)

#### Step 4.1: Configure Branch Protection Rules
```bash
# This will be done via GitHub web interface or API:
# - Require pull request reviews before merging
# - Require at least 1 approval
# - Dismiss stale reviews when new commits are pushed
# - Require status checks to pass before merging
# - Restrict pushes to main branch
```

### Phase 5: Initial Commit and Verification (Estimated: 15 minutes)

#### Step 5.1: Commit Initial Structure
```bash
git add .
git commit -m "Initial commit: project structure setup

- Add monorepo structure with apps/chatbot directory
- Configure Poetry for Python monorepo management
- Add comprehensive .gitignore for Python projects
- Add .env.example with configuration templates
- Add detailed README.md with setup instructions
- Configure development tools (Black, Ruff, MyPy, Pytest)

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>"

git push origin main
```

#### Step 5.2: Verification Steps
- [ ] Verify repository structure is created correctly
- [ ] Test `poetry install` works without errors
- [ ] Verify branch protection rules are active
- [ ] Test that direct pushes to main are blocked
- [ ] Confirm all files are properly committed

## Success Criteria

✅ **Repository Setup Complete When:**
- [ ] Monorepo structure is established
- [ ] pyproject.toml is configured for Poetry
- [ ] README.md provides clear setup instructions
- [ ] .gitignore covers all Python/development artifacts
- [ ] .env.example documents all required environment variables
- [ ] Branch protection is enabled on main branch
- [ ] Initial commit is pushed successfully
- [ ] Repository is ready for subsequent development stories

## Time Estimation
- **Total Estimated Time:** 2.25 hours
- **Critical Path:** Repository initialization → Configuration → Documentation → Security setup
- **Dependencies:** None (this is the foundational story)

## Risk Mitigation
- **Risk:** Branch protection conflicts with existing setup
  - **Mitigation:** Review current repository settings before implementing
- **Risk:** Poetry configuration conflicts
  - **Mitigation:** Test configuration in a separate branch first
- **Risk:** Environment variable exposure
  - **Mitigation:** Ensure .env is in .gitignore before any commits

## Next Steps After Completion
- Epic 1.2: Basic Chainlit Application Deployment to Cloud Run
- Security Story S-1: API Rate Limiting and Budget Monitoring (parallel track)