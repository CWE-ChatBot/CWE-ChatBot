# CWE ChatBot

A conversational AI application designed to revolutionize interaction with the MITRE Common Weakness Enumeration (CWE) corpus.

## Overview

The CWE ChatBot enables cybersecurity professionals to interact with CWE data through natural language conversations, providing contextual, role-based responses for vulnerability analysis and prevention.

## Project Documentation

The following documents were created in order during the project planning phase:

| Order | Document | Review | Description |
|-------|----------|---------|-------------|
| 1 | [docs/project-brief.md](docs/project-brief.md) | inline | Executive summary and problem statement defining the project vision and user personas |
| 2 | [docs/prd.md](docs/prd.md) | [docs/prd_review.md](docs/prd_review.md) | Detailed functional and non-functional requirements with user stories |
| 3 | [docs/ui_ux.md](docs/ui_ux.md) | inline | User interface and user experience design specifications |
| 4 | [docs/architecture.md](docs/architecture.md) | [docs/architecture_review.md](docs/architecture_review.md) | Complete technical architecture and system design |
| 5 | [docs/product_owner_review.md](docs/product_owner_review.md) | - | Final product owner review and approval |

## Pre-existing Documentation

| Category | Document | Description |
|----------|----------|-------------|
| Cost Analysis | [docs/costs.md](docs/costs.md) | Project cost breakdown and analysis |
| Architecture Decision Records | [docs/ADR/](docs/ADR/) | Technical decisions and rationale |
| Research Documents | [docs/research/](docs/research/) | Security research and guardrails analysis |

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

- ✅ Project Brief completed
- ✅ Comprehensive PRD with user stories and NFRs
- ✅ Complete technical architecture designed
- ✅ UI/UX specifications defined
- ✅ Repository structure established
- 🔄 Implementation phase

## License

[License information to be added]

## Contact

[Contact information to be added]