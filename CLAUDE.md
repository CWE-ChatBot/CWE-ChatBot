# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains the **CWE ChatBot** project - a conversational AI application designed to revolutionize interaction with the MITRE Common Weakness Enumeration (CWE) corpus. The project aims to shift from static search and browse experiences to dynamic, interactive conversational interfaces for cybersecurity professionals.

**Current Status**: Planning and Documentation Phase - Ready for implementation

### Key Project Goals
- Enable efficient vulnerability advisory creation for PSIRT members
- Provide contextual CWE mapping assistance for developers
- Support academic research and bug bounty analysis
- Facilitate proactive weakness identification for product managers
- Deliver accurate, role-based CWE information without AI hallucination

## Repository Structure

This is a **documentation-driven project** that follows BMad-Method principles. The comprehensive documentation drives all development decisions:

```
cwe_chatbot_bmad/
├── docs/                    # Core project documentation (READ FIRST)
│   ├── architecture/        # Detailed architecture breakdown
│   │   ├── tech-stack.md           # Definitive technology selections and versions
│   │   ├── development-workflow.md # Local setup and development commands
│   │   ├── unified-project-structure.md # Future monorepo structure
│   │   ├── database-schema.md      # PostgreSQL and vector DB schemas
│   │   ├── rest-api-spec.md        # Complete API specifications
│   │   └── security.md             # Security architecture and requirements
│   ├── prd/                 # Product Requirements breakdown
│   │   ├── user-stories.md         # Detailed user stories with acceptance criteria
│   │   ├── requirements.md         # Functional and non-functional requirements
│   │   └── epic-*.md              # Development epics and story groupings
│   ├── security/            # Comprehensive security analysis
│   │   ├── bmad_fullagent_security/ # Complete security assessment
│   │   ├── threat_model_*.md       # Multiple threat modeling approaches
│   │   └── attack_tree.md          # Attack surface analysis
│   ├── stories/             # Individual user stories for implementation
│   └── plans/               # Implementation planning documents
├── scripts/                 # Python utility scripts (mostly for documentation processing)
├── web-bundles/            # BMad-Method AI agent framework
│   ├── agents/            # Specialized AI agents (analyst, architect, dev, etc.)
│   └── teams/             # Agent team configurations
└── tmp*/                   # Temporary working directories
```

## Architecture Overview

Based on the comprehensive architecture document, this project will be built as:

### Technology Stack
- **Primary Language**: Python 3.10+
- **Framework**: Chainlit (integrated web UI + backend)
- **Database**: PostgreSQL (traditional data) + Vector Database (CWE embeddings)
- **Cloud Platform**: Google Cloud Platform (GCP) with Cloud Run
- **Architecture Pattern**: RAG (Retrieval Augmented Generation)

### Key Components
1. **Chainlit Application**: Main conversational interface and backend logic
2. **NLP/AI Service**: RAG implementation for CWE corpus interaction
3. **Vector Database**: CWE embeddings for semantic search (Pinecone/Weaviate)
4. **Traditional Database**: User data, conversations, configurations
5. **Data Ingestion Pipeline**: CWE corpus processing and updating

## Development Commands

**Current Phase**: Documentation and Planning - No code implementation yet.

**Key Reference**: See `docs/architecture/development-workflow.md` for complete setup instructions when implementation begins.

### Future Development Commands (from architecture docs)
When implementation starts, these will be the primary commands:

```bash
# Project setup (Poetry-based monorepo)
poetry install                                    # Install all dependencies
gcloud auth login                                # Authenticate with GCP

# Development
poetry run chainlit run apps/chatbot/main.py -w  # Start with hot-reload
poetry run pytest                               # Run all tests
poetry run pytest apps/chatbot/tests/           # Test specific app

# Data processing
poetry run python services/cwe_data_ingestion/ingestion.py --local-dev

# Code quality
black .                                         # Format code
ruff check .                                    # Lint
mypy .                                         # Type checking

# Container builds
docker build -t cwe-chatbot-app apps/chatbot/  # Build Docker image
```

### Script Utilities
```bash
# Process documentation (existing scripts)
python3 scripts/process_chat_precise.py        # Format chat conversations
python3 scripts/update_chat_admonitions.py     # Add GitHub admonitions
```

## Key Development Patterns

### 1. Retrieval Augmented Generation (RAG)
The core architecture uses RAG to minimize AI hallucination:
- User queries are embedded and searched against CWE corpus
- Retrieved relevant CWE content augments LLM prompts
- Responses are grounded in official CWE documentation

### 2. Role-Based Context Adaptation
The system adapts responses based on user roles:
- **PSIRT Members**: Focus on impact assessment and advisory language
- **Developers**: Emphasize remediation steps and code examples
- **Academic Researchers**: Provide comprehensive analysis and relationships
- **Bug Bounty Hunters**: Highlight exploitation patterns and reporting
- **Product Managers**: Enable trend analysis and prevention strategies

### 3. Multi-Database Architecture
- **PostgreSQL**: Users, conversations, messages, configurations
- **Vector Database**: CWE embeddings for semantic search
- **Repository Pattern**: Abstracted data access across both databases

### 4. Bring Your Own (BYO) Model Support
- Support for user-provided LLM API keys
- Integration with self-hosted LLM models
- Flexible model configuration for different deployment scenarios

## Security Considerations

This project handles sensitive security information and must maintain strict security standards:

### Data Handling
- **No hardcoded secrets**: All credentials via environment variables or secret management
- **Input validation**: Rigorous validation to prevent injection attacks
- **Data privacy**: Secure handling of user queries and vulnerability information
- **Self-hosted deployments**: Ensure data never leaves user's domain

### Authentication & Authorization
- **OAuth 2.0/OpenID Connect**: Passwordless authentication
- **Role-based access control**: Based on user's cybersecurity role
- **Session management**: Secure token-based sessions

### AI Safety
- **Hallucination prevention**: RAG pattern with source citations
- **Confidence scoring**: Clear indicators of response reliability
- **Feedback mechanisms**: User reporting of incorrect mappings

## Current Project Status

**Phase**: Planning and Documentation
- ✅ Project Brief completed
- ✅ Comprehensive PRD with user stories and NFRs
- ✅ Complete technical architecture designed
- ✅ UI/UX specifications defined
- 🔄 Ready for implementation phase

## Next Steps for Implementation

1. **Repository Setup**: Initialize Python project structure
2. **Core Infrastructure**: Set up Chainlit application with basic UI
3. **Data Pipeline**: Implement CWE corpus ingestion and vector database setup
4. **RAG Implementation**: Build core NLP/AI service with embedding and retrieval
5. **User Management**: Implement authentication and role-based access
6. **Testing**: Comprehensive testing including security validation

## BMad-Method Integration

This project uses the BMad-Method framework for AI-driven development:
- **Specialized AI Agents**: PM, Architect, Developer, QA agents with specific roles
- **Structured Workflows**: Proven patterns from planning to deployment
- **Document-Driven Development**: PRD and architecture guide implementation
- **Agile Integration**: Clean handoffs between planning and development phases

### Key BMad Agents Available
- `analyst`: Business analysis and requirements gathering
- `pm`: Product management and PRD creation
- `architect`: System design and technical architecture
- `dev`: Code implementation and debugging
- `qa`: Testing and quality assurance
- `bmad-orchestrator`: Multi-agent coordination

## Important Notes

- This is a **defensive security project** - focused on vulnerability analysis and prevention
- The project emphasizes **accuracy and reliability** over feature completeness
- **User privacy and data security** are paramount concerns
- The system must handle **sensitive vulnerability information** appropriately
- Implementation will follow **security-first development practices**

## Essential Documentation to Read First

When working on this project, always start with these key documents:

### Architecture & Technical Design
- `docs/architecture.md`: Comprehensive fullstack architecture with C4 diagrams
- `docs/architecture/tech-stack.md`: **Definitive technology choices and versions** - ALL development must follow these selections
- `docs/architecture/development-workflow.md`: Local setup, environment vars, development commands
- `docs/architecture/unified-project-structure.md`: Future monorepo structure for implementation
- `docs/architecture/database-schema.md`: PostgreSQL and vector database schemas
- `docs/architecture/rest-api-spec.md`: Complete API specifications

### Product Requirements & Business Logic  
- `docs/prd.md`: Master PRD with functional/non-functional requirements
- `docs/prd/user-stories.md`: Detailed user stories with acceptance criteria
- `docs/prd/requirements.md`: All FR/NFR requirements with IDs for traceability

### Security Architecture (Critical for this project)
- `docs/security/bmad_fullagent_security/`: Complete security assessment and test cases
- `docs/security/threat_model_stride/`: STRIDE-based threat modeling
- `docs/architecture/security.md`: Security architecture requirements

### Implementation Planning
- `docs/stories/`: Individual implementation stories (1.1.*, 1.2.*, etc.)
- `docs/plans/`: Implementation planning documents

### BMad-Method Agent Framework
- `web-bundles/agents/`: Specialized AI agents for different development roles
- `web-bundles/teams/`: Pre-configured agent teams for different task types

## Critical Implementation Guidelines

### Technology Stack Compliance
**MUST READ**: `docs/architecture/tech-stack.md` contains definitive technology selections including specific versions. All code must use:
- Python 3.10+
- Chainlit (latest stable 0.7.x) for UI and backend
- PostgreSQL 14.x via Cloud SQL
- Pinecone for vector database (or self-hosted alternative)
- Poetry for dependency management
- Google Cloud Platform (GCP) with Cloud Run deployment

### Security-First Development
This is a **defensive security project** handling sensitive vulnerability data:
- Never hardcode secrets - use environment variables exclusively
- Follow OWASP guidelines for AI security (documented in security/)
- Implement comprehensive input validation and sanitization
- All features require security review before implementation
- RAG pattern is mandatory to prevent AI hallucination

### Documentation-Driven Development
- ALL features must be traced back to specific PRD requirements (FR/NFR IDs)
- User stories in `docs/stories/` provide acceptance criteria for implementation
- Architecture decisions are binding and documented in `docs/architecture/`
- Security requirements are non-negotiable (see `docs/security/`)

### Environment Configuration
When implementation begins, environment setup follows `docs/architecture/development-workflow.md`:
- Use `.env.example` as template for local `.env` file
- GCP authentication required: `gcloud auth login`
- Poetry-based monorepo with workspace dependencies
- All secrets via GCP Secret Manager in production

### Testing Requirements
- Unit tests: pytest with comprehensive coverage
- Integration tests: API endpoint testing
- E2E tests: Playwright for Chainlit UI flows  
- Security tests: SAST, DAST, and LLM security validation
- All tests must pass before any deployment