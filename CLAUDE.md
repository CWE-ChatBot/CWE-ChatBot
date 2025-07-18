# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains the **CWE ChatBot** project - a conversational AI application designed to revolutionize interaction with the MITRE Common Weakness Enumeration (CWE) corpus. The project aims to shift from static search and browse experiences to dynamic, interactive conversational interfaces for cybersecurity professionals.

### Key Project Goals
- Enable efficient vulnerability advisory creation for PSIRT members
- Provide contextual CWE mapping assistance for developers
- Support academic research and bug bounty analysis
- Facilitate proactive weakness identification for product managers
- Deliver accurate, role-based CWE information without AI hallucination

## Repository Structure

This is a **documentation-heavy project** currently in the planning phase. The repository follows a structured approach with comprehensive documentation driving development:

```
cwe_chatbot_bmad/
├── docs/                    # Core project documentation
│   ├── architecture.md      # Complete technical architecture (Python/Chainlit-based)
│   ├── prd.md              # Product Requirements Document with user stories
│   ├── project-brief.md    # Executive summary and problem statement
│   ├── ui_ux.md           # UI/UX specifications
│   └── *_review.md        # Review documents for each phase
├── web-bundles/            # BMad-Method AI agent framework
│   ├── agents/            # Specialized AI agents (analyst, architect, dev, etc.)
│   └── teams/             # Agent team configurations
└── notes.md               # Development notes and references
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

This project is currently in planning phase. Once implementation begins, these commands will be relevant:

### Setup and Environment
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies (when available)
pip install -r requirements.txt
# Or using Poetry
poetry install
```

### Running the Application
```bash
# Start Chainlit application (future)
chainlit run apps/chatbot/main.py

# With hot reload for development
chainlit run apps/chatbot/main.py -w
```

### Testing
```bash
# Run all tests
pytest

# Run specific test directory
pytest apps/chatbot/tests/

# Run with coverage
pytest --cov=apps/chatbot
```

### Code Quality
```bash
# Format code
black .

# Lint with Ruff
ruff check .

# Type checking
mypy .
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

## Files to Reference

- `docs/architecture.md`: Complete technical specifications and API designs
- `docs/prd.md`: Detailed functional and non-functional requirements
- `docs/project-brief.md`: High-level project vision and user personas
- `web-bundles/agents/`: BMad-Method AI agents for development assistance