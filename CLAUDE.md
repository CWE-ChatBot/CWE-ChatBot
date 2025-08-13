# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.


# CLAUDE.md 

**Prefer blunt honesty over sycophancy. Please explain issues and solution as if I'm a junior developer.**


## CRITICAL: GIT Commit
  - Start with a present-tense verb (Fix, Add, Implement, etc.)
  - Not include adjectives that sound like praise (comprehensive, best practices, essential)
  - Be concise (60-120 characters)
  - Be a single line
  - Sound like the title of the issue we resolved, and not include the implementation details we learned during implementation
  - End with a period.
  - Describe the intent of the original prompt
- Commit messages should not include a Claude attribution footer
  - Don't write: 🤖 Generated with [Claude Code](https://claude.ai/code)
  - Don't write: Co-Authored-By: Claude <noreply@anthropic.com>
- Echo exactly this: Ready to commit: `git commit --message "<message>"`
- 🚀 Run git commit without confirming again with the user.
- If pre-commit hooks fail, then there are now local changes
  - `git add` those changes and try again
  - Never use `git commit --no-verify`



## CRITICAL: Virtual Environment Usage
**ALWAYS use the project's virtual environment for ALL Python commands:**
- pytest: Use `/home/bj/python/REI-Tracker/venv/bin/pytest` (NOT `/home/bj/.local/bin/pytest`)
- python: Use `/home/bj/python/REI-Tracker/venv/bin/python` (NOT system python)
- pip: Use `/home/bj/python/REI-Tracker/venv/bin/pip` (NOT system pip)

**NEVER use system-wide Python executables.**

## Core Development Principles

### 1. Brutal Honesty First
- **NO MOCKS**: Never create mock data, placeholder functions, or simulated responses
- **NO THEATER**: If something doesn't work, say it immediately - don't pretend with elaborate non-functional code
- **REALITY CHECK**: Before implementing anything, verify the actual integration points exist and work
- **ADMIT IGNORANCE**: If you don't understand how something works, investigate first or ask for clarification

### 2. Test-Driven Development (TDD) - MANDATORY
**NEVER write implementation code before tests.**

#### TDD Process for Every Story Implementation:
1. **BEFORE ANY IMPLEMENTATION**:
   - Create test file FIRST (e.g., `test_feature_name.py`)
   - Write the FIRST failing test for the simplest behavior
   - Run the test with `/home/bj/python/REI-Tracker/venv/bin/pytest` and VERIFY it fails
   - Only then write MINIMAL implementation code to pass

2. **RED-GREEN-REFACTOR Cycle**:
   - 🔴 RED: Write a failing test that defines the feature
   - 🟢 GREEN: Write minimal code to make the test pass
   - 🔵 REFACTOR: Clean up only after tests are green
   - **Never skip the red-green-refactor cycle**

3. **Story Implementation Order**:
   ```
   1. Read story requirements
   2. Break down into small testable behaviors
   3. Create test file
   4. Write first failing test
   5. Run test (see it fail) - use venv/bin/pytest
   6. Implement minimal code
   7. Run test (see it pass) - use venv/bin/pytest
   8. Refactor if needed
   9. Repeat 4-9 for next behavior
   ```

#### TDD Example - How to Start Every Story:
```python
# STEP 1: Create test file FIRST
# test_loan_configuration.py

def test_can_create_loan_configuration():
    """Test creating a basic loan configuration."""
    # This test MUST fail first because LoanConfiguration doesn't exist yet
    loan = LoanConfiguration(
        loan_number=1,
        amount=100000,
        interest_rate=6.5,
        term_months=360
    )
    assert loan.loan_number == 1

# STEP 2: Run test - see it fail with "NameError: name 'LoanConfiguration' is not defined"
# ALWAYS use: /home/bj/python/REI-Tracker/venv/bin/pytest test_loan_configuration.py

# STEP 3: Create minimal implementation to pass
# loan_configuration.py
class LoanConfiguration:
    def __init__(self, loan_number, amount, interest_rate, term_months):
        self.loan_number = loan_number

# STEP 4: Run test - see it pass
# STEP 5: Write next failing test for next behavior
```

#### What Makes a Good TDD Test:
1. **Tests behavior, not implementation** - Test WHAT it does, not HOW
2. **One assertion per test** - Each test verifies ONE thing
3. **Descriptive test names** - `test_loan_with_zero_interest_rate_calculates_zero_interest()`
4. **Arrange-Act-Assert pattern** - Setup, Execute, Verify
5. **Fast and isolated** - No external dependencies, runs in milliseconds
6. **Fails for the right reason** - Verify the error message when test fails

### 3. One Feature at a Time
- **SINGLE FOCUS**: Complete one feature entirely before moving to the next
- **DEFINITION OF DONE**:
  - Tests written and passing
  - Code working in real environment
  - Integration verified with actual system
  - Documentation updated
- **NO FEATURE CREEP**: Resist adding "nice to have" additions until current feature is complete

### 4. Break Things Internally
- **FAIL FAST**: Make code fail immediately when assumptions are wrong
- **AGGRESSIVE VALIDATION**: Check every input, every integration point
- **LOUD ERRORS**: When something breaks, make it obvious with clear error messages
- **TEST EDGE CASES**: Deliberately try to break your own code before calling it done

### 5. Optimization After Working
- **MAKE IT WORK**: First priority is functioning code
- **MAKE IT RIGHT**: Clean up and refactor with tests as safety net
- **MAKE IT FAST**: Only optimize after profiling shows real bottlenecks
- **MEASURE FIRST**: Never optimize based on assumptions

## Implementation Checklist

### Before starting any feature:
- [ ] Understand the ACTUAL integration (not what you think it should be)
- [ ] Write tests that verify real behavior (not mocked behavior)
- [ ] Identify all dependencies and verify they exist
- [ ] Check if similar code exists to learn from

### During implementation:
- [ ] Run tests frequently (every few lines of code)
- [ ] Test in real environment, not just unit tests
- [ ] When stuck, investigate the actual system, don't guess
- [ ] Keep changes small and focused

### After implementation:
- [ ] Verify it works with the real system (no mocks!)
- [ ] Run all related tests
- [ ] Update documentation with what ACTUALLY works
- [ ] Clean up any experimental code

## CRITICAL DOCUMENTATION WORKFLOW

### During Story Implementation:
1. **START of each story**: 
   - Add an entry to `/docs/CURATION_NOTES.md` with story ID
   - Create TodoWrite list with TDD tasks:
     - [ ] Create test file for first feature
     - [ ] Write first failing test
     - [ ] Run test and see it fail
     - [ ] Implement minimal code to pass
     - [ ] Refactor if needed
     - [ ] Write next failing test
   - See bmad-agent/personas.sm.ide.md personal for documentation workflow responsibilities

2. **DURING implementation**: 
   - Document key decisions and technical debt in CURATION_NOTES.md
   - Mark each TDD cycle in TodoWrite as completed

3. **AFTER completing implementation**: Before marking story as done, update CURATION_NOTES.md with:
   - Final decisions made
   - Technical debt incurred
   - Lessons learned
   - Architectural notes

### After Epic/Feature Completion:
1. **EXTRACT** insights from CURATION_NOTES.md to:
   - `/docs/LESSONS_LEARNED.md` - Add dated entries with tags
   - `/docs/README.md` - Update if architecture changed
   - `/docs/TASKS.md` - Add new maintenance tasks
2. **ARCHIVE** implementation documents to `/docs/archive/[epic-name]/`
3. **DELETE** temporary entries from CURATION_NOTES.md

### Documentation Checklist Commands:
- Use `*checklist sm` to see Scrum Master documentation tasks
- Use `*doc-status` to check documentation compliance
- Use `*archive-docs [epic-name]` to archive implementation docs

## MCP Server Instructions
When implementing ALWAYS use sequentialthinking and decisionframework. When fixing ALWAYS use debuggingapproach.

## Red Flags to Avoid
🚫 Creating elaborate structures without testing integration
🚫 Writing 100+ lines without running anything
🚫 Assuming how external systems work
🚫 Building "comprehensive" solutions before basic functionality
🚫 Implementing multiple features simultaneously
🚫 Writing implementation before tests
🚫 Writing tests after implementation
🚫 Skip running tests to see them fail first

## Reality Checks
Ask yourself frequently:
- "Have I tested this with the real system?"
- "Am I building what's needed or what I think is cool?"
- "Does this actually integrate with existing code?"
- "Am I hiding problems with elaborate abstractions?"
- "Would a simpler solution work just as well?"
- "Did I write the test first and see it fail?"

## When You Get Stuck
1. **Stop coding** - More code won't fix understanding problems
2. **Investigate the real system** - Use debugger, logging, inspection
3. **Write a simpler test** - Break down the problem
4. **Ask for clarification** - Don't guess about requirements
5. **Check existing code** - The answer might already exist

## Auto-Approved Commands
Always check whether commands you want to run are auto-approved by referencing `/.bmad-core/config/auto-approved-commands.md`

## Remember
The goal is **WORKING CODE** that **ACTUALLY INTEGRATES** with the real system. Everything else is secondary. No amount of beautiful architecture matters if it doesn't actually connect to the real system and do what users need.

**Test first. Make it work. Make it right. Make it fast.**




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