# Unified Project Structure

This section outlines the monorepo directory structure, designed to logically separate the primary application, supporting services, shared code, and infrastructure. This organization facilitates collaboration, code reuse, and independent deployment of logical components while maintaining a single version-controlled repository.

```
cwe-chatbot-monorepo/
├── .github/                               # GitHub Actions workflows for CI/CD pipelines
│   └── workflows/
│       ├── build-and-deploy-chatbot.yml   # CI/CD for main Chainlit chatbot application
│       └── data-ingestion-schedule.yml    # Workflow for scheduled CWE data ingestion service
├── apps/                                  # Contains primary user-facing applications
│   └── chatbot/                           # The main Chainlit application (Python)
│       ├── src/                           # Python source code for the Chainlit app
│       │   ├── api/                       # Internal API endpoints (e.g., /user/config)
│       │   ├── auth/                      # Authentication logic (OAuth callbacks, token handling)
│       │   ├── services/                  # Business logic, orchestration of NLP/AI and User services
│       │   │   ├── chatbot_core.py        # Main Chainlit chat logic (cl.on_message etc.)
│       │   │   └── user_config_service.py # Interacts with User Management Service
│       │   ├── ui_elements/               # Custom Chainlit/React UI components (if any, served statically)
│       │   ├── __init__.py                # Python package initializer
│       │   └── main.py                    # Chainlit entry point (cl.run_app)
│       ├── tests/                         # Unit and integration tests for chatbot app
│       ├── Dockerfile                     # For containerizing the Chainlit app
│       ├── requirements.txt               # Python dependencies for the app
│       └── pyproject.toml                 # Poetry/Rye/Pipenv config for app-specific dependencies
├── services/                              # Separate logical backend services (can be deployed independently)
│   ├── nlp_ai_processor/                  # Dedicated NLP/AI processing microservice (if decoupled from main app)
│   │   ├── src/
│   │   │   ├── models/                    # LLM/embedding model wrappers
│   │   │   └── processing.py              # Core NLP/RAG logic functions
│   │   ├── Dockerfile                     # Dockerfile for this service (if containerized for Cloud Run)
│   │   ├── requirements.txt
│   │   └── pyproject.toml
│   └── cwe_data_ingestion/                # Service for downloading and processing CWE data
│       ├── src/
│       │   ├── parsers/                   # CWE XML/JSON parsing logic
│       │   └── ingestion.py               # Main ingestion script/function
│       ├── Dockerfile                     # Optional, if deployed as separate container
│       ├── requirements.txt
│       └── pyproject.toml
├── packages/                              # Shared Python packages across apps/services
│   └── shared/                            # Common utilities, data models, interfaces
│       ├── src/
│       │   ├── auth/                      # Shared authentication utilities (e.g., token verification)
│       │   ├── data_models/               # Pydantic models/dataclasses for User, Conversation, Message, CWE entities
│       │   ├── db_utils/                  # Database utility functions, ORM definitions
│       │   ├── exceptions/                # Custom exceptions
│       │   └── __init__.py
│       ├── pyproject.toml
├── infrastructure/                        # Infrastructure as Code (IaC) definitions
│   ├── terraform/                         # Terraform configurations for GCP resources
│   │   ├── main.tf                        # Main Terraform configuration file
│   │   ├── variables.tf                   # Input variables for Terraform
│   │   └── outputs.tf                     # Output variables from Terraform
│   └── README.md                          # Guide for infrastructure setup and management
├── docs/                                  # Project documentation artifacts
│   ├── prd.md                             # Product Requirements Document
│   ├── ui-architecture.md                 # UI/UX Specification
│   ├── fullstack-architecture.md          # This document
│   └── stories/                           # Individual user stories (e.g., 1.1.repo-setup.md)
├── .env.example                           # Template for environment variables (local setup)
├── pyproject.toml                         # Root Poetry/Rye/Pipenv config for monorepo workspaces/dependencies
└── README.md                              # Main project README with high-level overview and setup instructions
```
