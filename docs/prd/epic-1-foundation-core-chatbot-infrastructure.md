# Epic 1: Foundation & Core Chatbot Infrastructure

**Epic Goal:** Establish the foundational project setup (monorepo structure), deploy the basic Chainlit application on GCP Cloud Run, and implement the initial pipeline for ingesting and preparing the CWE corpus data **for effective Retrieval Augmented Generation (RAG)**. This epic aims to deliver a "hello world" chatbot that can respond with simple, static CWE information, validating the core technical stack.

## Story 1.1: Project Repository Setup & Initial Commit

**As a** developer,
**I want** a new project repository set up with a monorepo structure,
**so that** the team can begin organizing code and managing versions.

### Acceptance Criteria

1.  **AC1:** The project repository is initialized on GitHub (or chosen VCS like GitLab/Bitbucket).
2.  **AC2:** A basic monorepo structure is established, including a root `pyproject.toml` (or equivalent for Python monorepo management) and an `apps/chatbot` directory for the main application.
3.  **AC3:** A `README.md` file is created at the repository root with an initial project description and basic setup instructions.
4.  **AC4:** An initial commit containing this foundational structure is pushed to the main branch.
5.  **AC5:** Standard `.gitignore` and `.env.example` files are present at the repository root to manage version control and environment variables.

## Story 1.2: Basic Chainlit Application Deployment to Cloud Run

**As an** administrator,
**I want** a basic Chainlit "Hello World" application deployed to Google Cloud Run,
**so that** we can validate our core deployment pipeline and infrastructure.

### Acceptance Criteria

1.  **AC1:** A minimal Chainlit application is created within the `apps/chatbot` directory, configured to respond with a simple greeting (e.g., "Hello, welcome to CWE ChatBot\!").
2.  **AC2:** The Chainlit application can be successfully containerized using a `Dockerfile` and built into a Docker image.
3.  **AC3:** A CI/CD pipeline (e.g., GitHub Actions, Google Cloud Build) is configured to automatically build the Docker image and deploy it to GCP Cloud Run upon changes to the `apps/chatbot` directory.
4.  **AC4:** The deployed Chainlit application is accessible via a public URL, and its basic functionality can be **verified via a simple HTTP request or browser interaction from a local machine**.
5.  **AC5:** Basic application logs from the Chainlit app (e.g., startup messages) are visible and accessible in Google Cloud Logging, **and can also be accessed locally during development.**

## Story 1.3: Initial CWE Data Ingestion Pipeline

**As a** data engineer,
**I want** an automated pipeline to ingest a small, curated subset of CWE data (e.g., 5-10 specific CWEs from MITRE's XML/JSON) into a vector database,
**so that** the chatbot can begin to retrieve basic information.

### Acceptance Criteria

1.  **AC1:** A Python script or service is developed to download the latest public CWE XML/JSON data from the MITRE website.
2.  **AC2:** The script can parse and extract relevant information (ID, Name, Description, Relationships) for a small, pre-defined subset of CWEs (e.g., CWE-79, CWE-89, CWE-123).
3.  **AC3:** Embeddings are generated for this subset of CWEs using a selected embedding model (e.g., a local sentence transformer or an external API).
4.  **AC4:** The generated embeddings and corresponding CWE metadata (ID, Name) are successfully stored in the chosen vector database (e.g., Pinecone, Weaviate, or a simple in-memory vector store for MVP validation).
5.  **AC5:** The ingestion process is repeatable and can be manually triggered via a command-line interface or simple function call, **and produces a verifiable local output (e.g., confirmation log, sample data file, or queryable local vector store).**
