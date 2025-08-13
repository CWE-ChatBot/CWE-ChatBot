# Development Workflow

This section outlines the standard procedures and configurations for local development of the CWE ChatBot, ensuring a consistent and streamlined environment for all contributors.

## Local Development Setup

This covers the prerequisites and commands needed to get the project running on a local development machine.

  * **Prerequisites:**
      * Python 3.10+
      * Git
      * Docker (for containerization and local testing)
      * Poetry (or equivalent, e.g., Pipenv, Rye) for Python dependency management
      * Google Cloud CLI (`gcloud`) (for authenticating with GCP services and Cloud Run emulation if needed)
  * **Initial Setup:**
    1.  **Clone the repository:** `git clone https://github.com/your-org/cwe-chatbot-monorepo.git`
    2.  **Navigate to project root:** `cd cwe-chatbot-monorepo`
    3.  **Install root dependencies and set up virtual environments:** `poetry install` (or `pipenv install`, `rye sync`). This will install dependencies for all packages and apps defined in `pyproject.toml`.
    4.  **Authenticate with GCP (if accessing cloud resources locally):** `gcloud auth login` and `gcloud config set project [YOUR_GCP_PROJECT_ID]`
  * **Development Commands:**
      * **Start the main Chainlit Chatbot application:**
        `poetry run chainlit run apps/chatbot/main.py -w` (The `-w` enables hot-reloading for development.)
      * **Run all project tests:**
        `poetry run pytest` (This will discover and run tests across `apps/` and `services/` directories).
      * **Run tests for a specific app/service:**
        `poetry run pytest apps/chatbot/tests/`
      * **Trigger local CWE data ingestion (example):**
        `poetry run python services/cwe_data_ingestion/ingestion.py --local-dev`
      * **Build Docker image for chatbot app:**
        `docker build -t cwe-chatbot-app apps/chatbot/`

## Environment Configuration

Environment variables are used to manage sensitive information and configuration specific to different environments (development, staging, production).

  * **Backend (.env file - at `cwe-chatbot-monorepo/.env`):** This file should be created based on `.env.example` and *never* committed to version control.
      * `CHAINLIT_PORT=8000` (Local port for Chainlit UI)
      * `CHAINLIT_HOST=0.0.0.0`
      * `OPENAI_API_KEY=sk-...` (Example: If using OpenAI LLM, for internal testing/development)
      * `GCP_PROJECT_ID=your-gcp-project-id`
      * `PG_CONN_STRING=postgresql://user:pass@localhost:5432/cwe_chatbot_db` (Local PostgreSQL connection string)
      * `VECTOR_DB_API_KEY=your-vector-db-api-key` (If using managed service like Pinecone)
      * `VECTOR_DB_ENVIRONMENT=your-vector-db-env`
      * `OAUTH_GOOGLE_CLIENT_ID=your-google-client-id` (For Google OAuth)
      * `OAUTH_GOOGLE_CLIENT_SECRET=your-google-client-secret`
      * `OAUTH_GITHUB_CLIENT_ID=your-github-client-id` (For GitHub OAuth)
      * `OAUTH_GITHUB_CLIENT_SECRET=your-github-client-secret`
      * `BYO_LLM_API_ENDPOINT=http://localhost:8080/v1` (Example: For local self-hosted LLM testing)
      * `BYO_LLM_API_KEY=your-byo-llm-api-key` (If BYO LLM requires a key)
  * **Shared Environment Practices:**
      * All environment variables should be accessed through a centralized configuration module within the Python application, ensuring consistency and preventing direct `os.environ` calls (NFR5).
      * Sensitive credentials **must never** be hardcoded or committed to version control.
