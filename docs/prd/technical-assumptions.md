# Technical Assumptions

This section documents the initial technical decisions and assumptions that will guide the overall architecture and development of the CWE ChatBot, now incorporating **Chainlit** as a core component. These are critical choices that set constraints for the Architect and provide direction for the engineering team.

## Repository Structure: Monorepo

  * **Rationale:** A Monorepo structure (e.g., using Nx, Turborepo, or a simpler Python-centric monorepo structure) remains preferred. This will facilitate organizing the main Chainlit application, any separate Python services (e.g., for data ingestion or complex NLP pipelines), and shared components, ensuring unified tooling and streamlined dependency management.

## Service Architecture

  * **CRITICAL DECISION - High-Level Service Architecture:** We will adopt a **Python-based application leveraging Chainlit's framework** for the core conversational logic and its integrated web UI. This unified application will interact with other services as needed:
      * **Chainlit Application:** Handles the primary conversational flow, user interface, and directs interactions with other services.
      * **NLP/AI Processing (within/adjacent to Chainlit):** Python's robust AI/ML ecosystem will be leveraged directly by Chainlit for natural language understanding, embedding generation, and vector database interactions. Highly specialized or compute-intensive AI components may be exposed as separate microservices.
      * **CWE Data Ingestion/Retrieval Service:** Manages access and updates from the CWE corpus.
      * **Authentication/User Management Service:** If user accounts are implemented, either through Chainlit's capabilities or an external service.
  * **Rationale:** Chainlit provides a rapid development environment for AI chatbots with built-in UI, significantly simplifying the full-stack deployment and leveraging Python's strengths in AI/ML development.

## Testing Requirements

  * **CRITICAL DECISION - Testing Strategy:** We will implement a **Unit + Integration Testing** strategy for the MVP, aiming for comprehensive coverage of business logic and inter-service communication within the Python ecosystem. **End-to-End (E2E) testing** for critical user flows will utilize Chainlit's testing capabilities or compatible Python web testing frameworks (e.g., Playwright with Pytest).
  * **Rationale:** Ensures quality while optimizing for the Chainlit development paradigm and Python testing ecosystem.

## Primary Frontend/UI Technology

  * The user interface will be directly served and managed by **Chainlit**. Chainlit provides a pre-built, web-based conversational UI that integrates seamlessly with Python backend logic, eliminating the need for a separate frontend framework like React/Next.js for the core chatbot interface.
  * **Rationale:** Direct adoption of the specified tool, simplifying UI development, deployment, and maintaining a unified Python stack.

## Primary Backend Technology

  * **Python** will be the foundational language for the entire backend, encompassing the core chatbot logic, API services, and NLP/AI processing, orchestrated primarily through **Chainlit**. Any highly specialized or compute-intensive AI components may be developed as separate Python microservices and exposed via internal APIs.
  * **Rationale:** Aligns with Chainlit's Python-native ecosystem and leverages Python's strength and extensive libraries in AI/ML development.

## Cloud Provider

  * **Google Cloud Platform (GCP)** will be the primary cloud provider, utilizing services such as **Cloud Run** (for deploying containerized Chainlit apps), Cloud SQL (for PostgreSQL), and Vertex AI (for managed AI services) if needed, alongside a managed Vector Database solution.
  * **Rationale:** Chainlit applications can be easily containerized and deployed on serverless platforms like Cloud Run, aligning with our cost-efficiency, automatic scaling goals, and minimizing operational overhead.

## CWE Corpus Source

  * We assume the primary source for the CWE corpus will be the official MITRE XML/JSON feeds, and that methods for programmatic parsing and updates can be established (Ref. NFR18).

## Initial Authentication

  * For the MVP, authentication will focus on a simple, scalable mechanism (e.g., Chainlit's built-in authentication features, API keys, or integration with a managed identity service from GCP/AWS), deferring complex custom identity management. (Ref. NFR34)
