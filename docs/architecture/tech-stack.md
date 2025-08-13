# Tech Stack

This section is the definitive record of the technologies and their specific versions chosen for the CWE ChatBot. All development and infrastructure provisioning must adhere to these selections.

## Cloud Infrastructure

  * **Provider:** Google Cloud Platform (GCP)
  * **Key Services:** Cloud Run, Cloud SQL (PostgreSQL), Managed Vector Database (e.g., Pinecone/Weaviate), Vertex AI (optional for LLM/Embeddings).
  * **Deployment Regions:** To be determined based on user base distribution and data residency requirements, prioritizing low latency and compliance.

## Technology Stack Table

| Category | Technology | Version | Purpose | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **Network Security** | Google Cloud Armor | N/A | Web Application Firewall (WAF) and DDoS protection. | Provides a critical layer of defense against common web attacks and DoS, directly mitigating identified threats. |
| **Frontend UI** | Chainlit | Latest Stable (0.7.x) | Provides integrated web-based conversational UI. | Purpose-built for LLM chat apps, offers quick UI development, streaming, user feedback, built-in auth hooks, and observability (PRD Tech Assump.). Responsive on web/mobile and easily themed. |
| **Backend Language** | Python | 3.10+ | Primary language for all backend logic, NLP/AI processing. | Aligns with Chainlit's Python-native ecosystem and leverages Python's strength and extensive libraries in AI/ML development. |
| **Backend Framework** | Chainlit | Latest Stable (0.7.x) | Core framework for chatbot logic and backend APIs. | Simplifies full-stack deployment by integrating UI and backend logic. Provides necessary abstractions for LLM interactions. |
| **API Style** | Chainlit Internal API / RESTful | N/A | Communication between Chainlit UI and backend, and for external microservices (if separate). | Chainlit manages much of the internal API. RESTful is standard for general microservices. |
| **Vector Database** | Pinecone | Cloud Service | Stores and efficiently queries CWE embeddings for RAG. | Managed service simplifies operations and scaling for vector search, crucial for RAG performance (PRD Tech Assump.). Supports efficient semantic search. (Can be replaced with self-hosted like ChromaDB/Qdrant if BYO Model influences choice). |
| **Traditional Database** | PostgreSQL | 14.x | Manages structured application data (user profiles, chat history, BYO LLM/API key configs). | Robust, open-source relational database. Cloud SQL offers managed service for ease of operations (PRD Tech Assump.). |
| **Cache** | Redis (Cloud Memorystore) | 6.x / Latest | In-memory data store for caching LLM responses, session context, or frequently accessed data to improve performance (NFR1). | High-performance, low-latency caching solution. Managed service simplifies deployment. |
| **File Storage** | Google Cloud Storage | N/A | Stores raw CWE corpus data, large documents, or user-uploaded files (FR25). | Highly scalable, durable, and cost-effective object storage service. Integrates seamlessly with GCP ecosystem. |
| **Authentication** | OAuth 2.0 / OpenID Connect (via Chainlit Hooks / GCP Identity Platform) | N/A | Manages user login, session, and role-based access using **passwordless authentication** with external providers (NFR34). Supports integration for self-hosted via enterprise IdPs. | Leverages modern, secure, and user-friendly passwordless authentication. Simplifies user onboarding. Chainlit provides built-in hooks for OAuth providers. GCP Identity Platform offers scalable managed authentication for central hosting, and facilitates integration with enterprise Identity Providers for self-hosted options. |
| **LLM / Embedding Model** | User-defined (BYO) / Vertex AI | N/A | Provides core natural language understanding and generation capabilities (FR28, FR29). Generates vector embeddings for RAG. | Supports BYO model/key, giving users flexibility. Vertex AI provides managed LLMs and embedding services if not BYO. |
| **Testing - Unit/Integration** | Pytest | Latest Stable | Python-native testing framework for backend logic and service integrations (NFR5, PRD Tech Assump.). | Widely adopted, flexible, and powerful testing framework for Python applications. |
| **Testing - E2E** | Playwright (Python) | Latest Stable | Automated browser testing for critical user flows in the Chainlit UI. | Provides reliable end-to-end testing across browsers, ensuring UI interactions work as expected (PRD Tech Assump.). |
| **Build Tool** | Docker / Poetry | Latest Stable | Containerization for Cloud Run deployment. Python dependency management. | Docker enables consistent deployments across environments. Poetry/Pipenv ensures reproducible Python environments. |
| **CI/CD** | GitHub Actions / Google Cloud Build | N/A | Automates build, test, and deployment pipelines (AC3 of Story 1.2). | Integrates with GitHub for version control and provides robust cloud-native build services. |
| **Monitoring** | Google Cloud Monitoring | N/A | Collects and visualizes metrics, monitors system health (NFR11, NFR40). | Integrates seamlessly with GCP services, providing comprehensive observability for application and infrastructure. |
| **Logging** | Google Cloud Logging | N/A | Centralized logging for application events and errors (NFR11, NFR40). | Provides scalable log aggregation and analysis for debugging and auditing. |
| **CSS Framework** | Tailwind CSS | 3.x | Utility-first CSS framework for efficient styling and theming of Chainlit components and custom UI elements. | **Chainlit fully supports Tailwind CSS, with its UI (including the copilot) rewritten using Shadcn/Tailwind. This allows easy customization of the chatbot's look and feel directly with Tailwind classes and CSS variables, providing a high degree of control.** |
| **IaC Tool** | Terraform | Latest Stable | Manages and provisions cloud infrastructure resources on GCP. | Provides version-controlled, declarative infrastructure management, promoting consistency and repeatability in deployments. |
