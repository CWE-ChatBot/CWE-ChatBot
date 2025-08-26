# **CWE ChatBot Fullstack Architecture Document**

## **Introduction**

This document outlines the complete fullstack architecture for the **CWE ChatBot**, including backend systems, frontend implementation, and their integration. It serves as the single source of truth for AI-driven development, ensuring consistency across the entire technology stack.

This unified approach combines what would traditionally be separate backend and frontend architecture documents, streamlining the development process for modern fullstack applications where these concerns are increasingly intertwined.

### **Change Log**

| Date | Version | Description | Author |
| :---- | :---- | :---- | :---- |
| July 18, 2025 | 1.0 | Initial Architecture Draft | Winston (Architect) |
| July 23, 2025 | 2.0 | Integrated security agent's findings (WAF, AI Guardrails, DoS Protection, Enhanced Logging). | Winston (Architect) |
| July 30, 2025 | 2.1 | Aligned architecture with OWASP Securing Agentic Applications guide Version 1.0 July 28, 2025; defined Key Components (KCs) and added Runtime Hardening section. | Chris (Security Agent) |

## **High Level Architecture**

### **Technical Summary**

## **High Level Architecture**

### **Technical Summary**

The CWE ChatBot will be architected as a **Python-based conversational AI application**, primarily leveraging **Chainlit** for its integrated web UI and core backend logic. Deployed on **Google Cloud Platform (GCP) Cloud Run** and protected by **Google Cloud Armor (WAF)**, this full-stack solution will interact with a managed **Vector Database** (e.g., Pinecone/Weaviate) for efficient Retrieval Augmented Generation (RAG) against the CWE corpus, and a **PostgreSQL database (Cloud SQL)** for structured application data. The architecture emphasizes modularity through logical microservices, secure data handling, and supports both centralized hosting and self-hosting options. This design directly supports the PRD's goals for efficient, accurate, and role-based CWE interaction, as well as the "Bring Your Own Key/Model" requirements.

### **Platform and Infrastructure Choice**

  \* Provider: Google Cloud Platform (GCP)  
  \* Key Services:  
      \* Cloud Run: For deploying the containerized Chainlit application, providing automatic scaling and a serverless execution model (aligning with NFR2).  
      \* Cloud Armor: As a Web Application Firewall (WAF) to protect the public-facing Cloud Run endpoint from common web attacks and DDoS.  
      \* Cloud SQL (PostgreSQL): For managing structured application data (e.g., user profiles, chat history, BYO LLM/API key configurations).  
      \* Managed Vector Database (e.g., Pinecone, Weaviate, or self-hosted via GCP Kubernetes Engine): For storing and efficiently querying CWE embeddings for RAG.  
      \* Vertex AI (Optional/BYO LLM): For managed Large Language Model and embedding services, if not leveraging user-provided external LLMs or self-hosted models.  
  \* Deployment Regions: To be determined based on user base distribution and data residency requirements, prioritizing low latency and compliance.  
  \* Rationale: GCP offers a robust suite of serverless and managed services that align with our cost-efficiency, scalability, and security NFRs. Cloud Run is ideal for Chainlit deployments, and its ecosystem supports flexible database and AI integrations.

### **Repository Structure: Monorepo**

  \* Structure: A Monorepo approach will be adopted for code organization.  
  \* Monorepo Tool: While general Python monorepo structures (e.g., using poetry or pipenv workspaces with a well-defined folder structure) might suffice for the MVP, tools like Nx or Turborepo remain an option if multi-language components become necessary or if a more opinionated monorepo management is desired in the future.  
  \* Package Organization: The primary Chainlit application will reside in apps/chatbot. Shared code (e.g., Python packages for common utilities, data models, API interfaces) will be organized in packages/shared or similar directories, facilitating code reuse across services (if further microservices are introduced).  
  \* Rationale: A monorepo centralizes code management, simplifies dependency synchronization, and fosters code reuse between different logical components (backend services, data ingestion pipelines). This aligns with NFR5 (Codebase Adherence) and NFR49 (Contract-Centric Documentation).


### C4 Architecture Diagrams


> [!TIP]
> The C4 Model is a lightweight software architecture description method. It consists of a set of 4 diagrams that describe the static structure of a software system. https://crashedmind.github.io/PlantUMLHitchhikersGuide/C4/c4.html
>
> C4 is supported natively in Github via Mermaid https://mermaid.js.org/syntax/c4.html


#### C0: System Context Diagram for CWE Chatbot

C0: Context: A high-level diagram that sets the scene; including key system dependencies and people (actors/roles/personas/etc).

```mermaid
    C4Context
      title C0: System Context diagram for CWE Chatbot

        Enterprise_Boundary(b0, "System") {
            Person_Ext(userA, "CWE ChatBot User", "A user of the CWE Chatbot")

            System(cwe_chatbot, "CWE Chatbot", "Allows users to understand CWEs and map CWEs to vulnerability info.")

            System_Ext(cwe_corpus, "CWE List and Guidance", "The CWE List and associated guidance")
        }
        BiRel(userA, cwe_chatbot, "Uses")
        BiRel(cwe_corpus, cwe_chatbot, "Gets knowledge from")
```

#### C1: CWE Chatbot Container Diagram

C1: Container: A container diagram shows the high-level technology choices, how responsibilities are distributed across them and how the containers communicate.
- not to be confused with "containers" ala Docker

```mermaid
    
    C4Container

    title C1: Container diagram for CWE Chatbot

    Enterprise_Boundary(system, "CWE Chatbot System") {
        Person(userA, "CWE ChatBot User", "A user of the CWE Chatbot")



        Boundary(chatbot, "CWE Chatbot") {
            Container(web_app, "Frontend", "ChainLit")
            Container(api, "Backend", "LangChain")
            ContainerDb(db, "Persistent Storage", "LangChain")
            Container(log, "Logging", "ChainLit")
            Container(guardrails, "Guardrails", "LlamaFirewall")
            Container(auth, "Authentication", "ChainLit Authentication")
            Container(session_mgmt, "Session Management", "ChainLit Session Management")
            Container(cwe_corpus, "CWE Corpus", "Hybrid RAG")
        }

        Boundary(external, "CWE List and Guidance") {
            Container_Ext(cwe_list, "CWE List", "Definitions")
            Container_Ext(cwe_rcm, "CWE RCM Guidance", "Remediation tips")
        }
    }

    Rel(userA, web_app, "Uses")
    
    UpdateLayoutConfig(2,2)
    
    Rel(web_app, api, "Sends requests to")
    Rel(web_app, api, "Sends requests to")    
    Rel(api, db, "Reads from and writes to")
    Rel(api, log, "Logs events to")
    Rel(api, guardrails, "Validates responses with")
    Rel(api, auth, "Verifies user identity via")
    Rel(api, session_mgmt, "Manages sessions via")
    Rel(cwe_corpus, cwe_list, "Fetches CWE definitions from")
    Rel(cwe_corpus, cwe_rcm, "Fetches guidance from")

```



### **High Level Architecture Diagram**
```mermaid
graph TD
    subgraph "User's Browser"
        User(User)
    end

    subgraph "Google Cloud Platform (GCP)"
        WAF[Google Cloud Armor - WAF]
        subgraph "Chainlit Application on Cloud Run (KC2 - Orchestration)"
            WebUI[Chainlit Web UI]
            BackendAPI[Chainlit Backend]
        end
        subgraph "KC4 - Memory"
            VectorDB[Vector Database - RAG]
            TraditionalDB[Traditional DB PostgreSQL - App Data]
        end
        subgraph "KC6 - Operational Environment"
             DataIngestion[Data Ingestion Pipeline]
             LLM["KC1 - LLM / Embedding Model (BYO)"]
        end

        User -- HTTPS --> WAF
        WAF -- Forwards valid traffic --> WebUI
        WebUI -- Queries --> BackendAPI
        BackendAPI -- Executes RAG --> VectorDB
        BackendAPI -- Generates Response --> LLM
        BackendAPI -- Manages State --> TraditionalDB
    end

    subgraph "External Sources (Part of KC6)"
        CWE_Data[CWE Corpus XML/JSON from MITRE]
    end

    CWE_Data --> DataIngestion
    DataIngestion -- Stores Embeddings --> VectorDB
    DataIngestion -- Stores Metadata --> TraditionalDB

    subgraph DeploymentFlexibility [Deployment Flexibility NFR41]
        Direction[Centralized Cloud Hosting] --and/or--> SelfHost[Self-Hosted Option]
        SelfHost -- Data Never Leaves --> UserNetwork[User's Private Network FR19, NFR33]
    end

    style User fill:#FFF,stroke:#333,stroke-width:2px
    style WAF fill:#FFCDD2,stroke:#D32F2F,stroke-width:2px
    style WebUI fill:#E0F7FA,stroke:#00BCD4,stroke-width:2px
    style BackendAPI fill:#DCEDC8,stroke:#8BC34A,stroke-width:2px
    style NLP_AI fill:#FFE0B2,stroke:#FF9800,stroke-width:2px
    style VectorDB fill:#BBDEFB,stroke:#2196F3,stroke-width:2px
    style TraditionalDB fill:#CFD8DC,stroke:#607D8B,stroke-width:2px
    style CWE_Data fill:#F0F4C3,stroke:#CDDC39,stroke-width:2px
    style DataIngestion fill:#FFF9C4,stroke:#FFEB3B,stroke-width:2px
    style LLM fill:#D1C4E9,stroke:#673AB7,stroke-width:2px
    style DeploymentFlexibility fill:#F5F5F5,stroke:#9E9E9E,stroke-width:2px,stroke-dasharray: 5 5
    style SelfHost fill:#FFFACD,stroke:#FFD700,stroke-width:2px
    style UserNetwork fill:#FFDAB9,stroke:#FF8C00,stroke-width:2px

```

### Architectural and Design Patterns

The following architectural and design patterns will guide the detailed implementation:

  * **Serverless First (for Cloud Deployment):** Leveraging GCP Cloud Run and potentially Cloud Functions for compute, aligning with NFR2 (Automatic Scaling) and cost-efficiency.
  * **Retrieval Augmented Generation (RAG):** This is the core pattern for leveraging LLMs to provide factual, up-to-date, and hallucination-minimized responses by grounding them in the external CWE corpus data (NFR6).
  * **Component-Based UI:** Utilizing Chainlit's inherent component-based structure for the UI, supporting modularity and reusability.
  * **Repository Pattern:** For abstracting data access logic to both the Vector Database and the Traditional Database, promoting testability and database independence (NFR5).
  * **API-Driven Microservices (Logical):** Even if initially deployed as a single Chainlit application, components like NLP/AI processing or data ingestion will be designed with clear API boundaries, allowing for future extraction into separate microservices if needed (aligning with NFR41).
  * **Data-Centric Design:** Emphasizing efficient data modeling and access for both the structured application data and the unstructured CWE knowledge base.
  * **Configuration-Driven AI:** Allowing configurable LLM endpoints and API keys (FR28, FR29) rather than hardcoding, for flexibility and user control.

## Tech Stack

This section is the definitive record of the technologies and their specific versions chosen for the CWE ChatBot. All development and infrastructure provisioning must adhere to these selections.

### Cloud Infrastructure

  * **Provider:** Google Cloud Platform (GCP)
  * **Key Services:** Cloud Run, Cloud SQL (PostgreSQL), Managed Vector Database (e.g., Pinecone/Weaviate), Vertex AI (optional for LLM/Embeddings).
  * **Deployment Regions:** To be determined based on user base distribution and data residency requirements, prioritizing low latency and compliance.

### Technology Stack Table

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

## Data Models

This section defines the core data models and entities that will underpin the CWE ChatBot application. These models describe the structure of the information managed by the system, including user data, conversational history, and the representation of the CWE corpus.

### Data Flow and Storage Diagram

```mermaid
graph TD
    subgraph "External Sources"
        U(👤 User)
        MITRE[🏢 MITRE CWE Corpus <br> XML/JSON Files]
        OAUTH[🔐 OAuth Provider <br> e.g., Google, GitHub]
    end

    subgraph "Application & Processing Layer"
        direction LR
        Ingest[⚙️ Data Ingestion Pipeline]
        App[🌐 CWE ChatBot Application <br> Chainlit Backend]
    end

    subgraph "Data Storage Layer (Data at Rest)"
        direction LR
        subgraph "Vector Database (e.g., Pinecone)"
            VecDB("
                <b>CWE_Embedding</b><br>
                - cwe_id (string)<br>
                - embedding (float vector)<br>
                - metadata (full_text, version, etc.)
            ")
        end
        subgraph "PostgreSQL Database"
            SQLDB("
                <b>users</b><br>
                - id (UUID)<br>
                - email<br>
                - oauth_provider_user_id<br><br>
                <b>conversations</b><br>
                - id (UUID)<br>
                - user_id<br><br>
                <b>messages</b><br>
                - id (UUID)<br>
                - sender ('user'/'chatbot')<br>
                - content (User Query Text)
            ")
        end
    end

    %% Data Flows
    MITRE -- "1. Fetches raw data" --> Ingest
    Ingest -- "2. Processes & creates embeddings" --> VecDB
    
    U -- "3. Authenticates via Redirect" --> OAUTH
    OAUTH -- "4. Returns User Info/Token" --> App
    App -- "5. Creates/updates User record" --> SQLDB

    U -- "6. Sends Query" --> App
    App -- "7. Stores query in 'messages'" --> SQLDB
    App -- "8. Searches for relevant CWEs" --> VecDB
    VecDB -- "9. Returns CWE data" --> App
    App -- "10. Generates & stores response" --> SQLDB
    App -- "11. Displays response" --> U

    style U fill:#cde4ff
    style MITRE fill:#f5f5dc
    style OAUTH fill:#f8d7da
```

### User

  * **Purpose:** To manage user accounts, preferences, and authentication details for both centrally-hosted and self-hosted deployments. It also securely stores configurations for "Bring Your Own" (BYO) LLM API keys and models (FR28, FR29).
  * **Key Attributes:**
      * `id`: UUID, Primary Key (Unique identifier for the user)
      * `email`: String, Unique (User's primary email address)
      * `oauth_provider_type`: String, Nullable (e.g., 'google', 'microsoft', 'github' - Identifies the OAuth provider)
      * `oauth_provider_user_id`: String, Nullable (The unique user ID provided by the OAuth provider)
      * `role`: String (e.g., 'PSIRT Member', 'Developer', 'Academic Researcher', 'Bug Bounty Hunter', 'Product Manager', 'Admin') - supports FR4
      * `preferences`: JSONB/Text (Stores user-specific settings, e.g., preferred response verbosity)
      * `llm_api_key_id`: UUID, Nullable (Reference to a securely stored LLM API key record for FR28)
      * `llm_model_config`: JSONB, Nullable (Configuration details for BYO self-hosted LLM model for FR29)
      * `created_at`: Timestamp (Record creation time)
      * `updated_at`: Timestamp (Last update time)
  * **Relationships:** One-to-many with Conversation.
  * **TypeScript Interface:**
    ```typescript
    interface User {
      id: string;
      email: string;
      // Fields for passwordless OAuth
      oauthProviderType?: string; // e.g., 'google', 'microsoft', 'github'
      oauthProviderUserId?: string; // User ID from the OAuth provider
      role: 'PSIRT Member' | 'Developer' | 'Academic Researcher' | 'Bug Bounty Hunter' | 'Product Manager' | 'Admin';
      preferences?: { [key: string]: any };
      llmApiKeyId?: string; // Reference to securely stored API key record (for FR28)
      llmModelConfig?: { // For FR29
        type: 'api' | 'self-hosted'; // Specifies if it's an API endpoint or a self-hosted instance
        endpoint?: string; // URL for API or self-hosted model
        modelName?: string; // Name of the model (e.g., "llama-3-8b")
        // Additional configuration parameters as needed by the model
      };
      createdAt: string;
      updatedAt: string;
    }
    ```

### Conversation

  * **Purpose:** To store the history of interactions between a specific user and the chatbot, enabling context preservation across turns and sessions (NFR35). This data can be used for feedback loops and analysis.
  * **Key Attributes:**
      * `id`: UUID, Primary Key (Unique identifier for the conversation)
      * `user_id`: UUID, Foreign Key to User (Links to the user who had the conversation)
      * `session_id`: UUID, Unique (A transient ID to group related messages within a continuous interaction, can expire after inactivity)
      * `start_time`: Timestamp (When the conversation began)
      * `end_time`: Timestamp, Nullable (When the conversation ended or became inactive)
      * `current_context`: JSONB/Text (Stores a summary or key elements of the current conversational context to aid continuity)
      * `created_at`: Timestamp (Record creation time)
  * **Relationships:** One-to-many with Message.
  * **TypeScript Interface:**
    ```typescript
    interface Conversation {
      id: string;
      userId: string;
      sessionId: string;
      startTime: string;
      endTime?: string;
      currentContext?: { [key: string]: any }; // Summary or key elements of context (for NFR35)
      createdAt: string;
    }
    ```

### Message

  * **Purpose:** To store individual chat messages, including both user queries and chatbot responses, as part of a larger conversation. This forms the granular record of interaction.
  * **Key Attributes:**
      * `id`: UUID, Primary Key (Unique identifier for the message)
      * `conversation_id`: UUID, Foreign Key to Conversation (Links message to its parent conversation)
      * `sender`: String ('user', 'chatbot') (Indicates who sent the message)
      * `content`: Text (The actual message text)
      * `timestamp`: Timestamp (When the message was sent/received)
      * `is_feedback_eligible`: Boolean, Default FALSE (Indicates if this specific chatbot response is eligible for user feedback, FR27)
      * `feedback_provided`: Boolean, Default FALSE (True if user has given feedback for this response)
      * `cwe_ids_suggested`: VARCHAR(50)[], Nullable (Array of CWE IDs suggested/discussed in this message, for traceability)
      * `llm_model_used`: VARCHAR(255), Nullable (ID or name of the LLM model used to generate this specific response, useful for auditing BYO models)
  * **Relationships:** Many-to-one with Conversation.
  * **TypeScript Interface:**
    ```typescript
    interface Message {
      id: string;
      conversationId: string;
      sender: 'user' | 'chatbot';
      content: string;
      timestamp: string;
      isFeedbackEligible?: boolean; // For FR27
      feedbackProvided?: boolean;
      cweIdsSuggested?: string[]; // For traceability
      llmModelUsed?: string; // For auditing BYO models (FR28, FR29)
    }
    ```

### CWE\_Embedding (Conceptual model for Vector Database)

  * **Purpose:** To store the vector embeddings and essential metadata of CWE entries, optimized for semantic search and Retrieval Augmented Generation (RAG). This is the core knowledge base for the chatbot's intelligence.
  * **Key Attributes:**
      * `cwe_id`: String (e.g., 'CWE-79'), Primary Key / Unique ID (Reference to the official CWE)
      * `embedding`: Vector (float[]) (The numerical representation of the CWE text, for similarity search)
      * `name`: String (Official CWE Name)
      * `short_description`: Text (Concise summary of the CWE)
      * `full_text`: Text (The original or pre-processed full text of the CWE entry from which the embedding was derived; used for RAG context)
      * `version`: String (CWE version from MITRE this embedding corresponds to, NFR18)
      * `last_updated`: Timestamp (When this specific CWE entry was last updated in our database)
  * **Relationships:** None directly in the Vector Database itself, but linked conceptually to messages via `cwe_ids_suggested`.
  * **TypeScript Interface:**
    ```typescript
    interface CweEmbedding {
      cweId: string;
      embedding: number[];
      name: string;
      shortDescription: string;
      fullText: string;
      version: string;
      lastUpdated: string;
    }
    ```

## External APIs

This section identifies and documents the external APIs and data integrations that the CWE ChatBot will rely on. For each integration, details regarding its purpose, access methods, and any relevant constraints are provided.

### 1\. LLM / Embedding Model API (User-defined / Vertex AI)

  * **Purpose:** To provide core natural language understanding, text generation, and embedding capabilities, essential for the chatbot's conversational intelligence and Retrieval Augmented Generation (RAG) process. This covers both user-provided (BYO) and potentially centrally managed LLMs.
  * **Documentation:** Varies significantly based on the specific LLM/Embedding model provider (e.g., OpenAI API documentation, Google Cloud Vertex AI documentation, Hugging Face API documentation, or documentation for a self-hosted LLM).
  * **Base URL(s):** User-configurable endpoint (e.g., `https://api.openai.com/v1/`, `https://us-central1-aiplatform.googleapis.com/v1/projects/...`, or a custom URL for a self-hosted model).
  * **Authentication:** API Key (standard for most commercial LLMs, provided by user for FR28, securely stored), or specific token/header-based authentication for self-hosted models.
  * **Rate Limits:** Varies per provider/model. These limits must be monitored and accounted for to prevent service degradation and manage costs (NFR10).
  * **Key Endpoints Used:**
      * `POST /v1/chat/completions` (or equivalent): For conversational turn inference.
      * `POST /v1/embeddings` (or equivalent): For generating vector embeddings for CWE data and user queries.
  * **Integration Notes:** The system will dynamically switch between LLM endpoints based on user configuration (FR28, FR29). Robust error handling and fallback mechanisms are required for API failures (NFR38).

### 2\. OAuth Providers (e.g., Google, GitHub)

  * **Purpose:** To enable secure, passwordless user authentication and authorization, allowing users to sign in with their existing identity provider credentials.
  * **Documentation:**
      * Google OAuth 2.0 Documentation: `https://developers.google.com/identity/protocols/oauth2`
      * GitHub OAuth Apps Documentation: `https://docs.github.com/en/apps/oauth-apps`
      * (And documentation for any other supported OAuth provider).
  * **Base URL(s):**
      * Google: `https://accounts.google.com/o/oauth2/v2/auth` (authorization endpoint)
      * GitHub: `https://github.com/login/oauth/authorize` (authorization endpoint)
      * (Specific token and user info endpoints will also be used.)
  * **Authentication:** OAuth 2.0 / OpenID Connect flow, using Client ID, Client Secret, and configured Redirect URIs.
  * **Rate Limits:** Generally high for authentication flows, but specific limits per provider apply.
  * **Key Endpoints Used:** Authorization, Token exchange, and User Info endpoints to retrieve user identity (email, basic profile) (NFR34).
  * **Integration Notes:** Integration will leverage Chainlit's built-in authentication hooks where possible. Secure storage of Client Secrets and careful management of Redirect URIs are critical.

### 3\. MITRE CWE Data Source (XML/JSON Feeds)

  * **Purpose:** To provide the official, canonical Common Weakness Enumeration (CWE) corpus data, which forms the foundational knowledge base for the chatbot's information retrieval.
  * **Documentation:** MITRE CWE website, specifically their data feeds section (e.g., `https://cwe.mitre.org/data/downloads.html`).
  * **Base URL(s):** `https://cwe.mitre.org/data/xml/` (for XML files) or `https://cwe.mitre.org/data/json/` (for JSON files).
  * **Authentication:** None (publicly available data).
  * **Rate Limits:** Standard web server download limits. Continuous polling at high frequency is not expected or supported.
  * **Key Access:** Direct file download of the latest XML or JSON `*.zip` archives (e.g., `cwe_latest.xml.zip`) (Story 1.3, NFR18).
  * **Integration Notes:** The CWE Data Ingestion Service will be responsible for periodically downloading, parsing, and processing these files. Robust error handling for network issues or unexpected file formats is required.

## Core Workflows

This section illustrates key system workflows using sequence diagrams, highlighting the interactions between components and the flow of data. These diagrams clarify architectural decisions and complex interactions.

### User Query and RAG-based Response Generation

  * **Purpose:** To detail the full interaction flow from a user submitting a query to the ChatBot generating an intelligent, context-aware response using the Retrieval Augmented Generation (RAG) process.
  * **Key Components Involved:** User, Chatbot Application (Chainlit Core), NLP/AI Service, Vector Database, LLM/Embedding Model.
  * **Clarifies Architectural Decisions:** This flow demonstrates the interaction between the core Chainlit app, the logical NLP/AI service, the vector database for retrieval, and the LLM for generation. It also highlights the RAG pattern.

#### Sequence Diagram

```mermaid
sequenceDiagram
    participant U as User
    participant CA as Chatbot Application Chainlit Core
    participant NAI as NLP/AI Service
    participant VDB as Vector Database
    participant LLM as LLM/Embedding Model

    U->>CA: 1. Enters Query e.g. How to prevent XSS?
    activate CA
    CA->>NAI: 2. Send Query for NLU & Embedding FR1
    activate NAI
    NAI->>LLM: 3. Request Query Embedding
    activate LLM
    LLM-->>NAI: 4. Provide Query Embedding
    deactivate LLM
    NAI->>VDB: 5. Search Vector DB for relevant CWEs FR2
    activate VDB
    VDB-->>NAI: 6. Return Top N relevant CWE chunks
    deactivate VDB
    NAI->>LLM: 7. Formulate Prompt Query + Relevant CWE Chunks for RAG
    activate LLM
    LLM-->>NAI: 8. Generate Contextual Response
    deactivate LLM
    NAI-->>CA: 9. Send Generated Response
    deactivate NAI
    CA->>U: 10. Display Response to User FR5
    deactivate CA
```

**Rationale for Sequence Diagram:** This diagram clearly visualizes the multi-step process of an AI-powered conversational response. It maps how the user's query travels through the system, gets enriched with relevant data from the vector database (RAG), interacts with the LLM, and finally delivers a tailored answer back to the user. It explicitly ties into the FRs and NFRs related to NLU, retrieval, response generation, and hallucination mitigation.

## REST API Spec

This section defines the core REST API endpoints exposed by the Chatbot Application (Chainlit Backend) for internal UI communication and essential system functions in the MVP. A more extensive programmatic API for external clients is a post-MVP consideration as per NFR37.

### OpenAPI 3.0 Specification (YAML)

```yaml
openapi: 3.0.0
info:
  title: CWE ChatBot Internal Configuration API (MVP)
  version: 1.0.0
  description: Minimal API for managing user-specific chatbot configurations and health status, primarily used by the internal UI.
servers:
  - url: /api
    description: Relative path from Chainlit application base URL
tags:
  - name: Health
    description: API Health Check
  - name: User Configuration
    description: Operations related to user-specific chatbot settings
paths:
  /health:
    get:
      tags:
        - Health
      summary: Health check endpoint
      operationId: getHealthStatus
      responses:
        '200':
          description: Service is healthy
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
                    example: "healthy"
  /user/config:
    get:
      tags:
        - User Configuration
      summary: Retrieve authenticated user's chatbot configuration
      operationId: getUserConfig
      security:
        - bearerAuth: []
      responses:
        '200':
          description: User configuration retrieved successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserConfig'
        '401':
          description: Unauthorized
    put:
      tags:
        - User Configuration
      summary: Update authenticated user's chatbot configuration
      operationId: updateUserConfig
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserConfigUpdate'
      responses:
        '200':
          description: Configuration updated successfully
        '400':
          description: Invalid input
        '401':
          description: Unauthorized
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT # JWTs issued via OAuth provider authentication
  schemas:
    UserConfig:
      type: object
      description: Represents the user-configurable settings for the chatbot.
      properties:
        role:
          type: string
          enum: [ "PSIRT Member", "Developer", "Academic Researcher", "Bug Bounty Hunter", "Product Manager", "Admin" ]
          description: The user's selected role, influencing chatbot responses (FR4).
        preferences:
          type: object
          description: User-specific UI or interaction preferences.
          additionalProperties: true
        llmModelConfig:
          type: object
          description: Configuration for Bring Your Own LLM model (FR29).
          properties:
            type:
              type: string
              enum: [ "api", "self-hosted" ]
              description: Type of LLM integration (API endpoint or self-hosted).
            endpoint:
              type: string
              format: uri
              description: Endpoint URL for BYO LLM API or self-hosted model.
            modelName:
              type: string
              description: Name or identifier of the BYO LLM.
          required:
            - type
            - endpoint
            - modelName
      required:
        - role # Role is likely a mandatory user setting
      example:
        role: "Developer"
        preferences:
          theme: "dark"
          verbosity: "verbose"
        llmModelConfig:
          type: "api"
          endpoint: "https://api.example.com/custom-llm"
          modelName: "custom-model-v2"
    UserConfigUpdate:
      type: object
      description: Schema for updating user-configurable chatbot settings.
      properties:
        role:
          type: string
          enum: [ "PSIRT Member", "Developer", "Academic Researcher", "Bug Bounty Hunter", "Product Manager", "Admin" ]
        preferences:
          type: object
        llmModelConfig:
          type: object
          properties:
            type:
              type: string
              enum: [ "api", "self-hosted" ]
            endpoint:
              type: string
              format: uri
            modelName:
              type: string
          required:
            - type
            - endpoint
            - modelName
      example:
        role: "PSIRT Member"
        preferences:
          notifications: "email"
        llmModelConfig:
          type: "self-hosted"
          endpoint: "http://my-llm-server.internal/model"
          modelName: "local-llama"
```

## Database Schema

This section translates the conceptual data models into concrete database schemas, considering the selected database types (PostgreSQL for structured data and a Vector Database for embeddings). It includes definitions for tables, indexes, constraints, and relationships.

### Traditional Database Schema (PostgreSQL DDL)

The following SQL DDL (Data Definition Language) defines the schema for the PostgreSQL database, which will store user data, conversation history, and configuration.

```sql
-- Table: public.users
CREATE TABLE IF NOT EXISTS public.users
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    oauth_provider_type VARCHAR(50),
    oauth_provider_user_id VARCHAR(255),
    role VARCHAR(50) NOT NULL, -- e.g., 'Developer', 'PSIRT Member', 'Admin' (FR4)
    preferences JSONB DEFAULT '{}'::jsonb, -- User-specific settings (JSONB for flexibility)
    llm_api_key_id UUID, -- Reference to a securely stored API key (if internal management is implemented)
    llm_model_config JSONB, -- Config for BYO self-hosted LLM (FR29)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE public.users IS 'Stores user accounts, preferences, and BYO LLM configurations.';
COMMENT ON COLUMN public.users.llm_api_key_id IS 'Foreign key or identifier for securely stored LLM API keys.';
COMMENT ON COLUMN public.users.llm_model_config IS 'JSONB configuration for Bring Your Own self-hosted LLM models.';

-- Optional: Add index on oauth_provider_user_id for faster lookups if frequently used for authentication
CREATE INDEX IF NOT EXISTS idx_users_oauth_id ON public.users (oauth_provider_user_id);


-- Table: public.conversations
CREATE TABLE IF NOT EXISTS public.conversations
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    session_id UUID UNIQUE NOT NULL, -- Unique identifier for a continuous chat session (NFR35)
    start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP WITH TIME ZONE,
    current_context JSONB, -- Summary of conversational context (NFR35)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE public.conversations IS 'Stores high-level conversation history and session context.';
CREATE INDEX IF NOT EXISTS idx_conversations_user_id ON public.conversations (user_id);
CREATE INDEX IF NOT EXISTS idx_conversations_session_id ON public.conversations (session_id);


-- Table: public.messages
CREATE TABLE IF NOT EXISTS public.messages
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES public.conversations(id) ON DELETE CASCADE,
    sender VARCHAR(10) NOT NULL, -- 'user' or 'chatbot'
    content TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_feedback_eligible BOOLEAN DEFAULT FALSE, -- Indicates if this bot response can receive feedback (FR27)
    feedback_provided BOOLEAN DEFAULT FALSE, -- True if user has given feedback for this response
    cwe_ids_suggested VARCHAR(50)[], -- Array of CWE IDs suggested in this message (for traceability)
    llm_model_used VARCHAR(255) -- Name or ID of the LLM model used for this message
);

COMMENT ON TABLE public.messages IS 'Stores individual messages within a conversation.';
CREATE INDEX IF NOT EXISTS idx_messages_conversation_id ON public.messages (conversation_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON public.messages (timestamp);
```

**Rationale for Traditional Database Schema:**

  * **UUIDs for IDs:** Provides globally unique identifiers, suitable for distributed systems and potential future microservice expansion.
  * **`ON DELETE CASCADE`:** Ensures referential integrity by automatically deleting related conversations and messages if a user is removed.
  * **`JSONB` for flexible data:** `preferences` and `current_context` are `JSONB` to allow flexible, schemaless storage of varying user settings and conversational context summaries.
  * **Indexing:** Basic indexes are added for common lookup fields (`user_id`, `session_id`, `conversation_id`, `timestamp`) to optimize query performance.
  * **Traceability:** `cwe_ids_suggested` and `llm_model_used` attributes support tracking chatbot performance and BYO LLM usage.

### Vector Database Conceptual Schema (e.g., Pinecone)

For the Vector Database, the structure is optimized for high-dimensional vector search. The exact implementation will depend on the chosen provider (e.g., Pinecone, Weaviate, Qdrant), but the conceptual model for each stored item (`vector` or `record`) will typically include:

  * **Index Definition:** An index will be configured with a specific vector `dimension` (matching the output size of our chosen embedding model), and a `metric type` (e.g., cosine similarity for text embeddings).
  * **Vector Object Structure (per CWE entry):**
      * `id`: String (e.g., 'CWE-79', 'CWE-123'), serving as a unique identifier for the CWE entry in the vector database.
      * `values`: `float[]` (the actual numerical vector embedding of the CWE text). This is the core data for similarity search.
      * `metadata`: `JSONB` (or equivalent schema-less object) containing crucial CWE attributes for filtering and retrieval, enabling post-query filtering and enriching LLM prompts. This metadata will include:
          * `cwe_id`: String (Official CWE ID)
          * `name`: String (Official CWE Name)
          * `short_description`: String (Concise summary)
          * `full_text`: String (The original or pre-processed full text of the CWE entry from which the embedding was derived; used for RAG context)
          * `version`: String (CWE version from MITRE this embedding corresponds to, NFR18)
          * `last_updated`: Timestamp (When this specific CWE entry was last updated in our database)

**Rationale for Vector Database Schema:**

  * **Optimized for Search:** Focuses on the core components needed for efficient vector similarity search.
  * **RAG Support:** The `full_text` in metadata is crucial for passing relevant context to the LLM during RAG.
  * **Metadata Richness:** Including metadata allows for filtering results before sending to the LLM (e.g., only show CWEs related to web applications) and provides additional context for response generation.

**Security Considerations:**

* **CRITICAL:** The Vector Database, which provides context for the RAG process, **MUST** only be populated with public, non-sensitive data (e.g., the official CWE corpus). This is a fundamental control to prevent the leakage of confidential information to user-configured BYO LLM endpoints, as identified in threat **I-4**.

## REST API Spec

This section defines the core REST API endpoints exposed by the Chatbot Application (Chainlit Backend) for internal UI communication and essential system functions in the MVP. A more extensive programmatic API for external clients is a post-MVP consideration as per NFR37.

### OpenAPI 3.0 Specification (YAML)

```yaml
openapi: 3.0.0
info:
  title: CWE ChatBot Internal Configuration API (MVP)
  version: 1.0.0
  description: Minimal API for managing user-specific chatbot configurations and health status, primarily used by the internal UI.
servers:
  - url: /api
    description: Relative path from Chainlit application base URL
tags:
  - name: Health
    description: API Health Check
  - name: User Configuration
    description: Operations related to user-specific chatbot settings
paths:
  /health:
    get:
      tags:
        - Health
      summary: Health check endpoint
      operationId: getHealthStatus
      responses:
        '200':
          description: Service is healthy
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
                    example: "healthy"
  /user/config:
    get:
      tags:
        - User Configuration
      summary: Retrieve authenticated user's chatbot configuration
      operationId: getUserConfig
      security:
        - bearerAuth: []
      responses:
        '200':
          description: User configuration retrieved successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserConfig'
        '401':
          description: Unauthorized
    put:
      tags:
        - User Configuration
      summary: Update authenticated user's chatbot configuration
      operationId: updateUserConfig
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserConfigUpdate'
      responses:
        '200':
          description: Configuration updated successfully
        '400':
          description: Invalid input
        '401':
          description: Unauthorized
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT # JWTs issued via OAuth provider authentication
  schemas:
    UserConfig:
      type: object
      description: Represents the user-configurable settings for the chatbot.
      properties:
        role:
          type: string
          enum: [ "PSIRT Member", "Developer", "Academic Researcher", "Bug Bounty Hunter", "Product Manager", "Admin" ]
          description: The user's selected role, influencing chatbot responses (FR4).
        preferences:
          type: object
          description: User-specific UI or interaction preferences.
          additionalProperties: true
        llmModelConfig:
          type: object
          description: Configuration for Bring Your Own LLM model (FR29).
          properties:
            type:
              type: string
              enum: [ "api", "self-hosted" ]
              description: Type of LLM integration (API endpoint or self-hosted).
            endpoint:
              type: string
              format: uri
              description: Endpoint URL for BYO LLM API or self-hosted model.
            modelName:
              type: string
              description: Name or identifier of the BYO LLM.
          required:
            - type
            - endpoint
            - modelName
      required:
        - role # Role is likely a mandatory user setting
      example:
        role: "Developer"
        preferences:
          theme: "dark"
          verbosity: "verbose"
        llmModelConfig:
          type: "api"
          endpoint: "https://api.example.com/custom-llm"
          modelName: "custom-model-v2"
    UserConfigUpdate:
      type: object
      description: Schema for updating user-configurable chatbot settings.
      properties:
        role:
          type: string
          enum: [ "PSIRT Member", "Developer", "Academic Researcher", "Bug Bounty Hunter", "Product Manager", "Admin" ]
        preferences:
          type: object
        llmModelConfig:
          type: object
          properties:
            type:
              type: string
              enum: [ "api", "self-hosted" ]
            endpoint:
              type: string
              format: uri
            modelName:
              type: string
          required:
            - type
            - endpoint
            - modelName
      example:
        role: "PSIRT Member"
        preferences:
          notifications: "email"
        llmModelConfig:
          type: "self-hosted"
          endpoint: "http://my-llm-server.internal/model"
          modelName: "local-llama"
```

## Frontend Architecture

This section details the frontend-specific architectural considerations and patterns for the CWE ChatBot, focusing on leveraging Chainlit's capabilities and extending them for custom UI/UX requirements.

### Component Architecture

The UI will be built upon Chainlit's integrated component system, which utilizes React internally. Custom components will be developed to extend Chainlit's native functionality, adhering to defined styling and interaction patterns.

  * **Component Organization:** Custom React components or Chainlit elements will be organized in a clear directory structure, such as `app/frontend/src/components` (if custom React components are served by Chainlit's static files) or within Python files if leveraging Chainlit's direct UI element definitions (`cl.Message`, `cl.AskUserMessage`, `cl.Action`).

  * **Component Template (Conceptual - Python/Chainlit Paradigm):** This illustrates how custom UI logic or content might be defined and sent within the Chainlit backend to be rendered in the frontend.

    ```python
    # In your main Chainlit app.py or a custom module
    import chainlit as cl
    from chainlit.types import AskFileMessage, AskUserMessage, Audio, Image, Text, Pdf, Video, Action, Element, Task, TaskList

    @cl.step(type="ui_component_interaction") # Example of a custom step type
    async def display_custom_settings_ui(user_id: str):
        # This is a conceptual representation. In reality, you'd send cl.Message
        # with elements that trigger custom React components, or use Chainlit's native elements.
        settings_card = Text(
            name="user_settings_card",
            content=f"""
            ## User Settings for {user_id}
            - **Role:** Developer
            - **LLM Config:** Custom API
            
            [Edit Role](link/to/role/edit) | [Manage LLM API Key](link/to/key/manage)
            """,
            language="markdown"
        )
        await cl.Message(
            content="Here are your current settings:",
            elements=[settings_card],
            actions=[cl.Action(name="refresh_settings", label="Refresh Settings")]
        ).send()

    # @cl.action("edit_role") - would trigger a backend action from frontend interaction
    # async def handle_edit_role(): ...
    ```

  * **Naming Conventions:** Consistent PascalCase for React component names (if custom React components are used) and snake\_case for Python module/function names related to Chainlit UI elements.

### State Management Architecture

Chainlit provides built-in mechanisms for managing user session state. For any global UI state beyond session context, standard Python patterns or Chainlit's capabilities will be leveraged.

  * **Store Structure:** Chainlit primarily manages state per user session via `cl.user_session`. This object is directly accessible within Chainlit message handlers and functions.

  * **State Management Patterns:**

      * **Chainlit Session State (`cl.user_session`):** For storing user-specific data that persists across messages within a session (e.g., user role, current conversation context, preferences). This aligns with NFR35 (Session Context Preservation).
      * **Local Python Variables:** For transient state within a single function call.
      * **Database Persistence:** For state that needs to persist across sessions or be shared/audited (e.g., `User` preferences, `Conversation` history, stored in PostgreSQL).

    <!-- end list -->

    ```python
    # Example of Chainlit session state usage
    import chainlit as cl

    @cl.on_chat_start
    async def start():
        # Initialize user-specific session state at the start of a conversation
        cl.user_session.set("user_role", "general") # Default role
        await cl.Message(content="What is your role today? (Developer, PSIRT Member, etc.)").send()

    @cl.on_message
    async def update_role(message: cl.Message):
        if "my role is" in message.content.lower():
            if "developer" in message.content.lower():
                cl.user_session.set("user_role", "Developer")
                await cl.Message(content="Understood, I will tailor responses for a Developer.").send()
            # ... handle other roles
        current_role = cl.user_session.get("user_role")
        await cl.Message(content=f"Current role in session: {current_role}").send()
    ```

### Routing Architecture

Chainlit intrinsically handles the routing for the main conversational interface. For any supplementary web pages (e.g., a dedicated settings dashboard), these would either be separate routes managed by Chainlit or a minimal web framework integrated within the Chainlit application.

  * **Route Organization:**
      * The primary chatbot UI is served directly by Chainlit's internal routing.
      * Custom web pages (e.g., `/settings`, `/profile`) would be managed as part of the main Chainlit Python application using standard web framework patterns (e.g., Flask/FastAPI routes within the Chainlit app if extended, or external static files served by Chainlit).
  * **Protected Route Pattern:** Authentication and authorization will be handled by Chainlit's built-in authentication hooks (NFR34). These hooks enable securing routes or specific functionalities based on user login status and roles.

### Internal Service Interaction Patterns (within Chainlit Backend)

This layer defines how the Python Chainlit application and its logical components communicate with each other, and with external APIs like LLMs.

  * **API Client Setup:** For interacting with external LLM APIs (FR28), embedding models, or other external services, standard Python HTTP clients (`httpx` for async, `requests` for sync) will be used. These clients will be configured with necessary authentication headers (e.g., API keys, OAuth tokens) and robust error handling.
    ```python
    # Python example for calling an external LLM API from the Chainlit backend
    import httpx
    import os

    async def call_byo_llm_api(endpoint: str, api_key: str, prompt: str, model_name: str):
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}]
        }
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(endpoint, headers=headers, json=payload, timeout=60.0)
                response.raise_for_status() # Raises HTTPStatusError for bad responses (4xx/5xx)
                return response.json()["choices"][0]["message"]["content"]
        except httpx.RequestError as exc:
            print(f"An error occurred while requesting {exc.request.url!r}: {exc}")
            raise # Re-raise to be handled by higher level
        except httpx.HTTPStatusError as exc:
            print(f"Error response {exc.response.status_code} while requesting {exc.request.url!r}: {exc.response.text}")
            raise # Re-raise
    ```
  * **Service Example:** Interactions between logical components (e.g., `Chatbot Application` calling `NLP/AI Service` or `User Management Service`) will be achieved through direct Python function calls, class instantiations, or dependency injection patterns, optimizing for performance within the unified Python backend.

## Backend Architecture

This section provides specific architectural details for the backend components of the CWE ChatBot, focusing on service organization, database interaction, and the implementation of authentication and authorization.

### Service Architecture

We will adhere to a **Serverless-first approach** where feasible, primarily utilizing Google Cloud Run for containerized services and potentially Cloud Functions for event-driven processing. This structure supports modularity, independent scalability, and aligns with our cost-efficiency goals (NFR2).

  * **Function/Service Organization:** Within the monorepo, logical services will be organized into distinct Python modules or packages, fostering clear separation of concerns.
      * `apps/chatbot/`: Contains the main Chainlit application, which orchestrates calls to other logical services.
      * `services/nlp_ai/`: Encapsulates NLP/AI processing logic, RAG implementation, and LLM interactions. This could be deployed as part of the main Chainlit app initially or as a separate Cloud Run service for dedicated scaling.
      * `services/cwe_ingestion/`: Houses the data ingestion pipeline, deployed as a Cloud Function for scheduled runs or a separate Cloud Run service for on-demand processing.
      * `services/user_auth/`: Manages user authentication and authorization logic, integrated via Chainlit hooks or as a dedicated internal microservice.
      * `packages/shared/`: Contains common data models (e.g., User, Conversation), utilities, and API interface definitions to be shared across all services.
  * **Function/Service Template (Conceptual Python Module):** This illustrates how a reusable backend service module might be structured, demonstrating its independence from the main Chainlit app's direct request handling.
    ```python
    # Example: services/nlp_ai/processing.py
    from typing import List, Dict
    # Assume imports for vector_db_client, llm_client, cwe_data_model

    async def get_cwe_embedding(text: str) -> List[float]:
        """Generates a vector embedding for the given text."""
        # Call LLM_Embedding Model (BYO/External) to get embedding
        pass

    async def search_cwe_corpus(embedding: List[float], top_k: int = 5) -> List[Dict]:
        """Searches the vector database for relevant CWEs."""
        # Call VectorDB to perform similarity search
        pass

    async def generate_rag_response(query: str, relevant_cwe_data: List[Dict], llm_model_config: Dict) -> str:
        """Generates a contextual response using RAG."""
        # Formulate prompt using query and cwe_data, call LLM
        pass
    ```

### Database Architecture

Our strategy involves a hybrid approach, combining a traditional relational database for structured application data with a specialized vector database for efficient semantic search of the CWE corpus.

  * **Schema Design:** The detailed SQL DDL for PostgreSQL (`users`, `conversations`, `messages` tables) and the conceptual schema for the Vector Database (CWE embeddings) are defined in the dedicated [Database Schema](https://www.google.com/search?q=%23database-schema) section.
  * **Data Access Layer (Repository Pattern):** All direct database interactions will be abstracted behind a Repository Pattern (NFR5). This provides a clean interface for services, promotes testability, and allows for potential future changes in the underlying database technology with minimal impact on business logic.
    ```python
    # Example: packages/shared/data_access/cwe_repository.py
    from typing import List, Dict
    # Assume imports for vector_db_client, TraditionalDB_Session

    class CweRepository:
        def __init__(self, vector_db_client, traditional_db_session):
            self.vector_db_client = vector_db_client
            self.traditional_db_session = traditional_db_session

        async def get_cwe_metadata(self, cwe_id: str) -> Dict:
            """Retrieves structured CWE metadata from the traditional DB."""
            # Use self.traditional_db_session to query PostgreSQL
            pass

        async def search_cwe_embeddings(self, query_embedding: List[float], limit: int) -> List[str]:
            """Performs vector search for CWE IDs."""
            # Use self.vector_db_client to query VectorDB
            pass
    ```

### Authentication and Authorization Architecture

Authentication will be **passwordless** using OAuth 2.0 / OpenID Connect. Authorization will be role-based, ensuring secure access control (NFR34).

  * **Auth Flow Diagram (Mermaid):** This sequence illustrates the user authentication flow via an external OAuth provider.
    ```mermaid
    sequenceDiagram
        participant U as User
        participant UI as Chatbot UI
        participant IDP as OAuth Provider e.g. Google
        participant CA as Chatbot Application
        participant UM as User Management Service/DB

        U->>UI: 1. Clicks "Sign In"
        UI->>IDP: 2. Redirects for Authorization Request
        IDP->>U: 3. Displays Login/Consent Screen
        U->>IDP: 4. Grants Consent
        IDP->>UI: 5. Redirects with Authorization Code
        UI->>CA: 6. Exchanges Code for Access Token
        activate CA
        CA->>IDP: 7. Validate Code & Request Token
        IDP-->>CA: 8. Returns Access Token & ID Token
        CA->>UM: 9. Validate/Create User Record & Role NFR34
        activate UM
        UM-->>CA: 10. User ID & Role Confirmed/Created
        deactivate UM
        CA-->>UI: 11. Stores Session/Token & Redirects to Chat
        deactivate CA
        UI->>CA: 12. Subsequent Authenticated Requests with Token
    ```
  * **Middleware/Guards:** Authentication and authorization checks will be enforced at the API entry points of relevant services. Chainlit's built-in authentication hooks will be utilized to protect conversational endpoints. For separately deployed microservices (if applicable), standard Python web framework middleware will apply.
    ```python
    # Example: Conceptual Authentication Middleware/Decorator
    from functools import wraps
    from fastapi import Request, HTTPException, Depends
    # Assume imports for token_validation_util, user_repo, UserRole

    def require_role(allowed_roles: List[str]):
        def decorator(func):
            @wraps(func)
            async def wrapper(request: Request, *args, **kwargs):
                auth_header = request.headers.get("Authorization")
                if not auth_header or not auth_header.startswith("Bearer "):
                    raise HTTPException(status_code=401, detail="Bearer token missing or invalid")
                token = auth_header.split(" ")[1]
                
                try:
                    payload = token_validation_util.verify_oauth_jwt(token) # Verifies JWT and returns payload
                    user_email = payload.get("email")
                    if not user_email:
                        raise HTTPException(status_code=403, detail="Invalid token payload: missing email")
                    
                    user = await user_repo.get_user_by_email(user_email) # Fetch user from our DB
                    if not user or user.role not in allowed_roles:
                        raise HTTPException(status_code=403, detail="Insufficient privileges")
                    
                    # Store user in request state or pass to function
                    request.state.user = user
                    return await func(request, *args, **kwargs)
                except Exception as e:
                    print(f"Auth/AuthZ Error: {e}")
                    raise HTTPException(status_code=401, detail="Invalid token or access denied")
            return wrapper
        return decorator

    # Usage in a protected endpoint (e.g., in a separate microservice)
    # @app.get("/admin/dashboard")
    # @require_role(["Admin"])
    # async def get_admin_dashboard(request: Request):
    #     user = request.state.user # Access user object from state
    #     return {"message": f"Welcome Admin {user.email}"}
    ```

## Unified Project Structure

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

## Development Workflow

This section outlines the standard procedures and configurations for local development of the CWE ChatBot, ensuring a consistent and streamlined environment for all contributors.

### Local Development Setup

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

### Environment Configuration

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

## Deployment Architecture

This section outlines the strategy for deploying the CWE ChatBot, including the chosen platforms, CI/CD pipeline, environment management, and rollback procedures.

### Deployment Strategy

The CWE ChatBot will leverage Google Cloud Platform's serverless capabilities for highly scalable and efficient deployments.

  * **Frontend & Backend Deployment:** The unified **Chainlit application (Python)**, serving both the UI and core backend logic, will be deployed as a containerized service to **Google Cloud Run**. This provides automatic scaling, serverless execution, and a publicly accessible endpoint.
  * **Supporting Services Deployment:** Logical microservices such as the `NLP/AI Processor` (if separated) and the `CWE Data Ingestion Service` will also be deployed to **Google Cloud Run** or **Google Cloud Functions**, depending on their execution pattern (long-running vs. event-driven/scheduled).
  * **Build Command:** Docker will be used as the primary containerization technology. The `Dockerfile` within each app/service directory will define its build process.
  * **Deployment Method:** We will aim for **Continuous Deployment (CD)** to our staging environment, and **Continuous Delivery (CD)** with a manual approval gate for production releases.

### CI/CD Pipeline

A robust Continuous Integration/Continuous Delivery (CI/CD) pipeline will automate the process of building, testing, and deploying the application.

  * **CI/CD Platform:** **GitHub Actions** will be used for orchestrating the overall pipeline due to its tight integration with our code repository. **Google Cloud Build** will be leveraged for efficient and secure Docker image builds and deployment to GCP resources.
  * **Pipeline Configuration:** Configuration files (e.g., `.github/workflows/*.yml`) will reside in the `.github/workflows/` directory of the monorepo.
  * **Conceptual Workflow:**
    1.  **Code Commit/Pull Request:** Developer pushes code changes or opens a Pull Request.
    2.  **Continuous Integration (CI):** GitHub Actions triggers:
          * Automated tests (unit, integration) using Pytest (NFR47).
          * Code linting and static analysis (NFR5, NFR48).
          * Security scanning (SAST) (NFR47).
    3.  **Image Build:** On successful CI and merge to `main`, Google Cloud Build triggers to:
          * Build Docker images for affected services/apps.
          * Push images to Google Artifact Registry.
    4.  **Automated Deployment to Staging:** GitHub Actions/Cloud Build deploys the new images to the dedicated **Staging** Cloud Run services.
    5.  **Dynamic Application Security Testing (DAST):** Automated DAST scans run against the newly deployed staging environment (NFR47).
    6.  **Manual Approval (for Production):** A manual gate (e.g., in GitHub Actions or a dedicated release tool) requires approval for deployment to Production.
    7.  **Production Deployment:** Upon approval, the new images are deployed to the **Production** Cloud Run services.
    8.  **Scheduled Data Ingestion:** A separate CI/CD flow or Cloud Scheduler job will trigger the `cwe_data_ingestion` service periodically (e.g., weekly, aligning with NFR18).

### Environments

Distinct environments will be used to ensure proper testing and separation of development stages.

  * **Development:** Local developer machines, used for coding, local testing, and rapid iteration.
  * **Staging:** A dedicated GCP project or set of resources, mirroring the production environment. Used for integration testing, user acceptance testing (UAT), DAST, and pre-release validation.
  * **Production:** A fully isolated and hardened GCP project, hosting the live application accessible by end-users.

### Availability & DoS Protection

* **Rate Limiting:** The system will implement per-user rate limiting on all public endpoints via Google Cloud Armor to mitigate API Flooding (**D-2**) and Financial DoS (**D-3**).  
* **Billing Alerts:** GCP billing alerts will be configured via Terraform to provide early warning of potential FDoS attacks (**D-3**).  
* **Query Complexity:** The application logic will include timeouts and complexity analysis on AI-driven queries to prevent resource exhaustion (**D-1**).
* 
### Rollback Strategy

A clear rollback strategy is essential to quickly recover from critical issues post-deployment (NFR42).

  * **Primary Method:** **Google Cloud Run Revision Management.** Cloud Run automatically creates a new revision for each deployment. Rolling back is as simple as routing traffic to a previously known stable revision with a single command or UI action. This provides near-instantaneous rollback capabilities.
  * **Trigger Conditions:** Critical errors detected in post-deployment monitoring (e.g., high error rates, performance degradation, major functional regressions, security alerts).
  * **Recovery Time Objective (RTO):** Aim for an RTO of less than 5 minutes for critical issues by leveraging Cloud Run's rapid rollback feature.

## Error Handling Strategy

This section outlines the comprehensive approach to error detection, handling, logging, and recovery within the CWE ChatBot system, ensuring resilience and clear diagnostics.

### General Approach

  * **Error Model:** The system will adopt a consistent error model across all services, utilizing custom exception classes for anticipated domain-specific errors and standard exceptions for unexpected issues.
  * **Exception Hierarchy:** A structured exception hierarchy will be defined to categorize different types of errors (e.g., `CweNotFoundError`, `InvalidInputError`, `LlmApiError`), allowing for specific handling and clear error propagation.
  * **Error Propagation:** Clear rules will govern how errors are caught, logged, transformed, and re-thrown. External errors will be wrapped or translated into internal, standardized error responses to maintain system consistency.

### Logging Standards

Consistent and comprehensive logging is vital for monitoring, debugging, and auditing.

  * **Library:** Standard Python `logging` module will be used, configured to integrate seamlessly with **Google Cloud Logging** for centralized log aggregation.
  * **Format:** **Structured logging (JSON format)** will be enforced to facilitate easy parsing, filtering, and analysis by monitoring tools.
  * **Levels:** Standard logging levels will be used: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`.
  * **Required Context:** All log entries, especially warnings and errors, shall include essential contextual information for traceability and debugging (NFR11, NFR40):
      * `correlation_id`: For tracing a single request or operation across multiple services.
      * `user_id`: (If authenticated) to link errors to specific users.
      * `session_id`: For tracing errors within a specific user's chat session.
      * `service_name` / `module`: To identify the source of the log.
      * `request_id`: For API requests.
  * **Mandatory Security Events:** The following events must be logged with a "SECURITY" tag for auditing (**R-1**):  
    * Login success/failure  
    * BYO endpoint or API key configuration changes (with old/new values, excluding secrets)  
    * User role modifications  
    * Any event triggered by the AI/Prompt Security guardrails (e.g., detected prompt injection)  
    * Any failed authorization attempt (e.g., IDOR attempt)

### Error Handling Patterns

Specific patterns will be applied for different categories of errors to ensure consistent and effective handling.

  * **External API Errors (e.g., LLM APIs, OAuth Providers):**
      * **Retry Policy:** An **exponential backoff with jitter** strategy will be implemented for transient errors (e.g., network issues, temporary service unavailability, rate limits) when calling external APIs (NFR10).
      * **Circuit Breaker:** For critical external dependencies (e.g., primary LLM provider, Vector Database), a **Circuit Breaker pattern** will be implemented to prevent cascading failures during sustained outages (NFR38).
      * **Timeout Configuration:** Strict and appropriate timeouts will be applied to all outgoing external API calls to prevent indefinite hanging and resource exhaustion.
      * **Error Translation:** External API-specific error codes and messages will be translated into standardized internal error responses (e.g., `LlmApiError`, `OAuthError`) before propagation.
  * **Business Logic Errors:**
      * **Custom Exceptions:** Domain-specific business rule violations (e.g., `CweNotFoundError`, `InvalidInputError`, `UnauthorizedUserRoleError`) will be represented by custom exceptions within the Python application.
      * **User-Facing Errors:** Internal errors will be transformed into clear, concise, and user-friendly messages for display in the chatbot UI, guiding the user on next steps (FR17, FR26). Raw technical details will not be exposed to the user.
      * **Error Codes:** An internal system of error codes might be considered for programmatic handling and consistency across the API (as per REST API Spec).
  * **Data Consistency:**
      * **Transaction Strategy:** Database operations involving multiple statements will be enclosed within **transactions** to ensure atomicity and data integrity (e.g., creating a conversation and its first message).
      * **Compensation Logic:** For distributed or asynchronous operations (e.g., data ingestion where multiple steps write to different databases), compensation logic or saga patterns will be considered to ensure eventual consistency in case of failures.
      * **Idempotency:** Critical operations (especially data ingestion, API calls that modify state) will be designed to be **idempotent** where possible, allowing them to be safely retried without unintended side effects.

## Coding Standards

This section defines the mandatory security requirements for AI and human developers, focusing on implementation-specific rules, referencing security tools from the Tech Stack, and defining clear patterns for common scenarios. These rules directly impact code generation.

### Core Standards

  * **Languages & Runtimes:** Python 3.10+ is the primary development language.
  * **Style & Linting:**
      * **Code Formatting:** [Black](https://github.com/psf/black) for uncompromising code formatting.
      * **Linting:** [Ruff](https://astral.sh/ruff) for fast static code analysis and adherence to style conventions, acting as a linter and formatter.
      * **Type Checking:** [MyPy](https://mypy-lang.org/) for static type checking across the entire codebase.
  * **Automation:** All formatting, linting (**specifically Ruff**), and type checking tools will be integrated into pre-commit hooks (e.g., via `pre-commit.com`), **code generation hooks**, and continuously run as part of the CI/CD pipeline (NFR47, NFR48).

### Naming Conventions

Consistent naming is crucial for code readability and maintainability.

| Element | Convention | Example |
| :--- | :--- | :--- |
| **Modules/Files** | `snake_case` | `user_config_service.py` |
| **Classes** | `PascalCase` | `UserConfigService` |
| **Functions/Methods** | `snake_case` | `get_user_preferences` |
| **Variables** | `snake_case` | `user_data`, `cwe_id` |
| **Constants** | `UPPER_SNAKE_CASE` | `DEFAULT_TIMEOUT_SECONDS` |

### Critical Rules

These are non-negotiable rules specifically highlighted to prevent common pitfalls and enforce architectural principles for both human and AI developers:

  * **Secret Handling:** **NEVER hardcode secrets** (API keys, credentials, sensitive configuration values). Always retrieve them securely from environment variables, dedicated secret management services (e.g., Google Secret Manager), or Chainlit's secure configuration mechanisms (NFR33, NFR31).
  * **Direct Database Access:** All direct database interactions (e.g., raw SQL queries, ORM calls) MUST be encapsulated within the **Repository Pattern** (as defined in NFR5). Business logic services should interact only with these repositories, not directly with database clients or ORMs.
  * **Error Handling:** All external API calls and critical business logic paths MUST include robust error handling (e.g., `try-except` blocks, custom exceptions), ensuring graceful degradation (NFR38) and clear user feedback (FR17, FR26).
  * **LLM Prompt Management:** All LLM prompts used for generating responses MUST be version-controlled (NFR31). Sensitive user data (PII or confidential code) MUST be stripped or anonymized before being sent to external LLMs (NFR33).
  * **Data Validation:** All incoming data, especially from external sources (API requests, user messages, file uploads), MUST be rigorously validated at the earliest possible entry point to prevent injection attacks and ensure data integrity (NFR8).
  * **Logging:** Consistent and structured logging (NFR11, NFR40) must be applied across all services. Critical log messages (WARNING, ERROR, CRITICAL) MUST include sufficient context (correlation IDs, user/session IDs) for effective debugging and auditing.
  * **Code Duplication:** Developers should actively strive to minimize code duplication by abstracting common logic into reusable functions, classes, or shared packages (NFR48). Automated tools will flag high duplication.
  * **Documentation:** Key interfaces, complex functions, and architectural decisions must have clear docstrings and supporting READMEs (NFR49). This aligns with the "documentation as contracts" principle.

### Language-Specific Guidelines (Python)

  * **Type Hinting:** Mandatory for all function signatures, class attributes, and complex data structures (`mypy` will enforce this).
  * **Asynchronous Programming:** Use `async/await` syntax with `asyncio` for all I/O-bound operations (e.g., database calls, external HTTP requests, file I/O) to ensure non-blocking execution and optimize performance.
  * **Dependency Injection:** Favor explicit dependency injection over global variables or direct instantiations within services to improve testability and modularity.

## Security

This section defines the mandatory security requirements for AI and human developers, focusing on implementation-specific rules, referencing security tools from the Tech Stack, and defining clear patterns for common scenarios. These rules directly impact code generation.

### Input Validation

  * **Validation Library:** Python libraries such as [Pydantic](https://pydantic-docs.helpmanual.io/) will be used for defining and validating data schemas for API requests and internal data structures, particularly within FastAPI/Chainlit endpoints.
  * **Validation Location:** Input validation shall occur at all system entry points, including API boundaries (e.g., Chainlit message handlers, custom backend endpoints) and data ingestion points (CWE Data Ingestion Service).
  * **Required Rules:** All external inputs MUST be rigorously validated (NFR8). A **whitelist approach** (explicitly allowing known safe inputs) is preferred over a blacklist approach (blocking known bad inputs). Inputs must be sanitized to prevent common web vulnerabilities like Cross-Site Scripting (XSS), SQL Injection, and Prompt Injection (NFR8).

### AI & Prompt Security

* **Input Guardrails:** All user input must be sanitized before being sent to an LLM to detect and neutralize prompt injection patterns (**T-1**).  
* **Output Validation:** All responses from LLMs must be scanned to prevent the leaking of confidential system prompts or instructions (**I-2**).  
* **Untrusted BYO Endpoints:** All user-configured BYO LLM endpoints are to be treated as untrusted external services. Responses must be sanitized, and network requests should be made through a sandboxed egress proxy (**S-3**, **I-4**).  
* **LLM Tooling Permissions:** If/when the LLM is granted access to internal tools, a strict, user-permission-based authorization model must be implemented to prevent abuse (**E-2**).
  
### Authentication & Authorization

  * **Auth Method:** **OAuth 2.0 / OpenID Connect** (via providers like Google, GitHub) will be the primary authentication mechanism (FR19, NFR33, NFR34). Chainlit's built-in authentication hooks will be leveraged.
  * **Session Management:** Token-based sessions (e.g., JWTs issued by the OAuth provider and managed by the backend) will be used for user session management, ensuring statelessness where appropriate.
  * **Required Patterns:**
      * Authentication and authorization checks will be enforced at the earliest possible point in the request lifecycle (e.g., Chainlit decorators, FastAPI dependencies).
      * Role-based access control (RBAC) will be applied using roles managed by the User Management Service (FR4, NFR34) to restrict access to sensitive functionalities or data based on user privileges.

### Secrets Management

  * **Development:** Sensitive credentials for local development will be managed via `.env` files (excluded from version control). For cloud development/staging environments, **Google Secret Manager** will be used.
  * **Production:** **Google Secret Manager** will be the definitive solution for storing and managing all production secrets (API keys, database credentials, LLM keys/tokens).
  * **Code Requirements:**
      * **NEVER hardcode secrets** directly in code or commit them to version control.
      * Secrets shall only be accessed through a centralized, secure configuration loading mechanism that integrates with Google Secret Manager or Chainlit's secure configuration.
      * No secrets will be logged or exposed in error messages (NFR33).

### API Security

  * **Rate Limiting:** The system will implement **per-user quotas and overall rate limits** (NFR10) to protect against abuse, resource exhaustion, and Denial of Service (DoS) attempts on public-facing APIs or the Chainlit interface.
  * **CORS Policy:** A strict [CORS (Cross-Origin Resource Sharing)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) policy will be enforced on all web-exposed endpoints, allowing requests only from explicitly whitelisted origins.
  * **Security Headers:** Standard HTTP security headers (e.g., Content-Security-Policy, X-Content-Type-Options, X-Frame-Options) will be applied to all web responses to mitigate common client-side attacks.
  * **HTTPS Enforcement:** All communications, both external and internal where possible, MUST enforce **HTTPS/TLS** (NFR4) to ensure data encryption in transit.

### Data Protection

  * **Encryption at Rest:** All sensitive data stored in the Traditional Database (PostgreSQL) and the Vector Database (Pinecone/managed service) will be encrypted at rest, leveraging the cloud provider's managed encryption capabilities.
  * **Encryption in Transit:** All data transmission will be encrypted using HTTPS/TLS (NFR4).
  * **PII Handling:** User login ID, email, and credentials are classified as PII (NFR33) and will be handled in full compliance with **GDPR requirements**. This includes data minimization, secure storage, access restrictions, and defined data retention policies (NFR39).
  * **Logging Restrictions:** No PII, sensitive user queries, or confidential code snippets shall be logged in plain text. Logging will adhere to data minimization principles (NFR33).

### Dependency Security

  * **Scanning Tool:** Automated dependency vulnerability scanning tools (e.g., [Dependabot](https://github.com/features/security/), [Snyk](https://snyk.io/), [Trivy](https://aquasecurity.github.io/trivy/)) will be integrated into the CI/CD pipeline (NFR47).
  * **Update Policy:** A regular policy for reviewing and applying dependency updates, prioritizing critical security patches and known vulnerabilities, will be established.
  * **Approval Process:** A formal process for reviewing and approving new third-party dependencies will be followed to minimize supply chain risks.


### Runtime Hardening

To protect the production environment, the following runtime hardening principles will be applied:

- Harden the Virtual Machine (Base Level): The Cloud Run environment will be based on minimal, hardened base images. All unnecessary services and packages will be removed. Network access will be restricted by default. 
- Contain the Agentic Runtime: The Chainlit application will be containerized. Where it executes tools (like code interpreters in the future), it will do so in a sandboxed environment to restrict syscalls and filesystem access. 
- Secure the Agent's Memory, Tools, and Context: In-memory state will be encrypted where feasible and auto-cleared at session end. All tool calls will be validated at runtime. 
- Observability + Forensics: Every agent action (tool use, memory writes) will be logged with a timestamp, agent/user ID, and session ID for full traceability. 
- Identity, Authentication, and Agent Authorization: Each agent service will have a distinct, manageable machine identity (GCP Service Account) with least-privilege IAM roles. 



### Security Testing

  * **Comprehensive Testing:** The system will undergo comprehensive security testing as defined in **NFR47 (Security & Privacy - Application Security Testing)**. This includes:
      * Static Application Security Testing (SAST)
      * Dynamic Application Security Testing (DAST)
      * LLM-based Security Reviews
      * Manual Penetration Testing

