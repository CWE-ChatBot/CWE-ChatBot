# External APIs

This section identifies and documents the external APIs and data integrations that the CWE ChatBot will rely on. For each integration, details regarding its purpose, access methods, and any relevant constraints are provided.

## 1\. LLM / Embedding Model API (User-defined / Vertex AI)

  * **Purpose:** To provide core natural language understanding, text generation, and embedding capabilities, essential for the chatbot's conversational intelligence and Retrieval Augmented Generation (RAG) process. This covers both user-provided (BYO) and potentially centrally managed LLMs.
  * **Documentation:** Varies significantly based on the specific LLM/Embedding model provider (e.g., OpenAI API documentation, Google Cloud Vertex AI documentation, Hugging Face API documentation, or documentation for a self-hosted LLM).
  * **Base URL(s):** User-configurable endpoint (e.g., `https://api.openai.com/v1/`, `https://us-central1-aiplatform.googleapis.com/v1/projects/...`, or a custom URL for a self-hosted model).
  * **Authentication:** API Key (standard for most commercial LLMs, provided by user for FR28, securely stored), or specific token/header-based authentication for self-hosted models.
  * **Rate Limits:** Varies per provider/model. These limits must be monitored and accounted for to prevent service degradation and manage costs (NFR10).
  * **Key Endpoints Used:**
      * `POST /v1/chat/completions` (or equivalent): For conversational turn inference.
      * `POST /v1/embeddings` (or equivalent): For generating vector embeddings for CWE data and user queries.
  * **Integration Notes:** The system will dynamically switch between LLM endpoints based on user configuration (FR28, FR29). Robust error handling and fallback mechanisms are required for API failures (NFR38).

## 2\. OAuth Providers (e.g., Google, GitHub)

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

## 3\. MITRE CWE Data Source (XML/JSON Feeds)

  * **Purpose:** To provide the official, canonical Common Weakness Enumeration (CWE) corpus data, which forms the foundational knowledge base for the chatbot's information retrieval.
  * **Documentation:** MITRE CWE website, specifically their data feeds section (e.g., `https://cwe.mitre.org/data/downloads.html`).
  * **Base URL(s):** `https://cwe.mitre.org/data/xml/` (for XML files) or `https://cwe.mitre.org/data/json/` (for JSON files).
  * **Authentication:** None (publicly available data).
  * **Rate Limits:** Standard web server download limits. Continuous polling at high frequency is not expected or supported.
  * **Key Access:** Direct file download of the latest XML or JSON `*.zip` archives (e.g., `cwe_latest.xml.zip`) (Story 1.3, NFR18).
  * **Integration Notes:** The CWE Data Ingestion Service will be responsible for periodically downloading, parsing, and processing these files. Robust error handling for network issues or unexpected file formats is required.
