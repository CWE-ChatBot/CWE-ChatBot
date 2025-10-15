# Security

This section defines the mandatory security requirements for AI and human developers, focusing on implementation-specific rules, referencing security tools from the Tech Stack, and defining clear patterns for common scenarios. These rules directly impact code generation.

## Input Validation

  * **Validation Library:** Python libraries such as [Pydantic](https://pydantic-docs.helpmanual.io/) will be used for defining and validating data schemas for API requests and internal data structures, particularly within FastAPI/Chainlit endpoints.
  * **Validation Location:** Input validation shall occur at all system entry points, including API boundaries (e.g., Chainlit message handlers, custom backend endpoints) and data ingestion points (CWE Data Ingestion Service).
  * **Required Rules:** All external inputs MUST be rigorously validated (NFR8). A **whitelist approach** (explicitly allowing known safe inputs) is preferred over a blacklist approach (blocking known bad inputs). Inputs must be sanitized to prevent common web vulnerabilities like Cross-Site Scripting (XSS), SQL Injection, and Prompt Injection (NFR8).

## AI & Prompt Security

* **Input Guardrails (Pre-LLM):** All user input must be sanitized before being sent to an LLM to detect and neutralize prompt injection patterns (**T-1**). Primary control: Google Model Armor. Secondary control: Meta Llama Guard.  
* **Output Validation (Post-LLM):** All responses from LLMs must be scanned to prevent the leaking of confidential system prompts or instructions (**I-2**). Same two layers apply, with legacy sanitizer as tertiary fallback. For streaming, post-sanitization buffers server-side to prevent unsafe tokens reaching clients mid-stream.  
* **Consensus Decisioning:** Majority vote across available layers determines allow/transform/block; disagreements invoke the legacy sanitizer as a tie-breaker. Unsafe outputs are transformed/redacted with rationale and logged.  
* **Resilience:** Circuit breakers protect against upstream AI guard failures; bounded retries with jitter; graceful degradation to remaining layers.  
* **Observability:** Structured audit logs include decision, categories, confidence, policy/version, and timing; CRITICAL severity for blocks; stable payload hashes only (no raw payload). Metrics exported for rate, latency, error, and category distributions.  
* **Feature Flags & Roles:** Rollout controlled via `MODEL_ARMOR_ENABLED` and `LLAMA_GUARD_ENABLED`. Sensitivity and policy templates are role-aware (admin, analyst, viewer).  
* **Untrusted BYO Endpoints:** All user-configured BYO LLM endpoints are treated as untrusted external services. Requests route through a sandboxed egress proxy where applicable; all I/O passes through the AI security pipeline (**S-3**, **I-4**).  
* **LLM Tooling Permissions:** If/when the LLM is granted access to internal tools, a strict, user-permission-based authorization model must be implemented to prevent abuse (**E-2**).

## Network Edge Protections (LB/WAF)

* **Global HTTP(S) Load Balancer:** Terminates TLS and fronts Cloud Run; enforces HTTPS-only traffic paths.  
* **Cloud Armor Policies:**
  * Managed rulesets for common web threats and L7 DDoS protections.
  * Per-IP and per-identity rate limiting per S-1.1, tuned to app SLOs (burst/sustained).  
  * IP reputation and geo-based controls; custom rules for chatbot-specific abuse patterns.  
  * Logging and preview mode usage for safe rollout of new protections.  
* **Request Flow:** User → Global LB → Cloud Armor evaluation → Cloud Run (Chainlit) → AI Security Pipeline → RAG/LLM → Post-LLM sanitization.  
* **Budget & Quotas:** Quota/budget alerts on upstream AI guardrails; anomaly detection and escalation paths defined.

## Model Armor Configuration Summary

* **Endpoint:** `modelarmor.{location}.rep.googleapis.com` (regional; required)
* **IAM:** `roles/modelarmor.user` granted to service accounts
* **Template:** `projects/<project>/locations/<region>/templates/llm-guardrails-default`
* **Toggle:** `MODEL_ARMOR_ENABLED=true`
* **Behavior:** Fail-closed on errors/timeouts; generic user messaging; see docs/LLM_GUARDRAILS.md for latency profile and runbooks.
  
## Authentication & Authorization

  * **Auth Method:** **OAuth 2.0 / OpenID Connect** (via providers like Google, GitHub) will be the primary authentication mechanism (FR19, NFR33, NFR34). Chainlit's built-in authentication hooks will be leveraged.
  * **Session Management:** Token-based sessions (e.g., JWTs issued by the OAuth provider and managed by the backend) will be used for user session management, ensuring statelessness where appropriate.
  * **Required Patterns:**
      * Authentication and authorization checks will be enforced at the earliest possible point in the request lifecycle (e.g., Chainlit decorators, FastAPI dependencies).
      * Role-based access control (RBAC) will be applied using roles managed by the User Management Service (FR4, NFR34) to restrict access to sensitive functionalities or data based on user privileges.

## Secrets Management

  * **Development:** Sensitive credentials for local development will be managed via `.env` files (excluded from version control). For cloud development/staging environments, **Google Secret Manager** will be used.
  * **Production:** **Google Secret Manager** will be the definitive solution for storing and managing all production secrets (API keys, database credentials, LLM keys/tokens).
  * **Code Requirements:**
      * **NEVER hardcode secrets** directly in code or commit them to version control.
      * Secrets shall only be accessed through a centralized, secure configuration loading mechanism that integrates with Google Secret Manager or Chainlit's secure configuration.
      * No secrets will be logged or exposed in error messages (NFR33).

## API Security

  * **Rate Limiting:** The system will implement **per-user quotas and overall rate limits** (NFR10) to protect against abuse, resource exhaustion, and Denial of Service (DoS) attempts on public-facing APIs or the Chainlit interface.
  * **CORS Policy:** A strict [CORS (Cross-Origin Resource Sharing)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) policy will be enforced on all web-exposed endpoints, allowing requests only from explicitly whitelisted origins.
  * **Security Headers:** Standard HTTP security headers (e.g., Content-Security-Policy, X-Content-Type-Options, X-Frame-Options) will be applied to all web responses to mitigate common client-side attacks.
  * **HTTPS Enforcement:** All communications, both external and internal where possible, MUST enforce **HTTPS/TLS** (NFR4) to ensure data encryption in transit.

## Data Protection

  * **Encryption at Rest:** All sensitive data stored in the Traditional Database (PostgreSQL) and the Vector Database (Pinecone/managed service) will be encrypted at rest, leveraging the cloud provider's managed encryption capabilities.
  * **Encryption in Transit:** All data transmission will be encrypted using HTTPS/TLS (NFR4).
  * **PII Handling:** User login ID, email, and credentials are classified as PII (NFR33) and will be handled in full compliance with **GDPR requirements**. This includes data minimization, secure storage, access restrictions, and defined data retention policies (NFR39).
  * **Logging Restrictions:** No PII, sensitive user queries, or confidential code snippets shall be logged in plain text. Logging will adhere to data minimization principles (NFR33).

## Dependency Security

  * **Scanning Tool:** Automated dependency vulnerability scanning tools (e.g., [Dependabot](https://github.com/features/security/), [Snyk](https://snyk.io/), [Trivy](https://aquasecurity.github.io/trivy/)) will be integrated into the CI/CD pipeline (NFR47).
  * **Update Policy:** A regular policy for reviewing and applying dependency updates, prioritizing critical security patches and known vulnerabilities, will be established.
  * **Approval Process:** A formal process for reviewing and approving new third-party dependencies will be followed to minimize supply chain risks.


## Runtime Hardening

To protect the production environment, the following runtime hardening principles will be applied:

- Harden the Virtual Machine (Base Level): The Cloud Run environment will be based on minimal, hardened base images. All unnecessary services and packages will be removed. Network access will be restricted by default. 
- Contain the Agentic Runtime: The Chainlit application will be containerized. Where it executes tools (like code interpreters in the future), it will do so in a sandboxed environment to restrict syscalls and filesystem access. 
- Secure the Agent's Memory, Tools, and Context: In-memory state will be encrypted where feasible and auto-cleared at session end. All tool calls will be validated at runtime. 
- Observability + Forensics: Every agent action (tool use, memory writes) will be logged with a timestamp, agent/user ID, and session ID for full traceability. 
- Identity, Authentication, and Agent Authorization: Each agent service will have a distinct, manageable machine identity (GCP Service Account) with least-privilege IAM roles. 



## Security Testing

  * **Comprehensive Testing:** The system will undergo comprehensive security testing as defined in **NFR47 (Security & Privacy - Application Security Testing)**. This includes:
      * Static Application Security Testing (SAST)
      * Dynamic Application Security Testing (DAST)
      * LLM-based Security Reviews
      * Manual Penetration Testing
