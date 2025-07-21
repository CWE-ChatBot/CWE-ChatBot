# APPLICATION THREAT MODEL

## ASSETS
- User Credentials and Tokens  
  OAuth 2.0 access tokens, refresh tokens, JWTs issued by external providers.
- User Profile Data  
  `User` records: id, email, role, preferences, BYO LLM API key references.
- Conversation and Message Data  
  `Conversation` and `Message` tables: chat history, session context, feedback flags, suggested CWE IDs, LLM model metadata.
- LLM API Keys and Endpoints  
  User-provided BYO LLM API keys and endpoints stored in `User.llmModelConfig`.
- Vector Database Embeddings and Metadata  
  CWE embeddings, embedding vectors, associated metadata (`CweEmbedding`).
- Traditional Database (Cloud SQL) Data  
  Structured data in PostgreSQL: users, conversations, messages.
- CWE Corpus Data  
  Raw CWE XML/JSON from MITRE ingested via the data ingestion pipeline.
- Application Configuration  
  Environment variables, Terraform/IaC definitions, Dockerfiles, Chainlit configuration.
- Logs and Audit Trails  
  Structured logs in Google Cloud Logging.

## TRUST BOUNDARIES
1. Internet User ↔ Chainlit Front-End UI  
2. Chainlit Front-End UI ↔ Internal Backend API (`/api/*`)  
3. Backend API ↔ External Services  
   - OAuth Providers  
   - Cloud SQL (PostgreSQL)  
   - Vector Database (Pinecone/Weaviate)  
   - LLM/Embedding API (BYO or Vertex AI)  
   - Cloud Logging  
4. Data Ingestion Service ↔ MITRE CWE Data Source  
5. Backend API ↔ Guardrails Service (LlamaFirewall)

## DATA FLOWS
- DF1: User (browser) → Web UI (HTTP/WebSocket) **[Crosses TB1]**  
- DF2: Web UI → Backend API (HTTP POST/GET to `/api/*`) **[Crosses TB2]**  
- DF3: Backend API ↔ OAuth Provider for token exchange/validation **[Crosses TB3]**  
- DF4: Backend API → Cloud SQL for user, conversation, message operations **[Crosses TB3]**  
- DF5: Backend API → Cloud Logging for event/audit logs **[Crosses TB3]**  
- DF6: Backend API → NLP/AI Service (in-process or internal API)  
- DF7: NLP/AI Service → LLM/Embedding API for embeddings and completions **[Crosses TB3]**  
- DF8: NLP/AI Service → Vector Database for similarity search **[Crosses TB3]**  
- DF9: Data Ingestion → MITRE CWE XML/JSON feed download **[Crosses TB4]**  
- DF10: Data Ingestion → Vector Database & Cloud SQL for storing embeddings & metadata **[Crosses TB3]**  

## APPLICATION THREATS

| THREAT ID | COMPONENT NAME       | THREAT NAME                                                                                                   | STRIDE CATEGORY     | WHY APPLICABLE                                                                                       | HOW MITIGATED                                                                                                                        | MITIGATION                                                                                                                                                                                   | LIKELIHOOD EXPLANATION                                                                                                      | IMPACT EXPLANATION                                                                                              | RISK SEVERITY |
|-----------|----------------------|---------------------------------------------------------------------------------------------------------------|---------------------|------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|--------------|
| 0001      | Backend API          | Attacker forges or replays an OAuth/JWT token to impersonate another user                                      | Spoofing            | Uses bearer tokens for authentication; relies on external JWTs                                       | Chainlit Authentication hooks validate tokens via OAuth provider; checks expiry                                                          | Enforce JWT signature validation with provider’s public keys; validate audience, issuer, and expiry; implement short token TTLs                                           | Medium: token theft or replay is feasible if tokens are exposed                                                   | High: unauthorized access to chat history, user settings, BYO LLM configs                                       | High         |
| 0002      | Web UI               | Cross-Site Scripting (XSS) via malicious user-supplied message content                                         | Tampering           | Chainlit UI renders markdown from user messages; custom components may show HTML                  | Chainlit sanitizes basic Markdown but custom UI elements may bypass filters                                                           | Whitelist allowed HTML tags; enforce sanitization on markdown and user content; use a secure renderer (e.g., DOMPurify)                                                    | Medium: user can attempt script injection in chat messages                                                      | High: session cookies or tokens could be stolen; UI compromised                                             | High         |
| 0003      | TraditionalDB        | SQL Injection through unsanitized user configuration or message parameters                                     | Tampering           | Backend constructs queries for user config and messages                                             | Repository Pattern abstracts DB access; uses parameterized queries via ORM                                                           | Enforce strict input validation with Pydantic; always use parameterized queries; add query logging and alerts on anomalies                                              | Low: repository pattern reduces raw SQL, but risk remains if raw queries are used                            | High: full DB compromise or data modification                                                        | High         |
| 0004      | NLP/AI Service       | Prompt injection: malicious user input alters RAG prompt leading to misinformation or LLM misuse               | Tampering           | Queries are concatenated with CWE context for LLM; no strict prompt templates                      | LlamaFirewall guardrails validate some response patterns                                                                              | Pre-sanitize user input; wrap user queries in a fixed prompt template; enforce guardrail policies; use instruction-level sanitization                                     | Medium: typical vector RAG pipelines are vulnerable to injection                                          | Medium: incorrect or malicious advice provided                                                      | Medium       |
| 0005      | Vector Database      | Unauthorized access or exfiltration of CWE embeddings and metadata                                             | Information Disclosure | Vector DB is externally managed with API key; metadata includes full CWE text                     | API key stored in environment variable; network restricted by default in GCP                                                           | Store vector DB API key in Secret Manager; enforce IP allow-list or VPC peering; rotate keys regularly; enable audit logs                                              | Low-Medium: key leakage possible if env vars logged or exposed                                               | Medium: attacker gains insight into internal knowledge base                                           | Medium       |
| 0006      | LLM/Embedding API    | Denial of Service by exhausting rate limits or quota on the external LLM API                                  | Denial of Service   | BYO LLM or Vertex AI has per-key rate limits; high-volume requests possible                         | No rate limiting currently configured                                                                                        | Implement per-user and global rate limits; enforce exponential backoff on 429 responses; monitor usage in real time                                                 | Medium: uncontrolled user queries can hit quotas                                                           | Medium: service unavailability for legitimate users                                                   | Medium       |
| 0007      | Backend API          | Privilege escalation by updating own role to Admin via `/user/config` endpoint                                | Elevation of Privilege | `PUT /user/config` allows changes to `role` field without restriction                              | Chainlit authentication ensures user identity but no role change guard                                                            | Enforce server-side checks: only Admins may assign or change `role`; separate endpoint for admin role management; audit role changes                                 | Medium: API can be called by authenticated users                                                     | High: unauthorized access to sensitive features                                                    | High         |
| 0008      | Backend API          | Exposure of BYO LLM API key in logs or error messages                                                          | Information Disclosure | `llm_api_key` may be logged if exceptions include full config                                      | Exceptions printed in console; no structured masking                                                                               | Mask sensitive fields in logs; configure logger to omit `llm_api_key`; use structured logging with field filtering                                           | Medium: inexperienced logging may include secrets                                                      | High: attacker could use stolen key for arbitrary LLM calls                                       | High         |
| 0009      | Data Ingestion       | Tampering of MITRE CWE feed leading to ingestion of malicious or incorrect CWE data                           | Tampering           | Pipeline downloads XML/JSON over HTTPS without integrity verification                               | Uses HTTPS but does not verify checksum or digital signature                                                                | Fetch published checksum/signature from MITRE; verify archive integrity before processing; run ingestion in restricted service account                              | Low-Medium: MITRE feed rarely malicious, but attacker-in-the-middle threat if no integrity check     | Medium: responses may reference incorrect or malicious CWE info                            | Medium       |
| 0010      | Logging Service      | Incomplete or missing audit logs enabling repudiation of user actions                                          | Repudiation         | Logs routed to Cloud Logging but may lack correlation_id or user_id metadata                        | Logging configured but no explicit correlation id or user context shown                                                           | Enrich logs with `correlation_id`, `user_id`, `session_id` fields; enforce structured logging standards                                                     | Medium: developers may overlook adding context                                                   | Low-Medium: hinders forensic investigation                                                | Low          |

---

# DEPLOYMENT THREAT MODEL

## Possible Deployment Solutions
- Centralized Cloud Hosting on GCP (Cloud Run, Cloud SQL, Managed Vector DB)  
- Self-Hosted Option (on-prem containers, self-hosted vector DB)  

Selected Architecture for Threat Modeling: Centralized Cloud Hosting on Google Cloud Run with Cloud SQL, Managed Vector DB, Secret Manager, Artifact Registry.

## ASSETS
- Container Images in Artifact Registry  
- Cloud Run Service endpoints and traffic routing  
- Cloud SQL (PostgreSQL) instance and credentials  
- Managed Vector Database API endpoint and credentials  
- GCP Secret Manager secrets (DB credentials, LLM API keys)  
- Terraform state and IaC definitions  
- Service account keys and IAM roles/policies  
- VPC connectors or private network peering  
- GitHub repository and GitHub Actions configuration  

## TRUST BOUNDARIES
1. Internet ↔ Cloud Run public endpoint  
2. Cloud Run ↔ Cloud SQL (private IP or managed endpoint)  
3. Cloud Run ↔ Vector Database API  
4. Cloud Run ↔ Secret Manager  
5. Cloud Run ↔ Artifact Registry (pull images)  
6. GitHub Actions ↔ Google Cloud Build / GCP APIs  
7. Developer Workstation ↔ GitHub Repository  

## DEPLOYMENT THREATS

| THREAT ID | COMPONENT NAME   | THREAT NAME                                                          | WHY APPLICABLE                                                                                                 | HOW MITIGATED                                                                                      | MITIGATION                                                                                                                                                                | LIKELIHOOD EXPLANATION                                                                | IMPACT EXPLANATION                                                           | RISK SEVERITY |
|-----------|------------------|----------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|--------------|
| 0001      | Artifact Registry | Container image tampering: pushing malicious or altered image        | Images used to deploy Cloud Run; if registry compromised, malicious code runs in production                    | Registry IAM limited to CI service account; images signed if enabled                               | Enable binary authorization/image signing; enforce vulnerability scanning on images; restrict push permissions to few principals                                   | Low-Medium: insider or compromised CI account could push bad image                 | High: arbitrary code execution in production                                | High         |
| 0002      | Secret Manager   | Unauthorized access to secrets (DB credentials, API keys)            | Cloud Run reads secrets; overly permissive IAM roles could expose secrets                                       | Secrets stored in Secret Manager; IAM grants limited to service account                             | Apply least-privilege IAM policies; enable CMEK; audit Secret Manager access; use dedicated service account                                                | Low: IAM policies can be misconfigured                                             | High: stolen credentials enable full environment compromise                | High         |
| 0003      | Cloud Run        | Public endpoint misconfiguration allowing unauthenticated access     | Default Cloud Run may allow unauthenticated invocations                                                        | Authentication hooks in Chainlit but Cloud Run ingress may permit public without JWT check         | Disable unauthenticated invocations at Cloud Run level; require IAM or auth header; enforce Cloud Armor in front                                      | Medium: Cloud Run default settings often leave unauthenticated access enabled     | High: bypasses application-level auth, full data access                  | High         |
| 0004      | Cloud SQL        | Network-level eavesdropping or MITM if TLS not enforced               | Cloud Run → Cloud SQL traffic; by default TLS supported but must be enforced                                   | Cloud SQL supports TLS but client must enforce `sslmode=require`                                      | Enforce TLS connections with `sslmode=require`; verify server certificates; restrict Cloud SQL to private network or VPC                                              | Low: GCP internal network is private, but misconfig can disable TLS             | Medium: intercept DB credentials or data in transit                       | Medium       |
| 0005      | Terraform State  | Leak of Terraform state file containing secrets or passwords         | IaC definitions likely reference secrets; state stored remotely/shared                                          | `.gitignore` excludes local `.tfstate`; remote state backend configured but access controls unclear | Store state in secured backend (e.g., GCS bucket with IAM), encrypt at rest, limit access; remove secrets from state via vault integration                                 | Medium: misconfigured storage backend or broad access                          | Medium-High: state leak reveals GCP service account keys, DB creds      | High         |
| 0006      | GitHub Actions   | Compromise of GitHub Actions secrets leading to unauthorized deploys | CI/CD uses GitHub Actions; secrets stored in GitHub may leak or be abused                                      | Secrets masked in logs; access limited to repo admins                                              | Rotate Actions secrets frequently; restrict write access; enable GitHubOIDC to GCP instead of long-lived keys; audit Actions workflows                                          | Medium: common source of secret leaks                                             | High: attacker can deploy malicious code or reconfigure infra           | High         |

---

# BUILD THREAT MODEL

## ASSETS
- Source Code Repository (monorepo) in GitHub  
- CI/CD Pipelines (GitHub Actions workflows, Cloud Build triggers)  
- Build Configuration (Dockerfiles, `pyproject.toml`, requirements)  
- Build Logs and Artifacts (test reports, container layers)  
- Dependency Manifests (`poetry.lock`, `requirements.txt`)  
- GitHub Actions Secrets (GCP credentials, Docker registry tokens)  
- Container Registry Images prior to deployment  

## TRUST BOUNDARIES
1. Developer Workstation ↔ GitHub Repository (git push/pull)  
2. GitHub Actions Runner ↔ Container Registry (docker push/pull)  
3. GitHub Actions Runner ↔ GCP (Cloud Build, Secret Manager)  
4. GitHub Actions Runner ↔ GitHub Secrets store  
5. Local CLI (Poetry/Docker) ↔ Developer environment variables  

## BUILD THREATS

| THREAT ID | COMPONENT NAME       | THREAT NAME                                                               | WHY APPLICABLE                                                                                     | HOW MITIGATED                                                                                | MITIGATION                                                                                                                                                                | LIKELIHOOD EXPLANATION                                                            | IMPACT EXPLANATION                                                        | RISK SEVERITY |
|-----------|----------------------|---------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|------------------------------------------------------------------------------|--------------|
| 0001      | GitHub Repository    | Malicious commit injection by compromised developer or malicious PR merge  | Monorepo controls all code; unreviewed PRs could introduce backdoors                              | Peer review process in place; required approvals configured                                  | Enforce branch protection rules; require multiple reviewers; enable CODEOWNERS; use signed commits                                                          | Medium: social engineering or stolen dev credentials                             | High: malicious code can run in prod or CI                                   | High         |
| 0002      | GitHub Actions       | Exposure of GCP credentials in build logs                                   | Secrets used in Actions; logs may inadvertently print env vars                                    | GitHub masks secrets in logs by default                                                      | Audit workflows to avoid `echo $SECRET`; use least-privilege service accounts; review logs for leaks                                                 | Medium: accidental `print` or debug statements                                     | High: attacker obtains GCP service account tokens                          | High         |
| 0003      | Dependency Management | Supply chain attack via malicious Python package dependency               | Uses public PyPI packages (`chainlit`, `langchain`, etc.); dependency compromise risk exists      | Dependabot or similar scanners may be configured                                              | Pin all dependencies to specific versions; enable SBOM generation; regularly scan dependencies with Snyk/Trivy; enforce dependency approval process              | Medium: public ecosystem often targeted                                            | Medium-High: malicious library in prod                                     | High         |
| 0004      | Docker Build         | Dockerfile misconfiguration leading to inclusion of secrets in image       | Dockerfile uses build args and env; risk of `ENV SECRET` or copying `.env`                       | `.dockerignore` includes `.env`; build args limited                                           | Review Dockerfile for unintended `COPY .env`; use multi-stage builds with no secret copying; remove build-time secrets after use                               | Low-Medium: developer error possible                                             | Medium: container may carry sensitive data                                 | Medium       |
| 0005      | CI/CD Pipeline       | Lack of SAST or dependency scanning allowing code with vulnerabilities     | GitHub Actions configured for tests but no explicit security scans shown                          | Pytest and Ruff run; no explicit SAST or dependency scan                                      | Integrate SAST (e.g., Bandit) and DAST scanning steps in pipeline; fail build on high-severity findings                                                       | Medium: missing pipeline steps common                                           | Medium: unpatched security flaws in production code                        | Medium       |
| 0006      | Container Registry   | Unauthorized push or pull from registry leading to rogue image deployment | Registry credentials stored in CI; compromised runner can push or pull arbitrary images           | Registry tokens scoped to specific repository                                               | Use ephemeral short-lived tokens via GitHub OIDC; restrict registry IAM roles; enable image signing and enforcement                                              | Medium: CI credentials compromise possible                                     | High: attacker can deploy malicious container                           | High         |

---

# QUESTIONS & ASSUMPTIONS

- Q1: Is Cloud Run configured to disallow unauthenticated invocations at the platform level, or is authentication purely at application layer?  
- Q2: Are Pydantic validation schemas applied to all user input (e.g., conversation messages), or only to config endpoints?  
- Q3: Does the data ingestion pipeline verify MITRE feed checksums or use any signature mechanism?  
- Q4: Are there defined SLA or quotas for the BYO LLM endpoint to support rate limiting?  
- Q5: How is secret rotation handled for user-provided LLM API keys and service account credentials?  
- Q6: Is there a staging environment with identical trust boundaries for pre-production testing?  

Assumptions:  
- All HTTP communications enforce HTTPS/TLS.  
- Cloud SQL and Vector DB are configured with default encryption at rest.  
- Guardrails (LlamaFirewall) are deployed inline with the Backend API and enforce policy.  
- GitHub Actions uses branch protection rules and required reviews.  
- Secret Manager is the primary store for production secrets; environment variables for local development only.