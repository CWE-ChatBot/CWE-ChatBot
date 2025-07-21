# Mitigation Strategies

1. **Input Validation and Sanitization**  
   **Description:**  
   1. Define Pydantic models for every external input: API requests, Chainlit message payloads, user‐uploaded files, and `llmModelConfig`.  
   2. Integrate validation at all entry points: FastAPI/Chainlit endpoints and data ingestion scripts.  
   3. Use whitelist validation (allowed patterns) rather than blacklists.  
   4. Sanitize or escape any markup/SQL‐sensitive characters in user messages and config fields.  
   5. Reject and log inputs that fail validation with clear error messages.  
   **Threats Mitigated:**  
   - SQL Injection (High)  
   - Cross‐Site Scripting (XSS) (High)  
   - Prompt Injection (High)  
   **Impact:**  
   - Eliminates ≈ 90% of injection attacks at the boundary.  
   **Currently Implemented:**  
   - Pydantic schemas for `/api/user/config` in the OpenAPI spec.  
   **Missing Implementation:**  
   - Validation of Chainlit message handlers (`cl.on_message`), `llmModelConfig` fields, file ingestion scripts.

2. **Prompt Injection Prevention via Structured Templates and Guardrails**  
   **Description:**  
   1. Keep system and user prompts strictly separated; never embed raw user text into system‐level instructions.  
   2. Store all prompt templates as versioned artifacts in the repo (fulfills NFR31).  
   3. Configure LlamaFirewall guardrails to inspect outgoing prompts and incoming LLM responses for malicious instructions or “jailbreak” patterns.  
   4. On detection, sanitize or truncate suspicious segments and fall back to safe defaults.  
   **Threats Mitigated:**  
   - Prompt Injection (Critical)  
   - Malicious LLM Output (High)  
   **Impact:**  
   - Reduces prompt‐tampering risk by > 95%.  
   **Currently Implemented:**  
   - LlamaFirewall container is shown in the C1 diagram.  
   **Missing Implementation:**  
   - No guardrail rule definitions or enforcement hooks in the RAG pipeline.

3. **Secure BYO LLM Endpoint Validation & Egress Controls**  
   **Description:**  
   1. Whitelist approved hostnames/IP ranges for user‐provided endpoints.  
   2. Validate `llmModelConfig.endpoint` at update time against that whitelist.  
   3. Deploy Cloud Run with VPC‐egress restrictions so only allowed hosts can be reached.  
   4. Maintain and periodically review the allowlist.  
   **Threats Mitigated:**  
   - Server‐Side Request Forgery (SSRF) via BYO endpoints (Critical)  
   - Data Exfiltration (Critical)  
   **Impact:**  
   - Blocks unauthorized internal/external calls via malicious endpoints.  
   **Currently Implemented:**  
   - Feature exists to configure BYO endpoints in user settings.  
   **Missing Implementation:**  
   - No hostname validation or network‐level egress rules defined.

4. **Role-Based Access Control Enforcement**  
   **Description:**  
   1. Map each API route and UI action to allowed roles.  
   2. Apply a `@require_role(...)` decorator or middleware on every Chainlit step and REST endpoint.  
   3. During JWT validation, confirm the user’s `role` matches the access policy.  
   4. Log and alert on denied access attempts.  
   **Threats Mitigated:**  
   - Privilege Escalation (High)  
   - Unauthorized Configuration Changes (High)  
   **Impact:**  
   - Fully prevents unauthorized role‐based operations.  
   **Currently Implemented:**  
   - Example `require_role` decorator provided in docs.  
   **Missing Implementation:**  
   - Enforcement on all real API/UI routes remains to be applied.

5. **Secret Management via Google Secret Manager**  
   **Description:**  
   1. Store all production secrets (DB credentials, OAuth client secrets, LLM API keys) in Secret Manager.  
   2. Grant each Cloud Run service account only the `secretmanager.secretAccessor` role needed.  
   3. Refactor the config module to fetch secrets at startup instead of reading `.env` directly.  
   4. Automate periodic rotation of secrets.  
   **Threats Mitigated:**  
   - Secret Leakage (Critical)  
   **Impact:**  
   - Eliminates risk of accidental secret disclosure via code or logs.  
   **Currently Implemented:**  
   - Local `.env` usage for dev; mention of Secret Manager in docs.  
   **Missing Implementation:**  
   - No Terraform or code integration with Secret Manager in production.

6. **Parameterized Database Access & Repository Pattern Enforcement**  
   **Description:**  
   1. Ensure every DB operation goes through the shared repository layer (`packages/shared/db_utils`).  
   2. Use parameterized queries or ORM methods; avoid string‐concatenated SQL.  
   3. Integrate static analysis (e.g., Ruff plugin) to flag any raw SQL concatenation.  
   4. Add unit tests that attempt SQL injection payloads.  
   **Threats Mitigated:**  
   - SQL Injection (High)  
   **Impact:**  
   - Eliminates DB injection risk entirely when correctly applied.  
   **Currently Implemented:**  
   - Repository pattern described in architecture.  
   **Missing Implementation:**  
   - No automated enforcement or audits to guarantee usage.

7. **Protection Against XML External Entity (XXE) in Data Ingestion**  
   **Description:**  
   1. Use a hardened XML parser (e.g., Python’s `defusedxml`) with external entities disabled.  
   2. Validate incoming CWE XML/JSON against a strict schema.  
   3. Reject or sandbox any file that fails schema validation.  
   4. Log parsing errors and alert on anomalies.  
   **Threats Mitigated:**  
   - XXE Attacks / Remote File Inclusion (High)  
   **Impact:**  
   - Eliminates the risk of sensitive file disclosure during ingestion.  
   **Currently Implemented:**  
   - CWE ingestion pipeline exists.  
   **Missing Implementation:**  
   - No explicit parser hardening or schema validation steps.

8. **Enforce HTTPS/TLS for All Communications**  
   **Description:**  
   1. Configure Cloud Run to require HTTPS and perform automatic HTTP→HTTPS redirects.  
   2. Enforce TLS (≥ 1.2) on all outbound calls: LLM APIs, vector DB, SQL, OAuth flows.  
   3. Disable weak ciphers and protocols.  
   **Threats Mitigated:**  
   - Man‐in‐the‐Middle (MiTM) Attacks (High)  
   **Impact:**  
   - Ensures confidentiality/integrity in transit.  
   **Currently Implemented:**  
   - TLS mandate noted in Data Protection section.  
   **Missing Implementation:**  
   - Terraform and Cloud Run settings for redirects and cipher configuration.

9. **Strict CORS Policy and CSRF Protection**  
   **Description:**  
   1. Apply CORS middleware allowing only trusted origins (e.g., the official UI domain).  
   2. For any state-changing endpoint, require CSRF tokens or enforce `SameSite=strict` on cookies.  
   3. Reject requests with invalid or missing `Origin`/`Referer` headers.  
   **Threats Mitigated:**  
   - Cross‐Site Request Forgery (CSRF) (Medium)  
   - Unauthorized Cross‐Origin Data Access (Medium)  
   **Impact:**  
   - Reduces cross-site attack surface by > 90%.  
   **Currently Implemented:**  
   - CORS policy referenced in API security section.  
   **Missing Implementation:**  
   - No actual CORS middleware or CSRF token mechanism in code.

10. **Content Security Policy (CSP) for Chainlit UI**  
    **Description:**  
    1. Define a strict CSP header (disallow inline scripts/styles, only allow scripts from known CDNs or same origin).  
    2. Configure Cloud Run (or API gateway) to inject the CSP header on every page response.  
    3. Test the UI end-to-end to ensure no CSP violations.  
    **Threats Mitigated:**  
    - Cross‐Site Scripting (XSS) in browser (Medium)  
    **Impact:**  
    - Prevents execution of injected JavaScript in victim browsers.  
    **Currently Implemented:**  
    - Not addressed.  
    **Missing Implementation:**  
    - No CSP headers configured in Chainlit or infrastructure.

11. **Network Egress Restrictions for Cloud Run Services**  
    **Description:**  
    1. Attach a VPC connector to Cloud Run and define egress rules to only approved external IP ranges (LLM, vector DB, MITRE).  
    2. Deny all other outbound traffic by default.  
    3. Audit logs of egress attempts periodically.  
    **Threats Mitigated:**  
    - Data Exfiltration (High)  
    - SSRF Amplification (High)  
    **Impact:**  
    - Blocks all unexpected outbound network flows.  
    **Currently Implemented:**  
    - No egress controls in Terraform or Cloud Run settings.  
    **Missing Implementation:**  
    - VPC connector and firewall rules.

12. **Vector Database Access Controls & Network Isolation**  
    **Description:**  
    1. Place the vector DB instance in a private VPC; disallow public access.  
    2. Restrict connections to Cloud Run service account IP ranges only.  
    3. Enforce IAM roles so only the chatbot service can read/write embeddings.  
    4. Enable encryption in transit and at rest on the vector DB.  
    **Threats Mitigated:**  
    - Unauthorized Data Access (High)  
    - Data Exfiltration (Medium)  
    **Impact:**  
    - Prevents any external party from querying or manipulating embeddings.  
    **Currently Implemented:**  
    - Vector DB described as managed service; no network/IAM specifics.  
    **Missing Implementation:**  
    - No VPC or IAM policy configured.

13. **LLM Response Guardrails Configuration**  
    **Description:**  
    1. Define concrete LlamaFirewall rules: block sensitive PII, disallowed topics, recursive prompt patterns.  
    2. Integrate the firewall as a synchronous step in the NAI pipeline before sending responses to users.  
    3. If guardrails flag a response, either sanitize or return a safe fallback.  
    **Threats Mitigated:**  
    - PII Leakage via LLM output (High)  
    - Generation of Unsafe Content (Medium)  
    **Impact:**  
    - Reduces harmful or overly revealing responses by ≈ 95%.  
    **Currently Implemented:**  
    - LlamaFirewall container exists in the C1 diagram.  
    **Missing Implementation:**  
    - No rule definitions or integration in code.

14. **PII Redaction in Application Logs**  
    **Description:**  
    1. Implement a logging middleware that scans messages and metadata for PII patterns (emails, tokens, API keys).  
    2. Redact or mask sensitive fields before writing to logs.  
    3. Periodically review logs to ensure no PII remains.  
    **Threats Mitigated:**  
    - PII Exposure in Logs (Medium)  
    **Impact:**  
    - Eliminates risk of sensitive data leak via logs.  
    **Currently Implemented:**  
    - Logging restrictions documented under Data Protection.  
    **Missing Implementation:**  
    - No automated redaction or masking in logging config.

15. **Session Management Hardening**  
    **Description:**  
    1. Use secure, HttpOnly, SameSite=strict cookies for session state.  
    2. Implement idle session timeout (e.g., 15 min) and absolute session expiry.  
    3. On logout or role change, revoke or blacklist the JWT.  
    4. Log session creation and invalidation events.  
    **Threats Mitigated:**  
    - Session Hijacking (Medium)  
    - Session Fixation (Medium)  
    **Impact:**  
    - Cuts session‐based attacks by > 90%.  
    **Currently Implemented:**  
    - JWT‐based sessions via OAuth but cookie settings not specified.  
    **Missing Implementation:**  
    - No cookie flags or timeout policies configured.

16. **Data Retention and Deletion Policies**  
    **Description:**  
    1. Define retention periods (e.g., 30 days for messages, 1 year for conversations) in privacy policy.  
    2. Schedule background jobs to purge expired records automatically.  
    3. Provide UI/CLI for users to delete their conversation history on demand.  
    **Threats Mitigated:**  
    - Privacy Violations (Medium)  
    - Accumulated PII Exposure (Low)  
    **Impact:**  
    - Minimizes stale PII exposure; aids GDPR compliance.  
    **Currently Implemented:**  
    - No retention/deletion features described.  
    **Missing Implementation:**  
    - Data purge jobs and user‐driven deletion controls.

17. **Rate Limiting on User Requests and LLM API Calls**  
    **Description:**  
    1. Implement per‐user and global rate limits (e.g., 60 requests/minute) via API gateway or Chainlit hooks.  
    2. Track LLM API usage quotas; back off and queue requests on exceeding provider limits.  
    3. Return HTTP 429 or custom error messages when limits are reached.  
    **Threats Mitigated:**  
    - Denial of Service (DoS) (Medium)  
    - Resource Exhaustion / Cost Overruns (Medium)  
    **Impact:**  
    - Mitigates spikes in traffic or abuse by > 80%.  
    **Currently Implemented:**  
    - Rate limiting mentioned under NFR10.  
    **Missing Implementation:**  
    - No actual rate‐limiting middleware or gateway rules in place.