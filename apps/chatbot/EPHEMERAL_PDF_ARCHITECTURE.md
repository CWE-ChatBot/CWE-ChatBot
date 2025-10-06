# Ephemeral PDF Processing Architecture

**Story**: 4.3 - Ephemeral Document Ingestion
**Status**: Production
**Security Level**: High Isolation

---

## Table of Contents
1. [Overview](#overview)
2. [Architecture Principles](#architecture-principles)
3. [System Components](#system-components)
4. [Security Isolation](#security-isolation)
5. [Authentication Flow (OIDC)](#authentication-flow-oidc)
6. [PDF Processing Workflow](#pdf-processing-workflow)
7. [Query Integration](#query-integration)
8. [Error Handling](#error-handling)
9. [Performance Considerations](#performance-considerations)

---

## Overview

The CWE ChatBot implements **ephemeral PDF processing** as a security-first architecture pattern that isolates potentially malicious PDF files from the main Chainlit application. This document describes the architectural decisions, security controls, and implementation details.

### Key Design Goals

1. **Security Isolation**: PDF processing in dedicated Cloud Functions worker (separate compute environment)
2. **No Persistence**: All PDF content processed in-memory only; zero disk writes
3. **Minimal Attack Surface**: Main app never executes PDF parsing code
4. **Service-to-Service Auth**: OIDC authentication prevents unauthorized access to PDF worker
5. **Graceful Degradation**: Failures in PDF processing don't crash the main application

---

## Architecture Principles

### 1. Defense in Depth

**Principle**: Multiple layers of security controls to protect against PDF-based attacks.

**Implementation**:
- **Layer 1**: File type validation via magic bytes (not extension-based)
- **Layer 2**: Size limits (10MB) enforced before transmission
- **Layer 3**: PDF processing in isolated Cloud Functions worker (GCP sandbox)
- **Layer 4**: Output sanitization and truncation (max 1M characters)
- **Layer 5**: Content validation before storage in user session

### 2. Least Privilege

**Principle**: Each component has minimal permissions required for its function.

**Implementation**:
- PDF worker: No database access, no Secret Manager access, no network egress (except response)
- Main app service account: `roles/run.invoker` on PDF worker only (no broader permissions)
- OIDC tokens: Scoped to single audience (PDF worker URL)

### 3. Fail-Safe Defaults

**Principle**: Failures result in safe state, not security bypass.

**Implementation**:
- PDF worker unreachable → User sees friendly error, no partial processing
- OIDC auth fails → Request rejected, no fallback to unauthenticated access
- Malformed PDF → Error message returned, no crash
- Timeout → Clean error, no zombie processes

---

## System Components

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    User Browser                             │
│  (OAuth authenticated: Google/GitHub)                       │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTPS (WebSocket)
                        ↓
┌─────────────────────────────────────────────────────────────┐
│              Chainlit App (Cloud Run)                       │
│  - main.py: Message handler                                 │
│  - file_processor.py: Orchestrates PDF processing           │
│  - conversation_manager.py: Query processing                │
│                                                              │
│  Security Controls:                                         │
│  ├─ File type detection (magic bytes)                       │
│  ├─ Size validation (10MB limit)                            │
│  ├─ OIDC token minting                                      │
│  └─ Content sanitization                                    │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTPS + OIDC Bearer Token
                        │ (Service-to-Service Auth)
                        ↓
┌─────────────────────────────────────────────────────────────┐
│         PDF Worker (Cloud Functions v2)                     │
│  - Isolated Python runtime                                  │
│  - pypdf library for PDF parsing                            │
│  - No database, no secrets, no egress                       │
│                                                              │
│  Security Controls:                                         │
│  ├─ OIDC authentication required                            │
│  ├─ PDF magic byte re-validation                            │
│  ├─ Page limit enforcement (50 pages)                       │
│  ├─ Encrypted PDF rejection                                 │
│  ├─ JavaScript/embedded content stripping                   │
│  └─ Output truncation (1M chars)                            │
└─────────────────────────────────────────────────────────────┘

Data Flow:
1. User uploads PDF via Chainlit UI
2. Main app validates file type and size
3. Main app mints OIDC token for PDF worker
4. PDF bytes + OIDC token sent to PDF worker (HTTPS POST)
5. PDF worker validates token, parses PDF, extracts text
6. Text returned to main app (JSON response)
7. Main app stores text in user session (ephemeral)
8. Text used as context for LLM query processing
9. Session cleared after response generation
```

---

## Security Isolation

### Why Isolate PDF Processing?

**Threat Model**: PDF files can contain:
- Embedded JavaScript (potential XSS if parsed unsafely)
- Malformed structures (parser exploits, buffer overflows)
- Encrypted content (password-protected PDFs)
- Excessive content (resource exhaustion attacks)
- Embedded files (polyglot attacks)

**Isolation Benefits**:

| Risk | Without Isolation | With Isolation (Current) |
|------|-------------------|--------------------------|
| PDF parser vulnerability | Main app compromise | PDF worker sandbox contains attack |
| Resource exhaustion | Main app OOM/crash | PDF worker timeout, main app unaffected |
| Malicious embedded content | Potential code execution | Sandboxed execution, no persistence |
| Supply chain attack (pypdf) | Full system access | Limited to PDF worker scope |

### Isolation Mechanisms

1. **Compute Isolation**: Cloud Functions v2 runs in separate GCP project VPC
2. **Memory Isolation**: PDF worker has independent memory allocation (512MB default)
3. **Network Isolation**: PDF worker has no egress beyond response return
4. **Filesystem Isolation**: No persistent disk; tmpfs only
5. **Process Isolation**: Each invocation runs in fresh container instance

---

## Authentication Flow (OIDC)

### Why OIDC Instead of API Keys?

**Decision**: Use OpenID Connect (OIDC) ID tokens for service-to-service authentication.

**Rationale**:
- ✅ **No Secret Storage**: ID tokens minted dynamically from GCP metadata server
- ✅ **Short-Lived**: Tokens expire in 1 hour (vs. static API keys)
- ✅ **Audience-Scoped**: Token valid only for PDF worker URL
- ✅ **Automatic Rotation**: GCP handles key rotation transparently
- ✅ **Audit Trail**: GCP logs all token minting operations

**Alternative Rejected**: Static API keys in Secret Manager
- ❌ Requires secret rotation process
- ❌ If compromised, valid until manually revoked
- ❌ Not scoped to specific audience

### OIDC Token Flow

```
┌─────────────────────┐
│  Chainlit App       │
│  (Cloud Run)        │
└──────────┬──────────┘
           │
           │ 1. Request ID token for audience
           │    Audience: https://pdf-worker-bmgj6wj65a-uc.a.run.app
           ↓
┌─────────────────────────────────────────┐
│  GCP Metadata Server                    │
│  (metadata.google.internal)             │
│                                          │
│  ├─ Verifies service account identity   │
│  ├─ Mints ID token (JWT)                │
│  └─ Signs with Google's private key     │
└──────────┬──────────────────────────────┘
           │
           │ 2. ID Token (JWT)
           │    Header: {"alg": "RS256", "kid": "..."}
           │    Payload: {
           │      "iss": "https://accounts.google.com",
           │      "aud": "https://pdf-worker-bmgj6wj65a-uc.a.run.app",
           │      "sub": "serviceAccount:cwe-chatbot-run-sa@...",
           │      "iat": 1728123456,
           │      "exp": 1728127056
           │    }
           ↓
┌─────────────────────┐
│  Chainlit App       │
│  Includes token in  │
│  Authorization hdr  │
└──────────┬──────────┘
           │
           │ 3. HTTPS POST /
           │    Authorization: Bearer <ID_TOKEN>
           │    Content-Type: application/pdf
           │    Body: <PDF bytes>
           ↓
┌─────────────────────────────────────────┐
│  PDF Worker (Cloud Run/Functions)       │
│                                          │
│  ├─ Cloud Run receives request          │
│  ├─ Verifies JWT signature (Google key) │
│  ├─ Validates audience matches self     │
│  ├─ Checks expiration (exp claim)       │
│  ├─ Validates issuer (accounts.google)  │
│  └─ Extracts service account from sub   │
└──────────┬──────────────────────────────┘
           │
           │ 4. IAM Policy Check
           │    Does cwe-chatbot-run-sa have roles/run.invoker?
           ↓
┌─────────────────────────────────────────┐
│  Cloud Run IAM Policy                   │
│  bindings:                               │
│  - members:                              │
│    - serviceAccount:cwe-chatbot-run-sa@  │
│      cwechatbot.iam.gserviceaccount.com  │
│    role: roles/run.invoker               │
└──────────┬──────────────────────────────┘
           │
           │ 5. Access GRANTED → Process PDF
           │    Access DENIED  → 403 Forbidden
           ↓
┌─────────────────────┐
│  PDF Worker         │
│  Processes PDF      │
│  Returns JSON       │
└─────────────────────┘
```

### Implementation Details

**Token Minting** (`file_processor.py`):
```python
def _fetch_token_sync() -> str:
    """Synchronous token fetch for thread pool execution."""
    import google.oauth2.id_token
    import google.auth.transport.requests as transport_requests

    # Fetch ID token using google.oauth2.id_token.fetch_id_token()
    # This is the recommended approach for Cloud Run → Cloud Run/Functions calls
    auth_req = transport_requests.Request()
    token = google.oauth2.id_token.fetch_id_token(auth_req, audience)
    return token
```

**Why ThreadPoolExecutor?**
- `fetch_id_token()` makes synchronous HTTP call to metadata server
- Blocking call in async event loop causes WebSocket disconnections
- `loop.run_in_executor()` offloads to thread pool
- Main event loop remains responsive for WebSocket heartbeats

**Token Validation** (Cloud Run handles automatically):
- Cloud Run validates JWT signature using Google's public keys
- Checks `aud` claim matches PDF worker URL
- Checks `exp` claim (expiration) is in future
- Verifies `iss` claim is `https://accounts.google.com`
- IAM policy check confirms service account has `roles/run.invoker`

---

## PDF Processing Workflow

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: File Upload (User → Chainlit)                     │
└─────────────────────────────────────────────────────────────┘
    User attaches sample.pdf to Chainlit message
    Chainlit stores file in temporary location
    main.py @cl.on_message handler triggered

    ↓

┌─────────────────────────────────────────────────────────────┐
│ Phase 2: Pre-Processing Validation (Chainlit App)          │
└─────────────────────────────────────────────────────────────┘
    file_processor.process_attachments(message)
    ├─ Read file bytes
    ├─ Check size ≤ 10MB (reject if too large)
    └─ Detect file type via magic bytes
        ├─ Starts with b'%PDF-' → PDF
        ├─ No \x00 bytes, UTF-8 valid → Text
        └─ Otherwise → Rejected (unsupported)

    ↓

┌─────────────────────────────────────────────────────────────┐
│ Phase 3: OIDC Authentication (Chainlit → GCP)              │
└─────────────────────────────────────────────────────────────┘
    get_oidc_token(audience="https://pdf-worker-bmgj6wj65a-uc.a.run.app")
    ├─ Call GCP metadata server (in thread pool)
    ├─ Receive signed JWT ID token
    └─ Token valid for 1 hour, audience-scoped

    ↓

┌─────────────────────────────────────────────────────────────┐
│ Phase 4: PDF Worker Invocation (Chainlit → PDF Worker)     │
└─────────────────────────────────────────────────────────────┘
    _call_pdf_worker_sync(pdf_bytes, url, token)  # In thread pool
    ├─ HTTP POST to PDF worker URL
    ├─ Headers:
    │   ├─ Authorization: Bearer <OIDC_TOKEN>
    │   └─ Content-Type: application/pdf
    ├─ Body: Raw PDF bytes
    ├─ Timeout: 55 seconds
    └─ Retry: 1 retry on 5xx errors (transient failures)

    ↓

┌─────────────────────────────────────────────────────────────┐
│ Phase 5: PDF Parsing (PDF Worker)                          │
└─────────────────────────────────────────────────────────────┘
    PDF Worker (Cloud Functions):
    ├─ Validate OIDC token (Cloud Run does this automatically)
    ├─ Re-check PDF magic bytes (defense in depth)
    ├─ Parse PDF with pypdf library
    ├─ Extract text from all pages
    ├─ Enforce limits:
    │   ├─ Max 50 pages (reject if exceeded)
    │   ├─ Reject encrypted PDFs
    │   └─ Strip JavaScript/embedded content
    ├─ Sanitize output:
    │   └─ Truncate to 1,000,000 characters
    └─ Return JSON:
        {
          "text": "Extracted text...",
          "pages": 2,
          "sanitized": true
        }

    ↓

┌─────────────────────────────────────────────────────────────┐
│ Phase 6: Content Storage (Chainlit App)                    │
└─────────────────────────────────────────────────────────────┘
    file_content = response['text']  # "CWE ChatBot Test Document\n..."

    ├─ Store in Chainlit user session (ephemeral):
    │   cl.user_session.set("uploaded_file_context", file_content)
    │
    ├─ Format for user display:
    │   file_info = f"\n--- File: {filename} ({pages} pages, sanitized) ---\n"
    │   extracted_content = file_info + text
    │   # Result: 118 characters total for sample.pdf
    │
    └─ Show in UI:
        file_step.output = "Extracted 118 characters from file(s) (stored as isolated evidence)"

    ↓

┌─────────────────────────────────────────────────────────────┐
│ Phase 7: Query Processing (See "Query Integration" below)  │
└─────────────────────────────────────────────────────────────┘
```

### Error Handling by Phase

| Phase | Error Condition | User-Facing Message | Internal Action |
|-------|----------------|---------------------|-----------------|
| 2 - Validation | File > 10MB | "File exceeds 10MB limit. Please upload a smaller file." | Reject upload, continue without file |
| 2 - Validation | Unsupported type | "Unsupported file type. Please upload PDF or text files." | Reject upload, continue without file |
| 3 - OIDC | Token fetch fails | "PDF processing service authentication failed." | Log error, reject upload |
| 4 - Invocation | Timeout (>55s) | "File processing timed out. Try a smaller file." | Cancel request, no retry |
| 4 - Invocation | 413 (Too Large) | "File exceeds 10MB limit." | Reject upload |
| 4 - Invocation | 422 (Invalid) | "PDF file appears to be corrupted or invalid." | Reject upload |
| 4 - Invocation | 401/403 (Auth) | "PDF processing service authentication failed." | Log error, check IAM policy |
| 4 - Invocation | 5xx (Server Error) | "PDF processing failed. Please try again." | Retry once, then fail |
| 5 - Parsing | Encrypted PDF | "Encrypted PDFs are not supported. Please remove password protection." | Reject upload |
| 5 - Parsing | > 50 pages | "PDF exceeds 50 pages. Please split into smaller documents." | Reject upload |

---

## Query Integration

### How PDF Content is Used

The extracted PDF text is stored as **isolated evidence** in the user session and integrated with the query in multiple ways depending on user input.

### Scenario 1: PDF Upload with Explicit Query

**User Action**:
- Uploads `sample.pdf`
- Types query: "What CWE vulnerabilities are mentioned in this document?"

**System Behavior**:
```python
user_query = "What CWE vulnerabilities are mentioned in this document?"
file_ctx = cl.user_session.get("uploaded_file_context")
# file_ctx = "--- File: sample.pdf (2 pages, sanitized) ---\nCWE ChatBot Test Document\n..."

# conversation_manager receives BOTH:
# 1. user_query (the question)
# 2. file_ctx (the evidence stored in context)

# Processing pipeline:
# ├─ query_processor: Sanitizes and validates query
# ├─ context.set_evidence(file_ctx): Stores PDF text as evidence
# ├─ query_handler: Searches CWE database for relevant chunks
# └─ response_generator: Generates response using:
#     ├─ User query
#     ├─ Retrieved CWE chunks (if relevant)
#     └─ PDF content (as evidence context)
```

**LLM Prompt Structure** (simplified):
```
System: You are a CWE expert assistant.

Context (Evidence from uploaded document):
--- File: sample.pdf (2 pages, sanitized) ---
CWE ChatBot Test Document
...

Retrieved CWE Information:
[CWE-79: Cross-site Scripting (XSS)]
[CWE-89: SQL Injection]
...

User Question:
What CWE vulnerabilities are mentioned in this document?

Assistant Response:
This document does not contain specific technical details or code snippets
that would allow for a direct mapping to the provided CWEs. The content is
a generic placeholder ("CWE ChatBot Test Document") and does not describe
any exploitable vulnerabilities.

To effectively perform a vulnerability assessment...
```

### Scenario 2: PDF Upload WITHOUT Query (Empty Message)

**User Action**:
- Uploads `sample.pdf`
- **Does not type any query text** (message content is empty or "...")

**System Behavior**:
```python
user_query = message.content.strip()  # Empty string or "..."
file_ctx = cl.user_session.get("uploaded_file_context")

# Before processing, check if query is empty but file was uploaded
if file_ctx and (not user_query or user_query == "..."):
    # Use default query
    user_query = "Analyze this document for security vulnerabilities and CWE mappings."
    logger.info(f"Using default query for file upload without user text")

# Now process with default query + file context
```

**Why This Fix Was Needed**:

Prior to this fix, uploading a PDF without a query caused:
```python
# query_processor.py line 247:
if not query or not query.strip():
    raise ValueError("Empty query provided")  # ← User saw "technical difficulties"
```

**Fix**: Default query ensures processing pipeline receives valid input.

### Scenario 3: Text File Upload

**User Action**:
- Uploads `vulnerability_report.txt`
- Query: "Summarize the vulnerabilities"

**System Behavior**:
```python
# file_processor detects file type via content sniffing
if b'\x00' in content:
    file_type = 'unknown'  # Binary file, reject
else:
    try:
        text = content.decode('utf-8', errors='strict')
        printable_ratio = sum(1 for c in text if c.isprintable() or c in '\n\r\t') / len(text)
        if printable_ratio >= 0.9:
            file_type = 'text'  # Process locally, no PDF worker needed
    except UnicodeDecodeError:
        file_type = 'unknown'  # Reject

# For text files:
# ├─ No PDF worker invocation (processed locally)
# ├─ No OIDC authentication needed
# ├─ Faster processing (no network call)
# └─ Same evidence storage mechanism
```

### Evidence Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│ 1. File Upload                                              │
│    User attaches PDF/text file                              │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Content Extraction                                       │
│    PDF → PDF worker (isolated)                              │
│    Text → Local processing (in-memory)                      │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Ephemeral Storage (User Session)                         │
│    cl.user_session.set("uploaded_file_context", content)    │
│    Stored in-memory in Chainlit session (not database)      │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Query Processing                                         │
│    context.set_evidence(file_ctx)                           │
│    Evidence passed to LLM as context                        │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. Response Generation                                      │
│    LLM generates response using:                            │
│    ├─ User query                                            │
│    ├─ Retrieved CWE chunks (from database)                  │
│    └─ Uploaded file content (evidence)                      │
└─────────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────────┐
│ 6. Cleanup                                                  │
│    cl.user_session.set("uploaded_file_context", None)       │
│    Evidence cleared from memory after response              │
│    No persistence to disk or database                       │
└─────────────────────────────────────────────────────────────┘
```

**Key Points**:
- ✅ Evidence stored **only** in user session (ephemeral)
- ✅ Evidence **never** written to database
- ✅ Evidence cleared after each message processing
- ✅ No cross-session contamination (each user's evidence is isolated)

---

## Performance Considerations

### WebSocket Keepalive During PDF Processing

**Problem**: PDF processing can take 3-5 seconds. During this time, the WebSocket connection can go idle and disconnect, causing JWT signature verification failures on reconnection.

**Solution**: Implement keepalive heartbeat during file processing.

**Implementation** (`main.py`):
```python
# Create a keepalive message to prevent WebSocket timeout during PDF processing
status_msg = await cl.Message(content="Processing files...").send()

# Keepalive heartbeat to prevent idle disconnects
heartbeat_running = True
async def heartbeat():
    """Send periodic updates to keep WebSocket alive during PDF processing."""
    count = 0
    while heartbeat_running:
        await asyncio.sleep(3)  # Update every 3 seconds
        if heartbeat_running:
            count += 1
            await status_msg.stream_token(".")  # Send "." to keep socket alive

# Start keepalive task
hb_task = asyncio.create_task(heartbeat())

try:
    file_content = await file_processor.process_attachments(message)
finally:
    # Stop keepalive
    heartbeat_running = False
    try:
        hb_task.cancel()
        await hb_task
    except asyncio.CancelledError:
        pass
    # Remove the status message
    await status_msg.remove()
```

**Why This Works**:
- WebSocket receives periodic updates (every 3s)
- Prevents idle timeout during long PDF processing
- No JWT reconnection issues
- Clean cancellation when processing completes

### ThreadPoolExecutor for Blocking I/O

**Problem**: Both OIDC token fetching and PDF worker HTTP calls are **synchronous** operations that block the asyncio event loop.

**Solution**: Offload blocking operations to thread pool using `loop.run_in_executor()`.

**OIDC Token Fetch**:
```python
async def get_oidc_token(self, audience: str) -> str:
    def _fetch_token_sync() -> str:
        # Synchronous call to metadata server
        auth_req = transport_requests.Request()
        token = google.oauth2.id_token.fetch_id_token(auth_req, audience)
        return token

    # Run in thread pool to avoid blocking event loop
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, _fetch_token_sync)
```

**PDF Worker HTTP Call**:
```python
async def call_pdf_worker(self, pdf_bytes: bytes) -> Dict[str, Any]:
    # Get OIDC token (async call to metadata server)
    token = await self.get_oidc_token(audience=self.pdf_worker_url)

    # Run blocking HTTP call in thread pool
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _executor,
        self._call_pdf_worker_sync,  # Synchronous function
        pdf_bytes,
        self.pdf_worker_url,
        token
    )

def _call_pdf_worker_sync(self, pdf_bytes: bytes, url: str, token: str) -> Dict[str, Any]:
    # Uses httpx.Client (sync) instead of httpx.AsyncClient
    with httpx.Client(timeout=55) as client:
        response = client.post(url, content=pdf_bytes, headers={...})
        return response.json()
```

**Benefits**:
- ✅ Event loop remains responsive for WebSocket heartbeats
- ✅ No blocking during 3-5 second PDF processing
- ✅ No JWT signature verification failures
- ✅ Clean async/await interface for callers

### Performance Metrics

| Operation | Duration | Bottleneck | Mitigation |
|-----------|----------|------------|------------|
| File upload (client → Chainlit) | ~500ms | Network bandwidth | Enforce 10MB limit |
| OIDC token fetch | ~100-200ms | Metadata server latency | Thread pool + caching (future) |
| PDF worker invocation | ~2-5s | PDF parsing (pypdf) | Timeout at 55s, async execution |
| Text extraction (local) | ~50-100ms | UTF-8 decode | In-memory processing |
| Total (PDF upload → response start) | ~3-6s | PDF worker | Keepalive prevents timeout |

---

## Example Response Analysis

### Sample PDF Content

**Input**: `sample.pdf` (2 pages)
```
CWE ChatBot Test Document

This is a test document for the CWE ChatBot ephemeral PDF processing feature.
It contains generic placeholder text without specific vulnerability details.
```

**Extracted Text** (118 characters including header):
```
--- File: sample.pdf (2 pages, sanitized) ---
CWE ChatBot Test Document
...
```

### System Response

**Query**: (Empty - default used)
**Default Query**: "Analyze this document for security vulnerabilities and CWE mappings."

**LLM Response**:
```
This document does not contain specific technical details or code snippets
that would allow for a direct mapping to the provided CWEs. The content is
a generic placeholder ("CWE ChatBot Test Document") and does not describe
any exploitable vulnerabilities.

To effectively perform a vulnerability assessment and create security
advisories, the document would need to contain:

1. Specific descriptions of software behavior
2. Code snippets or configuration examples
3. Observed security flaws

Without such technical content, a meaningful analysis and mapping to CWEs
cannot be performed.

General Guidance for Defensive Vulnerability Assessment:
- Identify Potential Weaknesses
- Map to CWEs (Common Weakness Enumeration)
- Assess Impact and Severity (CVSS)
- Provide Protective Measures
- Educate and Inform

Example (hypothetical):
If a document described a web application that failed to validate user-supplied
file paths, this could be mapped to:

CWE-22: Improper Limitation of a Pathname to a Restricted Directory
        ('Path Traversal')

Impact: Attacker could read sensitive files or write to critical system locations

Defensive Measures:
- Implement strict input validation on file path components
- Use canonicalization to resolve paths
- Enforce access controls on file operations
```

**Analysis of Response**:
- ✅ **Accurate Assessment**: Correctly identified lack of vulnerability content
- ✅ **Educational Guidance**: Provided framework for vulnerability analysis
- ✅ **Hypothetical Example**: Demonstrated CWE mapping with CWE-22
- ✅ **Defensive Focus**: Emphasized protective measures (per PSIRT persona)
- ✅ **No Hallucination**: Did not fabricate vulnerabilities from placeholder text

---

## Security Best Practices

### 1. Input Validation

**File Type Detection**:
```python
# CORRECT: Magic byte detection
if content.startswith(b'%PDF-'):
    return 'pdf'

# WRONG: Extension-based detection (bypassable)
if filename.endswith('.pdf'):  # Don't do this!
    return 'pdf'
```

### 2. Size Limits

```python
# Enforce at multiple layers (defense in depth)
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB

# Layer 1: Client-side (Chainlit UI)
# Layer 2: Server-side (file_processor.py)
if len(file_content) > self.max_file_size_bytes:
    raise ValueError("too_large")

# Layer 3: PDF worker (Cloud Functions payload limit)
# Layer 4: Output truncation
if len(text) > 1_000_000:
    text = text[:1_000_000] + "\n\n[Content truncated]"
```

### 3. Error Message Sanitization

```python
# CORRECT: User-friendly error codes
def get_friendly_error(self, error_code: str) -> str:
    messages = {
        'auth_failed': 'PDF processing service authentication failed.',
        'encrypted_pdf_unsupported': 'Encrypted PDFs are not supported.',
        # ...
    }
    return messages.get(error_code, f'File processing error: {error_code}')

# WRONG: Exposing internal errors
except Exception as e:
    return f"Error: {str(e)}"  # Don't do this!
```

### 4. No Logging of Sensitive Content

```python
# CORRECT: Log metadata only
logger.info(f"PDF processed: {element.name}, {pages} pages, {len(text)} chars")

# WRONG: Logging file content
logger.info(f"Extracted text: {text}")  # Don't do this!
```

### 5. Session Isolation

```python
# CORRECT: User session storage (per-user isolation)
cl.user_session.set("uploaded_file_context", file_content)

# WRONG: Global variable (cross-user contamination)
global_file_cache[user_id] = file_content  # Don't do this!
```

---

## Deployment Configuration

### Cloud Run (Main App)

**Service Account**: `cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com`

**IAM Permissions**:
```bash
# Required: Invoke PDF worker
gcloud run services add-iam-policy-binding pdf-worker \
  --region=us-central1 \
  --member='serviceAccount:cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com' \
  --role='roles/run.invoker'
```

**Environment Variables**:
```bash
PDF_WORKER_URL=https://pdf-worker-bmgj6wj65a-uc.a.run.app
```

### Cloud Functions (PDF Worker)

**Runtime**: Python 3.11
**Memory**: 512 MB
**Timeout**: 60 seconds
**Max Instances**: 10 (auto-scaling)

**IAM Policy**:
```yaml
bindings:
- members:
  - serviceAccount:cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com
  role: roles/run.invoker
```

**No Environment Variables Needed** (PDF worker has no secrets, no database access)

---

## Troubleshooting

### Issue: "PDF processing service authentication failed"

**Symptoms**: OIDC token fetch fails with `TransportError`

**Diagnosis**:
```bash
# Check if service account has invoker permission
gcloud run services get-iam-policy pdf-worker --region=us-central1

# Check Cloud Run logs for OIDC errors
gcloud logging read 'resource.labels.service_name="cwe-chatbot" AND textPayload=~"OIDC"' --limit=10
```

**Solution**:
- Verify service account has `roles/run.invoker` on PDF worker
- Ensure PDF_WORKER_URL environment variable is set correctly
- Check metadata server is accessible from Cloud Run

### Issue: WebSocket disconnects during PDF upload

**Symptoms**: "I apologize, but I'm experiencing technical difficulties" after file upload

**Diagnosis**:
```bash
# Check for JWT signature errors
gcloud logging read 'resource.labels.service_name="cwe-chatbot" AND textPayload=~"InvalidSignatureError"' --limit=10
```

**Solution**:
- Verify CHAINLIT_AUTH_SECRET is set from Secret Manager (stable across instances)
- Confirm keepalive heartbeat is running during file processing
- Check ThreadPoolExecutor is used for blocking I/O

### Issue: "Empty query provided" error

**Symptoms**: User uploads PDF without typing query, sees error

**Diagnosis**:
```bash
gcloud logging read 'resource.labels.service_name="cwe-chatbot" AND textPayload=~"Empty query"' --limit=10
```

**Solution**:
- Verify default query logic in `main.py` lines 626-630
- Ensure `uploaded_file_context` is checked before query validation

---

## Future Enhancements

### 1. Multi-File Upload Support
- **Current**: Single PDF per message
- **Future**: Accept multiple PDFs, concatenate content
- **Challenge**: Combined size limit enforcement

### 2. OCR for Scanned PDFs
- **Current**: Text-based PDFs only
- **Future**: Google Cloud Vision API for image-based PDFs
- **Challenge**: Cost, latency, accuracy

### 3. OIDC Token Caching
- **Current**: Fetch new token per PDF upload
- **Future**: Cache token for 50 minutes (before 1-hour expiration)
- **Benefit**: Reduce metadata server calls, faster processing

### 4. PDF Content Indexing
- **Current**: Ephemeral (discarded after response)
- **Future**: Optional persistent storage with user consent
- **Challenge**: Privacy, GDPR compliance, storage costs

---

## Conclusion

The ephemeral PDF processing architecture prioritizes **security**, **isolation**, and **user privacy** over convenience. By separating PDF parsing into a dedicated Cloud Functions worker with OIDC authentication, we minimize the attack surface and prevent PDF-based exploits from compromising the main Chainlit application.

**Key Architectural Decisions**:
1. ✅ Compute Isolation (Cloud Functions sandbox)
2. ✅ OIDC Authentication (no static secrets)
3. ✅ Ephemeral Storage (no persistence)
4. ✅ Graceful Degradation (failures don't crash main app)
5. ✅ Defense in Depth (multiple validation layers)

**Trade-offs**:
- ⚠️ Higher latency (3-5s for PDF processing)
- ⚠️ Additional GCP infrastructure (Cloud Functions cost)
- ⚠️ Increased complexity (OIDC auth, service-to-service calls)

**Benefits Outweigh Costs**:
- ✅ Security isolation protects main application
- ✅ No persistent storage reduces privacy/compliance risk
- ✅ OIDC eliminates secret management overhead
- ✅ Clean error handling improves user experience

This architecture serves as a reference implementation for secure document processing in sensitive applications.
