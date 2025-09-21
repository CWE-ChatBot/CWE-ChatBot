# System Design Document

**Purpose:** This document outlines the architecture, components, interfaces, and data flows of the *Ephemeral PDF/Text Processing for Chainlit on GCP* system to ensure it meets the functional and non‑functional requirements. It guides developers, testers, and stakeholders through implementation and operations.

---

## 1. Overview

**System Name:** Ephemeral Document Ingestion (EDI)

**Prepared By:**&#x20;

**Date:** \<YYYY‑MM‑DD>

**Version:** 1.0

---

## Executive Summary

* **Goal:** Enable secure, ephemeral ingestion of user files in a Chainlit app on GCP—handling **text** files locally and **PDFs** via an **isolated worker**—with **no persistence** of user content.
* **Why:** PDF parsing is a common attack surface (embedded JS, actions, malformed objects). Isolating parsing reduces blast radius; content sniffing prevents binary uploads disguised as text.
* **How:**

  * Chainlit service validates file type in memory. Text is decoded and capped at **1,000,000 characters**. PDFs are forwarded to a Cloud Run **PDF worker** using **service‑to‑service OIDC (ID tokens)**; the worker sanitizes (with pikepdf/qpdf) and extracts text (pdfminer.six) then returns JSON. No file is written to disk or GCS.
  * **Option A (chosen):** Worker is not publicly invokable (`--no-allow-unauthenticated`); only Chainlit’s service account has `roles/run.invoker`.
  * Defensive limits: 10 MB upload, ≤ 50 pages, ≤ 60 s processing, non‑root user, no payload logging, strict MIME checks.
* **Outcomes:** Strong isolation for risky content, reduced exfiltration risk, operational simplicity (Cloud Run), and clear, testable acceptance criteria.

## 2. System Objectives

* Accept **PDF** and **plain text** files (any extension) from users of a Chainlit app.
* **No persistence** of user files: process entirely **in memory**; do not write to local disk or cloud storage.
* For **text files**: validate that content is textual (content‑sniff, not extension) and pass up to **1,000,000 characters** into the chat prompt.
* For **PDFs**: forward bytes to an **isolated PDF worker** service that sanitizes and extracts text, returning up to **1,000,000 characters**.
* **Option A isolation:** call the PDF worker via **Cloud Run IAM** (no unauthenticated access) using service‑to‑service ID tokens.
* Enforce strict **resource guards** (size, time, page count) to reduce parser abuse.
* Provide **auditability** without logging user content.

---

## 3. Scope

**In scope**

* Chainlit UI and backend running on Cloud Run.
* PDF worker microservice on Cloud Run (separate service account & IAM boundary).
* Content sniffing for text; PDF sanitization + text extraction.
* Service‑to‑service authentication; configuration, monitoring, CI/CD.

**Out of scope (initial release)**

* OCR of scanned PDFs (no image‑based text extraction).
* Persistent storage (GCS buckets) and data retention workflows.
* Client‑side encryption or DLP redaction.
* Antivirus/malware scanning (may be added later).

---

## 4. Assumptions and Constraints

* Platform: **Google Cloud Run** for both Chainlit app and PDF worker.
* Runtime: **Python 3.12** containers; minimal base images; non‑root user.
* Max upload size: **10 MB** per file.
* Max extracted/accepted text: **1,000,000 characters**.
* PDF extraction limits: **≤ 50 pages**, **≤ 60s** request timeout, **≤ 512 MiB** memory per request.
* No egress to the public Internet from the worker other than Google APIs, unless required for logging/metrics.
* Secrets provided via **Secret Manager** (e.g., API keys for model provider).
* Regions: choose a single region (e.g., `europe‑west1`) for latency & simplicity.

---

## 5. Stakeholders

| Name               | Role                             | Contact       |
| ------------------ | -------------------------------- | ------------- |
| Product Owner      | Requirements & prioritization    | \<name/email> |
| Security Architect | Threat model & controls          | \<name/email> |
| Platform Engineer  | GCP infra, CI/CD                 | \<name/email> |
| Backend Engineer   | Chainlit + worker implementation | \<name/email> |
| QA Engineer        | Test plan & automation           | \<name/email> |
| SRE/On‑call        | Monitoring & incident response   | \<name/email> |

---

## 6. System Architecture

**Overview:** EDI introduces an **in‑memory ingestion path** and an **isolated PDF worker**. Chainlit validates text files locally; PDFs are sanitized and extracted in a separate Cloud Run service. Services communicate using **OIDC ID tokens** minted by the metadata server. No user file data is persisted.

### 6.1 Components

* **Chainlit Service (Cloud Run)**
  UI + backend. Accepts upload, content‑sniffs text, forwards PDFs to worker. Enforces size/character limits and discards bytes after use.
* **PDF Worker (Cloud Run)**
  Receives PDF bytes, sanitizes structure (remove `/OpenAction`, `/AA`, XFA, embedded files), extracts text, caps output, returns JSON.
* **Identity & Access**
  Cloud Run IAM (`roles/run.invoker`); service‑to‑service OIDC (ID tokens). Distinct service accounts per service; least privilege.
* **Observability**
  Cloud Logging (metadata only, no content), Cloud Monitoring metrics/alerts, Error Reporting.
* **CI/CD**
  Cloud Build → Artifact Registry → Cloud Run deploy; pinned versions & lockfiles.

### 6.2 System Diagram (Mermaid)

```mermaid
flowchart LR
  subgraph User
    U[Browser]
  end
  subgraph GCP[Google Cloud]
    CL[Chainlit Service\n(Cloud Run)]
    W[PDF Worker\n(Cloud Run, private IAM)]
    IDT[Metadata Server\n(ID token)]
    LOG[Cloud Logging/Monitoring]
  end

  U -- upload file --> CL
  CL -- if text --> CL
  CL -- if PDF: obtain ID token --> IDT
  CL -- POST /extract (Bearer ID token) --> W
  W -- text JSON --> CL
  CL -- prompt with text --> CL
  CL -- metrics/logs (no content) --> LOG
  W -- metrics/logs (no content) --> LOG
```

---

## 7. Data Design

**Data Flow Description:** Bytes arrive from the user, are validated in memory, optionally sent to the worker, converted to text, passed into the chat prompt, and then discarded. No persistence of user content occurs.

### 7.1 Data Entities

| Entity         | Description                                                                  |
| -------------- | ---------------------------------------------------------------------------- |
| Upload (bytes) | Raw file content from user; held in memory only.                             |
| Extracted Text | Cleaned UTF‑8 string used to build the prompt; truncated to 1,000,000 chars. |
| Metadata       | Request/response timings, sizes, status codes, error codes; no payloads.     |

### 7.2 Data Flow Diagrams

* **DFD‑1**: User → Chainlit: upload bytes; Chainlit validates size/type.
* **DFD‑2**: Chainlit → Worker: PDF bytes over HTTPS; worker returns text JSON.
* **DFD‑3**: Chainlit → Model Provider: prompt text only (no original bytes).

---

## 8. Interfaces

### 8.1 External Interfaces

* **User ↔ Chainlit**: HTTPS; upload via Chainlit file prompt. Accept `*/*`; server performs content sniffing. Max 10 MB.
* **Chainlit → PDF Worker**: `POST /extract` with `Content‑Type: application/pdf` and `Authorization: Bearer <OIDC ID token>`. Body: PDF bytes. Response: `{"text": "<extracted>"}`.
* **Chainlit → Model Provider**: HTTPS to configured LLM endpoint with prompt text (≤ 1,000,000 chars); provider auth via API key/SA.

### 8.2 Internal Interfaces

* **Metadata server**: `GET /instance/service-accounts/default/identity?audience=<worker-url>`; header `Metadata‑Flavor: Google`; returns OIDC ID token.
* **Logging/Monitoring**: Cloud Logging API (structured fields), Metrics → Cloud Monitoring.

---

## 9. Security Considerations

**Security Goals**

* Prevent RCE/abuse from malformed PDFs by **isolating parsing** in a minimal, locked‑down service.
* Ensure **no user content persists** beyond request lifetime.
* Authenticate/authorize all service calls (no public invocation of worker).
* Minimize **exfiltration** risk (no payload logging; least privilege; egress controls).

**Threat Model (STRIDE‑style)**

* *Spoofing*: Unauthorized caller invokes worker.
  **Mitigation:** Cloud Run IAM; `--no-allow-unauthenticated`; service‑to‑service OIDC; audience binding; per‑service SA.
* *Tampering*: PDF attempts to alter host or escape sandbox.
  **Mitigation:** Container runs as non‑root; read‑only FS (except `/tmp`); pikepdf sanitization; limits (pages/time/mem); no shell tools reachable; no disk writes.
* *Repudiation*: Lack of traceability.
  **Mitigation:** Structured audit logs of request metadata (caller SA, sizes, timings, status) without payloads.
* *Information Disclosure*: Logs or storage capture sensitive content.
  **Mitigation:** No persistence; payload logging disabled; memory‑only handling; Secret Manager for tokens.
* *Denial of Service*: Zip/page bombs; huge files; slowloris.
  **Mitigation:** Max 10 MB; max 50 pages; server timeouts; reverse proxy limits; concurrency caps; autoscaling controls.
* *Elevation of Privilege*: SA over‑privilege.
  **Mitigation:** Separate SAs; minimal roles (`run.invoker` only for Chainlit→worker); no broad project roles.

**Additional Controls**

* Content sniff for text: reject binaries (NUL bytes); printable ratio check; strict decoding (UTF‑8/16/Latin‑1).
* HTTP security: enforce `Content‑Type: application/pdf` to worker; reject otherwise (415).
* Dependency hygiene: pin versions; weekly CVE scans; renovate/bazel or equivalent.
* Config/Secrets: environment via Secret Manager; no secrets in images.
* Observability: percentiles for latency; error budgets; alerting on 5xx & timeout rates.

---

## 10. Performance Requirements

* **Latency:**

  * Text files (≤ 1 MB): ≤ 300 ms 95th percentile end‑to‑end ingestion.
  * PDFs (≤ 10 MB, ≤ 50 pages): ≤ 2 s 95th percentile extraction.
* **Throughput/Scale:** autoscale 0→N; target ≥ 50 concurrent requests combined.
* **Resource Caps:** worker `cpu=1`, `memory=512Mi`, `timeout=60s`; Chainlit `cpu=1`, `memory=512Mi`.

---

## 11. Glossary

* **Chainlit:** Python framework for chat apps.
* **Cloud Run:** Managed container platform by GCP.
* **OIDC ID token:** JWT used for authenticated service‑to‑service calls.
* **pikepdf:** Python wrapper over qpdf for PDF structure editing.
* **pdfminer.six:** Python library to extract text from PDFs.

---

## 12. Appendices

### A. Component Responsibilities

* **Chainlit Service**

  * Prompt user for file; enforce 10 MB limit.
  * If PDF: fetch ID token; call worker; receive JSON text.
  * If text: content sniff; normalize; truncate to 1,000,000 chars.
  * Build prompt; immediately discard original bytes.
  * Log metadata only.

* **PDF Worker**

  * Validate `Content‑Type` and PDF magic bytes.
  * Sanitize PDF (remove `/OpenAction`, `/AA`, XFA, attachments; normalize/linearize).
  * Extract text (pdfminer.six) with `maxpages=50`.
  * Normalize whitespace; cap to 1,000,000 chars; return JSON.
  * No disk writes; drop privileges; no unauthenticated access.

### B. IAM & Networking

* **Service Accounts**

  * `sa-chainlit`: minimal roles; `roles/run.invoker` on worker only.
  * `sa-pdf-worker`: no broad roles; logging writer only.
* **Ingress/Egress**

  * Worker: `--no-allow-unauthenticated`; ingress `all` (or internal+LB if required).
  * Optional: Serverless VPC Connector + egress firewall to limit outbound.

### C. CI/CD & Images

* Cloud Build triggers on main; build with `--no-cache`; push to Artifact Registry.
* Dockerfiles: slim Python base, `qpdf` installed; run as non‑root; `PORT` from env; health check.
* SBOM generation; image vulnerability scanning; pinned dependencies.

### D. Non‑Functional Requirements (NFRs)

* **Availability:** 99.9% monthly; multi‑zone within region.
* **Security:** no storage of user content; PASSED threat model mitigations; independent security review before GA.
* **Compliance:** align with internal data‑handling policies; ensure logging excludes content.

### E. Test Plan (Acceptance Criteria)

1. **Text acceptance**: upload `.md` with binary content → rejected with error.
2. **PDF acceptance**: valid PDF returns text; malformed PDF → 400.
3. **Limit tests**: 10.1 MB upload → 413; 1,000,001‑char output → truncated; >50 pages → 400 or graceful truncation.
4. **Isolation**: worker unreachable without IAM (403).
5. **No persistence**: inspect containers & logs; no payloads written.
6. **Perf**: PDF 5MB/20 pages within 2s p95.

### F. Runbook (Ops)

* **Alerts**: 5xx rate >2% (5 min), latency p95 > SLO, auth failures >10/min.
* **Common Errors**: 413 (too large), 415 (wrong content type), 401/403 (auth), 500 (parser error).
* **Rollbacks**: keep last two revisions; `gcloud run services update-traffic` to revert.
* **Secrets Rotation**: via Secret Manager; update env with latest versions; trigger redeploy.

### G. Future Enhancements

* OCR for scanned PDFs (PyMuPDF/Tesseract or Document AI).
* Cloud DLP redaction prior to prompting.
* ClamAV/virus scanning pre‑extract.
* Private Service Connect + internal LB for fully private worker.
* Rate limiting & per‑user quotas.

### H. Terraform Reference (IAM + Cloud Run)

Below is a minimal, production‑ready Terraform reference for **Option A** (worker requires IAM; Chainlit may be public or private). Adjust names/regions as needed.

```hcl
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {}
variable "region"     { default = "europe-west1" }
variable "chainlit_image" {}
variable "worker_image"   {}
variable "chainlit_public" { type = bool, default = true }

# Service Accounts
resource "google_service_account" "chainlit" {
  account_id   = "sa-chainlit"
  display_name = "Chainlit Service Account"
}

resource "google_service_account" "worker" {
  account_id   = "sa-pdf-worker"
  display_name = "PDF Worker Service Account"
}

# Minimal roles (logging + run.invoker on worker only)
resource "google_project_iam_member" "chainlit_logwriter" {
  role   = "roles/logging.logWriter"
  member = "serviceAccount:${google_service_account.chainlit.email}"
}

resource "google_project_iam_member" "worker_logwriter" {
  role   = "roles/logging.logWriter"
  member = "serviceAccount:${google_service_account.worker.email}"
}

# Cloud Run (v2) — Chainlit
resource "google_cloud_run_v2_service" "chainlit" {
  name     = "chainlit"
  location = var.region
  template {
    service_account = google_service_account.chainlit.email
    containers {
      image = var.chainlit_image
      resources { limits = { cpu = "1", memory = "512Mi" } }
      env { name = "PDF_WORKER_URL" value = google_cloud_run_v2_service.worker.uri ~ "/extract" }
    }
    scaling { min_instance_count = 0 max_instance_count = 5 }
    timeout = "60s"
  }
  ingress = "INGRESS_TRAFFIC_ALL"
}

# Optionally make Chainlit public for end users
resource "google_cloud_run_v2_service_iam_member" "chainlit_public_invoker" {
  count    = var.chainlit_public ? 1 : 0
  project  = google_cloud_run_v2_service.chainlit.project
  location = google_cloud_run_v2_service.chainlit.location
  name     = google_cloud_run_v2_service.chainlit.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# Cloud Run (v2) — PDF Worker (private, IAM only)
resource "google_cloud_run_v2_service" "worker" {
  name     = "pdf-worker"
  location = var.region
  template {
    service_account = google_service_account.worker.email
    containers {
      image = var.worker_image
      resources { limits = { cpu = "1", memory = "512Mi" } }
      env { name = "MAX_BYTES" value = "10485760" }     # 10 MB
      env { name = "MAX_PAGES" value = "50" }
    }
    scaling { min_instance_count = 0 max_instance_count = 5 }
    timeout = "60s"
  }
  ingress = "INGRESS_TRAFFIC_ALL"
}

# Allow only Chainlit to invoke the worker
resource "google_cloud_run_v2_service_iam_member" "worker_invoker" {
  project  = google_cloud_run_v2_service.worker.project
  location = google_cloud_run_v2_service.worker.location
  name     = google_cloud_run_v2_service.worker.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.chainlit.email}"
}

output "chainlit_url" { value = google_cloud_run_v2_service.chainlit.uri }
output "worker_url"   { value = google_cloud_run_v2_service.worker.uri }
```

**Equivalent gcloud flags (reference)**

```bash
# Chainlit (optionally public)
gcloud run deploy chainlit \
  --image $CHAINLIT_IMAGE \
  --region $REGION \
  --service-account sa-chainlit@$PROJECT.iam.gserviceaccount.com \
  --allow-unauthenticated   # omit if private \
  --ingress all \
  --cpu 1 --memory 512Mi --timeout 60

# PDF Worker (private, IAM only)
gcloud run deploy pdf-worker \
  --image $WORKER_IMAGE \
  --region $REGION \
  --service-account sa-pdf-worker@$PROJECT.iam.gserviceaccount.com \
  --no-allow-unauthenticated \
  --ingress all \
  --cpu 1 --memory 512Mi --timeout 60

# IAM: allow Chainlit to invoke worker
gcloud run services add-iam-policy-binding pdf-worker \
  --region $REGION \
  --member serviceAccount:sa-chainlit@$PROJECT.iam.gserviceaccount.com \
  --role roles/run.invoker
```

**Notes**

* If you require strictly private addressing, set `ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"` and front with an **internal HTTPS LB** (serverless NEG). Chainlit will need a Serverless VPC Connector to reach it.
* Avoid logging payloads; use structured logs for metadata (size, timing, caller) only.
* Scale limits and timeouts may be adjusted per SLOs.

---

### I. Makefile + Cloud Build (CI → Deploy)

This appendix provides a turnkey **Makefile** and **Cloud Build** pipeline that builds images for both services, pushes to **Artifact Registry**, and deploys to **Cloud Run**. It implements a single `make deploy` path.

> **Prereqs**
>
> 1. Terraform appendix (H) applied (service accounts exist).
> 2. An **Artifact Registry** Docker repo exists (see `make bootstrap-repo`).
> 3. Cloud Build SA (\<project-number'@cloudbuild.gserviceaccount.com) has roles: `artifactregistry.writer`, `run.admin`, `iam.serviceAccountUser`.

#### Repository Layout (suggested)

```
/
  chainlit/   # Chainlit service (Dockerfile, app.py, requirements.txt)
  worker/     # PDF worker (Dockerfile, app.py or main.py, requirements.txt)
  cloudbuild.yaml
  Makefile
```

#### Makefile

```makefile
# ====== Config ======
PROJECT_ID ?= your-project-id
REGION     ?= europe-west1
REPO       ?= app-images        # Artifact Registry repo name

CHAINLIT_SERVICE ?= chainlit
WORKER_SERVICE   ?= pdf-worker

CHAINLIT_DIR ?= chainlit
WORKER_DIR   ?= worker

AR_HOST = $(REGION)-docker.pkg.dev
CHAINLIT_IMG = $(AR_HOST)/$(PROJECT_ID)/$(REPO)/$(CHAINLIT_SERVICE)
WORKER_IMG   = $(AR_HOST)/$(PROJECT_ID)/$(REPO)/$(WORKER_SERVICE)

# ====== Targets ======
.PHONY: bootstrap-repo deploy clean

bootstrap-repo:
	gcloud artifacts repositories create $(REPO) \
	  --repository-format=docker \
	  --location=$(REGION) || echo "Repo exists"

# One command to build & deploy both services via Cloud Build
deploy:
	gcloud builds submit . \
	  --config=cloudbuild.yaml \
	  --substitutions=_REGION=$(REGION),_REPOSITORY=$(REPO),_CHAINLIT_SERVICE=$(CHAINLIT_SERVICE),_WORKER_SERVICE=$(WORKER_SERVICE),_CHAINLIT_DIR=$(CHAINLIT_DIR),_WORKER_DIR=$(WORKER_DIR)

# Optional: quick undeploy
clean:
	gcloud run services delete $(CHAINLIT_SERVICE) --region $(REGION) --quiet || true
	gcloud run services delete $(WORKER_SERVICE) --region $(REGION) --quiet || true
```

#### cloudbuild.yaml

```yaml
# Builds chainlit + worker images, pushes to Artifact Registry,
# deploys worker (IAM only), then deploys chainlit with PDF_WORKER_URL set.
substitutions:
  _REGION: europe-west1
  _REPOSITORY: app-images
  _CHAINLIT_SERVICE: chainlit
  _WORKER_SERVICE: pdf-worker
  _CHAINLIT_DIR: chainlit
  _WORKER_DIR: worker

options:
  logging: CLOUD_LOGGING_ONLY

steps:
  # Build images
  - name: gcr.io/cloud-builders/docker
    id: build-chainlit
    args: ["build","-t","${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPOSITORY}/${_CHAINLIT_SERVICE}:$SHORT_SHA","${_CHAINLIT_DIR}"]

  - name: gcr.io/cloud-builders/docker
    id: build-worker
    args: ["build","-t","${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPOSITORY}/${_WORKER_SERVICE}:$SHORT_SHA","${_WORKER_DIR}"]

  # Push images
  - name: gcr.io/cloud-builders/docker
    id: push-chainlit
    args: ["push","${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPOSITORY}/${_CHAINLIT_SERVICE}:$SHORT_SHA"]

  - name: gcr.io/cloud-builders/docker
    id: push-worker
    args: ["push","${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPOSITORY}/${_WORKER_SERVICE}:$SHORT_SHA"]

  # Deploy worker first (private: no unauthenticated)
  - name: gcr.io/google.com/cloudsdktool/cloud-sdk
    id: deploy-worker
    entrypoint: gcloud
    args:
      - run
      - deploy
      - ${_WORKER_SERVICE}
      - --image=${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPOSITORY}/${_WORKER_SERVICE}:$SHORT_SHA
      - --region=${_REGION}
      - --service-account=sa-pdf-worker@$PROJECT_ID.iam.gserviceaccount.com
      - --no-allow-unauthenticated
      - --ingress=all
      - --cpu=1
      - --memory=512Mi
      - --timeout=60

  # Deploy chainlit (public by default; adjust if private)
  - name: gcr.io/google.com/cloudsdktool/cloud-sdk
    id: deploy-chainlit
    entrypoint: bash
    args:
      - -c
      - |
        WORKER_URL=$(gcloud run services describe ${_WORKER_SERVICE} --region ${_REGION} --format='value(status.uri)')
        gcloud run deploy ${_CHAINLIT_SERVICE} \
          --image=${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPOSITORY}/${_CHAINLIT_SERVICE}:$SHORT_SHA \
          --region=${_REGION} \
          --service-account=sa-chainlit@$PROJECT_ID.iam.gserviceaccount.com \
          --allow-unauthenticated \
          --ingress=all \
          --cpu=1 --memory=512Mi --timeout=60 \
          --set-env-vars=PDF_WORKER_URL=${WORKER_URL}/extract

images:
  - "${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPOSITORY}/${_CHAINLIT_SERVICE}:$SHORT_SHA"
  - "${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPOSITORY}/${_WORKER_SERVICE}:$SHORT_SHA"
```

#### Optional: Create a Cloud Build Trigger

```bash
# Replace placeholders for GitHub; or use Cloud Source Repos
PROJECT_ID=your-project-id
REGION=europe-west1
REPO_NAME=your-github-repo
BRANCH_PATTERN=^main$

gcloud builds triggers create github \
  --project $PROJECT_ID \
  --name "edi-deploy" \
  --repo-name "$REPO_NAME" \
  --repo-owner "<org-or-user>" \
  --branch-pattern "$BRANCH_PATTERN" \
  --build-config "cloudbuild.yaml" \
  --substitutions _REGION=$REGION,_REPOSITORY=app-images,_CHAINLIT_SERVICE=chainlit,_WORKER_SERVICE=pdf-worker,_CHAINLIT_DIR=chainlit,_WORKER_DIR=worker
```

**Usage**

1. `make bootstrap-repo` (one time).
2. Push to `main` (if using trigger) **or** run `make deploy` locally to build & deploy both services.

---

### J. Repository Scaffold (Clone‑and‑Go)

This appendix contains a minimal repo layout with Dockerfiles and app stubs for both services.

```
.
├─ chainlit/
│  ├─ app.py
│  ├─ requirements.txt
│  ├─ Dockerfile
│  └─ .dockerignore
├─ worker/
│  ├─ app.py
│  ├─ requirements.txt
│  ├─ Dockerfile
│  └─ .dockerignore
├─ cloudbuild.yaml
├─ Makefile
└─ README.md
```

#### chainlit/app.py

```python
import chainlit as cl
import httpx, os
from typing import Tuple

PDF_MAGIC = b"%PDF-"
MAX_UPLOAD_MB = 10
MAX_TEXT_BYTES = 1_000_000  # characters/bytes target
PDF_WORKER_URL = os.environ.get("PDF_WORKER_URL")  # e.g. https://pdf-worker-xxx.a.run.app/extract
PDF_WORKER_AUDIENCE = PDF_WORKER_URL

# ---- text sniffing ----
def sniff_text(b: bytes) -> Tuple[bool, str]:
    if b"�" in b:
        return False, "Binary content detected (NUL byte)."
    printable = sum(32 <= c <= 126 or c in (9, 10, 13) for c in b)
    if len(b) == 0 or printable / max(1, len(b)) < 0.85:
        return False, "Low printable ratio; likely not plain text."
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            s = b.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        return False, "Unable to decode as text."
    cleaned = "".join(ch for ch in s if (31 < ord(ch) < 127) or ch in "	
")
    return True, cleaned[:MAX_TEXT_BYTES]

async def call_pdf_worker(pdf_bytes: bytes) -> str:
    if not PDF_WORKER_URL:
        raise RuntimeError("PDF_WORKER_URL env var is not set")
    async with httpx.AsyncClient(timeout=60) as client:
        # Fetch OIDC ID token from metadata server
        token_resp = await client.get(
            "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity",
            params={"audience": PDF_WORKER_AUDIENCE},
            headers={"Metadata-Flavor": "Google"},
        )
        token_resp.raise_for_status()
        id_token = token_resp.text
        resp = await client.post(
            PDF_WORKER_URL,
            headers={
                "Authorization": f"Bearer {id_token}",
                "Content-Type": "application/pdf",
            },
            content=pdf_bytes,
        )
        resp.raise_for_status()
        return (resp.json() or {}).get("text", "")[:MAX_TEXT_BYTES]

@cl.on_message
async def main(msg: cl.Message):
    ask = cl.AskFileMessage(
        content="Upload a file: PDF or plain text (any extension). Max 10 MB.",
        accept=["*/*"],
        max_size_mb=MAX_UPLOAD_MB,
        timeout=180,
    )
    files = await ask.send()
    if not files:
        await cl.Message(content="No file received.").send()
        return

    f = files[0]
    raw = await f.read()

    if raw.startswith(PDF_MAGIC):
        await cl.Message(content="PDF received → extracting text in isolated worker…").send()
        try:
            extracted = await call_pdf_worker(raw)
        except Exception as e:
            await cl.Message(content=f"PDF extraction failed: {e}").send()
            return
        if not extracted.strip():
            await cl.Message(content="No extractable text found in the PDF.").send()
            return
        await cl.Message(content=f"Extracted {len(extracted)} chars. Ready to use in your prompt.").send()
        return

    ok, text = sniff_text(raw)
    if not ok:
        await cl.Message(content=f"Rejected: {text}").send()
        return
    await cl.Message(content=f"Got text ({len(text)} chars). Ready to use in your prompt.").send()
```

#### chainlit/requirements.txt

```
chainlit==1.2.0
httpx==0.27.2
```

#### chainlit/Dockerfile

```dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
ENV PORT=8080
# Chainlit must listen on $PORT for Cloud Run
CMD ["bash", "-lc", "chainlit run app.py --host 0.0.0.0 --port $PORT"]
```

#### chainlit/.dockerignore

```
__pycache__
*.pyc
*.pyo
*.pyd
.env
.venv
```

---

#### worker/app.py (Flask)

```python
from flask import Flask, request, jsonify, abort
import io
import pikepdf
from pdfminer.high_level import extract_text

app = Flask(__name__)
MAX_BYTES = 10 * 1024 * 1024
MAX_PAGES = 50
MAX_CHARS = 1_000_000
PDF_MAGIC = b"%PDF-"

@app.get("/healthz")
def health():
    return {"status": "ok"}

def sanitize_pdf(b: bytes) -> bytes:
    with pikepdf.open(io.BytesIO(b)) as pdf:
        r = pdf.root
        for k in ("/OpenAction", "/AA", "/Names"):
            if k in r:
                del r[k]
        if "/AcroForm" in r:
            acro = r["/AcroForm"]
            if "/XFA" in acro:
                del acro["/XFA"]
        out = io.BytesIO()
        pdf.save(out, linearize=True, optimize_streams=True)
        return out.getvalue()

@app.post("/extract")
def extract():
    ctype = (request.headers.get("content-type") or "").split(";")[0].strip()
    if ctype != "application/pdf":
        abort(415, "Content-Type must be application/pdf")
    body = request.get_data(cache=False, as_text=False)
    if not body or len(body) > MAX_BYTES or not body.startswith(PDF_MAGIC):
        abort(400, "Invalid or oversized PDF")
    try:
        safe = sanitize_pdf(body)
        text = extract_text(io.BytesIO(safe), maxpages=MAX_PAGES)
        text = "
".join(line.rstrip() for line in text.splitlines())[:MAX_CHARS]
        return jsonify({"text": text})
    except pikepdf.PdfError:
        abort(400, "Corrupt or unsupported PDF")
    except Exception as e:
        abort(500, str(e))
```

#### worker/requirements.txt

```
flask==3.0.3
gunicorn==22.0.0
pikepdf==9.4.0
pdfminer.six==20240706
```

#### worker/Dockerfile

```dockerfile
FROM python:3.12-slim
# qpdf required by pikepdf; keep image lean
RUN apt-get update && apt-get install -y --no-install-recommends qpdf ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
# Drop privileges (optional in slim):
RUN useradd -u 10001 -m appuser && chown -R appuser /app
USER appuser
ENV PORT=8080 MAX_BYTES=10485760 MAX_PAGES=50
CMD exec gunicorn --bind 0.0.0.0:$PORT --workers=1 --threads=4 app:app
```

#### worker/.dockerignore

```
__pycache__
*.pyc
*.pyo
*.pyd
.env
.venv
```

---

#### README.md (snippets)

```markdown
# Ephemeral Document Ingestion (EDI)

Two Cloud Run services:
- **chainlit/** — user‑facing Chainlit app. Handles text locally; sends PDFs to worker.
- **worker/** — private PDF extraction service. Sanitizes and extracts text; no persistence.

## Quickstart
1. Create Artifact Registry repo: `make bootstrap-repo`.
2. Deploy both with Cloud Build: `make deploy`.
3. After deploy, set `PDF_WORKER_URL` automatically via Cloud Build. For manual runs, set it to the worker URL + `/extract`.

## Local Dev
- Chainlit: `cd chainlit && pip install -r requirements.txt && chainlit run app.py -h 0.0.0.0 -p 8000`
- Worker: `cd worker && pip install -r requirements.txt && gunicorn -b 0.0.0.0:8001 app:app`

Note: Metadata server ID tokens are only available on GCP; for local testing, temporarily **disable auth** on the worker or inject a dummy header behind a local proxy.
```

