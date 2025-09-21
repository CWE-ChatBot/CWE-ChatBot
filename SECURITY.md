# Security Overview

This repository uses a defense‑in‑depth approach combining GCP edge controls with application safeguards.

## Platform Controls (GCP)
- Cloud Armor: Rate limiting and WAF on the HTTPS Load Balancer in front of the chatbot (429 on abuse). See `docs/design/gcp_rate_limiting_and_budgets.md`.
- Billing Budgets: Alert on projected cost spikes (email/Slack via Pub/Sub).
- TLS termination at the load balancer; only HTTPS exposed publicly.

## Application Controls
- Input Sanitization: `apps/chatbot/src/input_security.py` blocks prompt injection patterns, normalizes Unicode, enforces length limits.
- Retrieval Safety: Ingestion stores use parameterized SQL and server‑side RRF (`apps/cwe_ingestion/pg_chunk_store.py::query_hybrid`). No dynamic SQL string building.
- Secrets: Loaded from env files; never commit secrets. Example: `GEMINI_API_KEY`, `DATABASE_URL`.
- Logging: Use `apps/chatbot/src/security/secure_logging.py` for redaction and safe logging.
  

## What We Do NOT Do In‑App
- Rate Limiting: Enforced at the edge (Cloud Armor/API Gateway), not in code.
- CSRF Tokens: Handled at the UI/proxy layer for state‑changing actions; the chatbot API is designed to be stateless/idempotent where possible.

## Verification
- Run security tests: `poetry run pytest apps/chatbot/tests/test_security.py -q`
- Inspect RRF SQL safety: `apps/cwe_ingestion/pg_chunk_store.py` (CTEs, parameterized binds).

## Reporting
If you discover a security issue, please file a private issue or contact the maintainers. Avoid sharing sensitive details publicly.
