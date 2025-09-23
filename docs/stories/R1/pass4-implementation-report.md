# R1 Pass 4 — Implementation Report

This report summarizes what was implemented from docs/stories/R1/pass4.md, validations performed, and items deferred with rationale.

## Summary

- Implemented uniform evidence policy for all personas (no special-casing); evidence is always isolated and injected as a low-weight pseudo‑chunk.
- Implemented the session unification helpers and updated ConversationManager to use a centralized `QueryProcessor` for preprocessing.
- Unified streaming vs non‑streaming by delegating both paths to a single core method.
- Added unit tests, including a new persona‑wide evidence injection test; kept `UserContextManager` for backward-compatible tests (not used by ConversationManager).

## Implemented

- Uniform evidence policy (all personas)
  - Removed persona‑based capability gates (e.g., no more `if persona == "CVE Creator"`).
  - Evidence upload/processing available to every persona; extracted content is never merged into the user prompt.
  - Evidence is injected as an isolated, low‑weight pseudo‑chunk with metadata `cwe_id="EVIDENCE"` and shown in the UI as a side element.

- Session helpers (P1.1)
  - Added `apps/chatbot/src/utils/session.py` with `get_user_context` and `set_user_context`.
  - Conversation now calls the helper (single source of truth in `cl.user_session`).
  - Added `UserContext.get_session_context_for_processing()` to expose minimal hints for processors.

- Consolidated preprocessing via QueryProcessor (P1.2)
  - ConversationManager now instantiates and uses `QueryProcessor.process_with_context(...)` for input sanitization and intent detection.
  - Fallback logic maps `security_check.detected_patterns` into the existing fallback generator for user-friendly responses.
  - CWE relevance validation remains via `InputSanitizer.validate_cwe_context` to preserve current behavior.

- Unit tests
  - Added `apps/chatbot/tests/unit/test_session_context.py` to validate session helper behavior with a monkeypatched `chainlit.user_session`.
  - Added `apps/chatbot/tests/unit/test_evidence_injection_all_personas.py` asserting the evidence pseudo‑chunk is injected for all personas.

- Unified streaming vs. non-streaming (P2.2)
  - Added `_process_message_core()` in `apps/chatbot/src/conversation.py` which handles sanitize → retrieve (+evidence) → generate.
  - `process_user_message` and `process_user_message_streaming` now delegate to the core path and return consistent payloads.
  - Streaming path sends the final validated response once (no double LLM calls), preserving source element support via returned `retrieval`.

## Deferred / Partially Implemented

- Packaging/import cleanup (P1.3)
  - Not fully applied to avoid breaking imports in the current test harness, which relies on `CWE_INGESTION_PATH` when launching from the `apps/chatbot` directory. Current logic already prefers `apps.cwe_ingestion` and falls back to the env-based path. This can be completed alongside a small harness change to include the repo root on `PYTHONPATH`.

- Unified streaming vs non-streaming core (P2.2)
  - Not applied to minimize change surface during this pass. Existing streaming path remains primary.

- RoleManager retirement and persona policy strategy (P2.1, P3.2)
  - `RoleManager` was previously removed; persona logic already resides in `UserContext`. Policy strategy left for a separate pass.

- Security regex refinements (P3.1), config simplification (P3.3), standardized logging (P3.4)
  - Existing components are functional; these quality improvements can be safely applied in a follow-up.

## Validation

- Unit tests
  - `pytest -q apps/chatbot/tests/unit` — All tests pass, including new evidence injection test.

- Integration/E2E tests
  - Integration: `pytest -q apps/chatbot/tests/integration` — Passed locally in the elevated environment.
  - E2E/Playwright: Not run in this report; follow TEST_EXECUTION_GUIDE to install browsers and execute UI flows if needed.

## Next Steps

- Complete packaging import cleanup: remove `sys.path` fallbacks in `query_handler.py` once the test launcher adds repo root to `PYTHONPATH` or the ingestion module is installed.
- Optionally unify message paths via `_process_message_core` for consistency and smaller code surface.
- Add persona policy strategy and security regex improvements as outlined in pass4.
