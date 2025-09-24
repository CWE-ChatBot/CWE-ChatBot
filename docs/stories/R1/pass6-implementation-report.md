# R1 Pass 6 — Implementation Report

## Summary

- Introduced Dependency Injection (DI) for `ConversationManager` to improve testability and clarity of responsibilities.
- Implemented a true streaming path: sanitize → retrieve → stream tokens → finalize and validate, replacing the previous hidden full‑generate step for streaming.
- Treated file evidence as a first‑class prompt field instead of a pseudo‑chunk. Evidence is optional, length‑capped, never merged into the user question, and cleared after use.
- Updated prompt templates to include a `{user_evidence}` section for all personas.
- Adjusted tests to align with the streaming/evidence model. All unit and integration tests pass.

## Implemented

- Dependency Injection (IoC)
  - `apps/chatbot/src/conversation.py`:
    - `ConversationManager.__init__(..., *, input_sanitizer=None, security_validator=None, query_handler=None, response_generator=None)`
    - Continues to create defaults when dependencies are not provided.
    - Lifecycle (health checks, resource closing) remains owned by `main.py` (and `@cl.on_stop`).

- True Streaming Path
  - `process_user_message_streaming` now:
    - Uses `QueryProcessor.process_with_context` for sanitization/intent.
    - Retrieves chunks via `QueryHandler`.
    - Creates an empty `cl.Message`, then iterates `ResponseGenerator.generate_response_streaming(...)`, streaming tokens with `msg.stream_token(...)`.
    - After streaming completes, runs `SecurityValidator.validate_response` on the final text; if masking/changes occur, updates the message content with `msg.update()`.
  - `process_user_message` (non‑stream) now calls `ResponseGenerator.generate_response(...)`, which itself uses the streaming generator internally and joins tokens for consistency.

- Evidence as Prompt Field
  - `apps/chatbot/src/user_context.py`:
    - Added `file_evidence: Optional[str]` and helpers: `set_evidence(text)` and `clear_evidence()`.
  - `apps/chatbot/src/response_generator.py`:
    - `generate_response_streaming(..., *, user_evidence=None)` yields tokens as an async generator and includes `user_evidence` in the prompt (if provided).
    - `generate_response(..., *, user_evidence=None)` builds on the streaming generator and joins tokens.
    - Updated fallback logic: if no retrieval context and no evidence, yields/returns a persona‑specific fallback message.
    - Prompt templates updated to include a “User‑Provided Evidence” section: `{user_evidence}`.
  - `apps/chatbot/src/conversation.py`:
    - Reads session `uploaded_file_context`, sets `context.file_evidence` (length‑capped), and clears it after answering.

## Files Changed

- Updated
  - `apps/chatbot/src/conversation.py`: DI for constructor; streaming now streams from the provider; evidence passed via `user_evidence`; final masking step updates the message content if needed; non‑stream path simplified.
  - `apps/chatbot/src/response_generator.py`: streaming as async generator; prompts accept `{user_evidence}`; non‑stream uses streaming internally; retained `_format_cve_creator()` only for test compatibility.
  - `apps/chatbot/src/user_context.py`: added `file_evidence` and helpers; existing session/context APIs unchanged.
  - `apps/chatbot/main.py`: comments and cleanup around evidence clearing; continues to rely on ConversationManager for primary logic.
- Tests
  - `apps/chatbot/tests/unit/test_evidence_injection_all_personas.py`: adjusted to assert that evidence is passed via `user_evidence` to the streaming generator.

## Security & UX Note

- Chosen approach: stream tokens optimistically, then validate/mask the final text and update the message if needed. This trades a brief flash of unmasked text for better perceived latency and simpler code. If stricter behavior is desired, we can add lightweight per‑chunk masking before streaming.

## Validation

- Unit tests: PASSED
  - `pytest -q apps/chatbot/tests/unit`
- Integration tests: PASSED
  - `pytest -q apps/chatbot/tests/integration`
- UI/Playwright tests: Not executed in this report; see TEST_EXECUTION_GUIDE for setup and execution.

## Follow‑ups

- Consider per‑chunk masking to avoid any flash of unmasked content during streaming (with a small latency cost).
- Optionally add summarization and redaction of evidence prior to prompt inclusion to further protect token budget and privacy.
- Continue consolidating lifecycle concerns in a small bootstrap to further decouple `ConversationManager` construction from environment concerns.
