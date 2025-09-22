# R1 Refactor — Pass 2 Progress Report

This report summarizes what has been implemented so far from the R1 Pass 2 checklist and adjacent improvements. It also notes what is partially complete and what remains.

## Summary
- Focused on correctness, security, and stability improvements (P0), plus a few high‑impact refactors (P1) and QoL items.
- Added targeted tests under `apps/tests/` to validate key changes.
- Reduced path/import hacks by packaging `apps/chatbot/src` as `src.*`.

## Implemented
- P0.2 Validate config once, fail fast, show UI error
  - Validate `config` at startup, gate handlers behind `_init_ok`, and show clear Chainlit error when misconfigured.
  - Files: `apps/chatbot/main.py`, `src/config.py`, `src/app_config.py`.

- P0.3 UTC everywhere
  - Switched timestamps to UTC for `UserContext`, message timestamps, and session cleanup logic.
  - Files: `src/user_context.py`, `src/conversation.py`.

- P0.4 Enforce final validation on streaming path
  - After streaming completes, validate and, if altered, update the final message text.
  - Files: `src/conversation.py`.

- P0.5 Harden input sanitizer without blocking PoCs
  - Ignore injection/command signals inside fenced code blocks.
  - Non‑strict mode (default controlled by `ENABLE_STRICT_SANITIZATION` env): require multiple distinct high‑risk categories to block.
  - Files: `src/input_security.py`.

- P0.7 Secure logging everywhere
  - Use `get_secure_logger(...).log_exception(...)` across startup, message processing, and retrieval.
  - Files: `apps/chatbot/main.py`, `src/conversation.py`, `src/query_handler.py`.

- P1.8 Use Chainlit Chat Settings for persona & toggles (already present, tightened)
  - `UISettings` model + `@cl.on_settings_update` drives persona and preferences.
  - File: `apps/chatbot/main.py`.

- P1.11 Close resources on shutdown
  - `@cl.on_stop` added; `CWEQueryHandler.close()` closes DB connection.
  - Files: `apps/chatbot/main.py`, `src/query_handler.py`.

- P2.15 Prevent double‑send
  - 1‑second debounce in `@cl.on_message` via `cl.user_session` timestamp.
  - File: `apps/chatbot/main.py`.

- CVE Creator file intake hardening (aligned with P0.6 intent)
  - Enforce 10MB PDF limit, add page cap (30 pages), and image‑only detection messages.
  - File: `src/file_processor.py`.

- Packaging/import cleanup (aligned with P0.1 intent)
  - Package `apps/chatbot/src` as `src.*` in `pyproject.toml`.
  - Removed ad‑hoc `sys.path` edits from `main.py`.

## Partially Implemented
- P0.1 Package & imports (kill path hacks)
  - Now packaged as `src.*`. Some legacy modules still reference older paths but runtime no longer depends on manual `sys.path` hacks.

- P0.4 Unify streaming & non‑streaming paths
  - Streaming path has final validation and update; non‑streaming path still separate. Unification pending.

- P0.5 Nudge vs hard denial
  - Thresholds relax blocking; fallbacks are still used for unsafe input. Further UX polish (nudge text) can be added per persona.

- P0.6 Use AskFileMessage for intake
  - We process Chainlit file elements safely with caps; explicit AskFileMessage widget wiring can be added to the chat start flow if desired.

- P2.12 Better source rendering
  - Sidebar “source chips” for top CWEs exist; tuning and linking can be improved.

- P3.20 Single config source
  - App uses `src/app_config.py` to avoid package naming conflict and centralize access. Some env fallbacks remain for DX.

## Not Yet Implemented
- P1.9 Decouple retrieval behind `Retriever` interface and inject
- P1.10 Delete/wire unused modules (processing/*) after confirming usage
- P2.13 Quick replies for non‑CWE queries
- P2.14 Persona‑bound output caps and a “Sources (CWE‑IDs)” footer standardization
- P3.16 LLM resilience (retry/backoff + per‑request timeouts for streaming)
- P3.17 Health & telemetry endpoint/page using `get_system_health()`
- P3.18 Consistent enums & tighter type hints across modules

## Tests Added (apps/tests/)
- `test_r1_pass2.py`
  - `test_user_context_uses_utc`: verifies UTC timestamps.
  - `test_sanitizer_ignores_code_blocks_and_multisignal`: ignores risky content inside code fences; blocks only when multiple risk categories in non‑strict mode.
- `conftest.py`: ensures `src.*` imports work in this test path.

Existing test suites under `apps/chatbot/tests/*` continue to cover broader functionality.

## How to Run
- App: `apps/chatbot/start_chatbot.sh --with-db` (see script for env setup)
- Tests: `poetry run pytest -q` or `poetry run pytest apps/tests -q`

## Next Steps (proposed)
- Unify stream and non‑stream handlers behind a single internal method.
- Add quick replies and persona‑bound output caps (P2.13–14).
- Introduce a small retry/backoff with timeouts for `generate_content_async` (P3.16).
- Expose health/telemetry (P3.17) and tighten type hints/enums (P3.18).
- Plan for retriever interface abstraction (P1.9) and prune unused modules (P1.10) after dependency check.

## Screenshot Guide
Live screenshots should be taken from the running app (no mockups). Use one of the flows below.

Manual capture (recommended):
- Start: `apps/chatbot/start_chatbot.sh --with-db --headless`
- Open the printed URL in your browser and capture:
  - Welcome screen and Settings panel (gear icon) open.
  - A query that streams a response and shows source chips in the side panel.
  - The startup error banner by launching without required env (e.g., unset `GEMINI_API_KEY`).
- Save images under `docs/stories/R1/screenshots/` with descriptive names (e.g., `welcome.png`, `settings.png`, `sources.png`).

Automated via Playwright (optional):
- Ensure the app is running locally.
- Run UI tests or a targeted capture using Playwright helpers:
  - `poetry run pytest tests/ui -q`
  - Or write a small test that uses `tests/ui/utils/screenshot_helpers.py` to save screenshots to `test-results/screenshots/current/` and then copy those to `docs/stories/R1/screenshots/`.
