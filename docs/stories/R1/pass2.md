# P0 — Must do (correctness & security)

1. **Package & imports (kill path hacks)**

* Standardize to `src.*` imports; add `pyproject.toml` so `src/` is the package root.
* In the short term, resolve the project root that contains `src/` once in `main.py`; long term, install the package and remove all `sys.path` edits.

2. **Validate config once, fail fast, show UI error**

* Call `config.validate_config()` at startup.
* Keep an `_init_ok` flag; if false, send a clear Chainlit message (“Startup error: check env/DB.”) and stop handlers.

3. **UTC everywhere**

* Replace `datetime.now()` with `datetime.now(timezone.utc)` in `UserContext`, `ConversationMessage`, session cleanup, analytics.

4. **Unify streaming & non-streaming paths and enforce final validation**

* One internal handler for both modes; stream tokens, then **post-validate** and update the message if the validator changed the text.

5. **Harden input sanitizer without blocking PoCs**

* Ignore pattern matches inside fenced code blocks.
* Don’t auto-block on a single prompt/command signal; require multiple high-risk signals.
* Keep flagging, but generate a helpful nudge instead of hard denial when possible.

6. **CVE Creator file intake via Chainlit widgets**

* Use `AskFileMessage` (PDF, ≤10 MB) instead of parsing elements manually.
* Add PDF page cap & image-only detection; suggest re-upload or (optional) OCR path.

7. **Secure logging everywhere**

* Use `get_secure_logger(...).log_exception(...)` for all IO/LLM/DB error paths (including `initialize_components`).

# P1 — High impact refactors (short work)

8. **Use Chainlit Chat Settings for persona & toggles**

* Render settings (persona, detail level, examples, mitigations).
* On update, set `UserContext` fields and call `update_user_persona`.
* Remove custom role actions / integrity flags.

9. **Decouple retrieval**

* Wrap the ingestion layer behind a `Retriever` interface and inject it into `CWEQueryHandler`. No `sys.path`/env import gymnastics.

10. **Delete or wire unused modules (keep the codebase lean)**

* Remove `processing/embedding_service.py`.
* Remove `processing/query_processor.py` and `processing/followup_processor.py` **unless** you actually call them from `ConversationManager`.
* Pick a single prompt source: keep `/prompts/*.md`; delete `prompts/role_templates.py` (or vice-versa).

11. **Close resources on shutdown**

* Add `@cl.on_stop` to close DB pools / retriever connections gracefully.

# P2 — UX & quality of life

12. **Better source rendering**

* Show top 2–3 CWE “source chips” in the side panel with relevance and a link (if available). Keep snippets short.

13. **Feedback & quick replies**

* You already use `@cl.on_feedback`. For non-CWE queries, send 2–3 Quick Reply actions (e.g., “Explain CWE-79 for a developer”).

14. **Deterministic outputs per persona**

* Keep `temperature=0.1`; cap output length by persona (shorter for PM/PSIRT). Append a tiny “Sources (CWE-IDs)” footer.

15. **Prevent double-send**

* Simple 1-second debounce in `@cl.on_message` using a timestamp in `cl.user_session`.

# P3 — Ops & polish

16. **LLM resilience**

* Add small retry/backoff and per-request timeout for `generate_content_async`; hard-stop long streams.

17. **Health & telemetry**

* Expose a tiny health step or page using `get_system_health()` (DB ok, active sessions, persona distribution, chunk count).

18. **Consistent enums & types**

* Compare personas using `UserPersona.X.value` only; tighten type hints; add `-> None` where missing.

19. **Remove dead scaffolding**

* `_add_message` is a no-op; rely on Chainlit’s persistence unless you add analytics.

20. **Single config source**

* Prefer `src.config.config` in `initialize_components()` instead of re-reading env vars directly.

---

### Quick wins to apply first

1. Call `config.validate_config()`; set `_init_ok`; show a clear UI error if false.
2. Swap persona controls to **Chat Settings**; push toggles into `UserContext`.
3. Standardize imports (`src.*`) and remove `sys.path` hacks.
4. Unify stream/non-stream and **update** the streamed message after validation.
5. Replace file parsing with `AskFileMessage`; add PDF caps and messages.

This list consolidates everything we discussed—no duplicates—and ordered to give you the biggest stability/security wins first.
