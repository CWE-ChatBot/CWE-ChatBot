Awesome—thanks for the full tree. Your retrieval is “done,” so here’s a **prioritized punch-list** to make the rest simple, secure, and very Chainlit-native. I’m focusing on correctness/security first, then UX/Chainlit features, then cleanup.

---

# P0 (fix now) — correctness & security

1. **Bug: undefined `encrypted_role` + bogus encryption claim**

* In `/user/role_manager.py > set_user_role`, you log `encrypted_role` which doesn’t exist, and nothing is actually encrypted.
* **Fix (minimal):**

  ```python
  def set_user_role(self, role: UserRole) -> bool:
      try:
          if not isinstance(role, UserRole):
              raise ValueError(f"Invalid role type: {type(role)}")
          cl.user_session[self.ROLE_SESSION_KEY] = role.value
          cl.user_session[self.ROLE_SET_FLAG] = True
          logger.info(f"User role set: {role.get_display_name()}")
          return True
      except Exception as e:
          logger.error(f"Failed to set user role: {e}")
          return False
  ```
* Also update docstrings: you’re not encrypting or decrypting session data.

2. **Session identity mismatch (may fork conversations)**

* `ConversationManager.process_user_message()` can **replace** the incoming `session_id` by creating a new `UserContext` (with its own UUID). That desyncs Chainlit’s session from your context.
* **Fix:** key `UserContextManager.active_sessions` **by Chainlit session id** and store an internal `context.session_id` if you want, but **don’t** swap the external key.

  * On `on_chat_start`, set `sid = cl.user_session.id` and pass that consistently.
  * In `create_session(sid)`, store under that `sid`.

3. **Async blocking**

* Several “async” paths call blocking code:

  * `CWEQueryHandler.process_query()` → `embedder.embed_text`, `store.query_hybrid` are sync.
  * `FileProcessor` PDF extraction is sync & CPU-ish.
* **Fix:** wrap with `await asyncio.to_thread(...)` or `await cl.make_async(func)(...)` to avoid blocking the event loop.

  ```python
  query_embedding = await asyncio.to_thread(self.embedder.embed_text, query)
  results = await asyncio.to_thread(self.store.query_hybrid, **query_params)
  content = await asyncio.to_thread(self._extract_pdf_content, file_bytes)
  ```

4. **Sanitizer changes user meaning (hurts retrieval)**

* `InputSanitizer.sanitize_input()` **rewrites** queries (adds “The following is a user query…”). That degrades recall and scoring.
* **Fix:** **flag** risky patterns but **don’t** prepend/alter semantics. Only normalize whitespace and (optionally) *mask* truly dangerous substrings, then pass the original text to retrieval/generation with a “ignore user instructions” system prompt. Keep `sanitized_input` == original when possible.

5. **Over-aggressive response scrubbing**

* `_clean_response()` removes `Instructions|System|Assistant` *anywhere*, which can nuke legit content (“system calls”, “assistant API”, etc.).
* **Fix:** only strip **leading** labels:

  ```python
  cleaned = re.sub(r'^(?:Instructions?|System|Assistant)\s*:\s*', '', response.strip(), flags=re.I)
  ```

6. **Weights are duplicated/inconsistent**

* `config.Config` enforces dense+sparse=1.0; `query_handler` hardcodes `w_vec=0.65, w_fts=0.25, w_alias=0.10`. Centralize weights in `Config`, pass them into `CWEQueryHandler` (constructor args), and remove hardcoded numbers.

7. **Path hacks**

* `sys.path.insert(...)` to `cwe_ingestion` is brittle. Package your ingestion module (or expose it as an installable extra) and import normally. At minimum, gate with env var (`CWE_INGESTION_PATH`) and fail fast with a clear error.

8. **Template duplication (three sources of truth)**

* Personas live in `UserRole`, `UserPersona`, plus markdown files. This will drift.
* **Fix:** define **one** enum (e.g., `UserPersona`) and generate role display/options from it everywhere. Keep prompt templates in one place (files or code), not both.

9. **Follow-up heuristics are fine—but guard array access**

* In `_build_context`, `chunk["metadata"]["section"]` may be missing—guard with `.get("section", "Content")` to avoid `KeyError`.

---

# P1 — “Chainlit-first” UX & features (simpler + less custom code)

1. **Use Chat Settings instead of custom role actions**

* Replace role selection/actions + `RoleManager` with **Pydantic Chat Settings**. It gives you a native side panel and updates per-session without extra UI wiring.

  ```python
  from pydantic import BaseModel, Field
  import chainlit as cl
  from typing import Literal

  class UISettings(BaseModel):
      persona: Literal["PSIRT Member","Developer","Academic Researcher","Bug Bounty Hunter","Product Manager","CWE Analyzer","CVE Creator"] = "Developer"
      detail_level: Literal["basic","standard","detailed"] = "standard"
      include_examples: bool = True
      include_mitigations: bool = True

  @cl.on_settings_update
  async def on_settings_update(settings: UISettings):
      cl.user_session.set("ui_settings", settings.dict())
  ```
* In `on_chat_start`, seed defaults; in your pipeline, read `ui_settings` instead of role manager/state duplication.

2. **Use Chainlit Steps for transparency**

* Wrap “Retrieve” and “Generate” phases in `cl.Step()` so users see timing & traces.

  ```python
  async with cl.Step(name="Retrieve CWE context"):
      results = await asyncio.to_thread(store.query_hybrid, **params)

  async with cl.Step(name="Generate answer (Gemini 1.5 Flash)"):
      text = await model.generate_content_async(...)
  ```

3. **Use built-in message feedback**

* Hook `@cl.on_feedback` to capture 👍/👎 and forward to `UserContextManager.record_feedback`.

  ```python
  @cl.on_feedback
  async def on_feedback(feedback: cl.Feedback):
      # feedback.forId -> message id, feedback.value -> 1/-1 or rating
      ...
  ```

4. **Source cards as Elements (no hand-rolled HTML)**

* Attach short source elements to the assistant message (e.g., `cl.Text` with CWE-IDs + links). It’s clickable and collapsible out-of-the-box.

5. **File uploads**

* You’re already reading `message.elements`. Keep it, but surface a friendly **upload prompt** on `on_chat_start` when persona == “CVE Creator”, with a small explainer message and a Step wrapping the extraction.

6. **Persistence**

* Prefer Chainlit’s built-in data layer for message history instead of your own `conversation_messages` dict. Keep only light, non-PII session vars in `cl.user_session`.

7. **Auth (if you need it)**

* If this isn’t public, enable simple auth in `chainlit.toml` (basic/OIDC). That’s simpler and safer than rolling your own.

---

# P2 — cleanup, simplicity & modularity

* **One persona model:** Delete `RoleManager` entirely once you move to Chat Settings. Put the enum + descriptions in one place (e.g., `user/persona.py`).
* **Protocols for providers:** Define simple interfaces for `Embedder`, `Retriever`, `LLM`. Your current classes can implement them; swapping providers later becomes trivial.
* **Consistent DTOs:** Make a typed `Chunk` (`cwe_id`, `name`, `section`, `document`, `scores`) and validate before prompting.
* **Streaming (optional):** If you want nicer UX, stream Gemini tokens and call `await msg.stream_token(token)`; Chainlit will handle partials.
* **Rate limiting (cheap):** Add a per-session guard (e.g., ≤ N requests/minute) to avoid abuse.

---

## Tiny but valuable code changes

### 1) Make blocking calls non-blocking

```python
# query_handler.py
async def process_query(...):
    query_embedding = await asyncio.to_thread(self.embedder.embed_text, query)
    results = await asyncio.to_thread(self.store.query_hybrid, **query_params)
    return results
```

### 2) Safer context builder (avoid KeyErrors, cap size)

```python
def _build_context(self, chunks):
    context_parts = []
    by_cwe = {}
    for ch in chunks:
        mid = (ch.get("metadata") or {})
        cid = mid.get("cwe_id", "CWE-UNKNOWN")
        by_cwe.setdefault(cid, []).append(ch)

    for cid, group in by_cwe.items():
        best = max(group, key=lambda g: float((g.get("scores") or {}).get("hybrid", 0)))
        name = (best.get("metadata") or {}).get("name", "")
        context_parts.append(f"\n--- {cid}: {name} ---")
        for ch in sorted(group, key=lambda g: (g.get("scores") or {}).get("hybrid", 0), reverse=True):
            section = (ch.get("metadata") or {}).get("section", "Content")
            doc = ch.get("document", "")[:1000]
            context_parts.append(f"\n{section}:\n{doc}{'...' if len(ch.get('document',''))>1000 else ''}")
            if section != "Content" and len(context_parts) > 12:
                break
    return "\n".join(context_parts[:4000])  # hard cap
```

### 3) InputSanitizer: don’t rewrite user text

```python
if pattern.search(user_input):
    security_flags.append("prompt_injection_detected")
# keep `sanitized_input` as the original (minus control chars & whitespace normalization)
```

### 4) Chainlit entrypoint (simple skeleton)

Create `src/app.py`:

```python
import chainlit as cl
from pydantic import BaseModel
from typing import Literal
from conversation import ConversationManager
from config import config

class UISettings(BaseModel):
    persona: Literal["PSIRT Member","Developer","Academic Researcher","Bug Bounty Hunter","Product Manager","CWE Analyzer","CVE Creator"] = "Developer"
    detail_level: Literal["basic","standard","detailed"] = "standard"
    include_examples: bool = True
    include_mitigations: bool = True

cm = ConversationManager(
    database_url=f"postgresql://{config.pg_user}:{config.pg_password}@{config.pg_host}:{config.pg_port}/{config.pg_database}",
    gemini_api_key=config.gemini_api_key,
)

@cl.on_chat_start
async def start():
    cl.user_session.set("ui_settings", UISettings().dict())
    await cl.Message("Hi! Choose your persona in **Settings** and ask about CWEs.").send()

@cl.on_settings_update
async def settings_update(settings: UISettings):
    cl.user_session.set("ui_settings", settings.dict())

@cl.on_message
async def on_message(message: cl.Message):
    sid = cl.user_session.id
    # optional: handle attachments here (CVE Creator)
    async with cl.Step("Process"):
        out = await cm.process_user_message(session_id=sid, message_content=message.content, message_id=message.id)
    await cl.Message(content=out["response"], metadata={"persona": out.get("persona"), "cwes": out.get("retrieved_cwes")}).send()
```

### 5) `chainlit.toml` (in `.chainlit/`)

```toml
[project]
name = "CWE Chatbot"
id = "cwe-chatbot"
enable_telemetry = false

[features]
# show settings drawer by default
default_settings = true

[UI]
theme = "dark"
```

---

## Security hardening (lightweight)

* **No secrets in logs** (you’re mostly good). Ensure `secure_logging` never dumps chunk text in production.
* **Output guardrails:** keep `SecurityValidator` but make it **advisory**—don’t silently replace long responses unless necessary; surface a notice to the user if truncated.
* **Attachment filtering:** already enforcing PDF + size cap—great. Add page cap (e.g., 100 pages) to avoid pathological PDFs.

---

## Why this keeps things simple

* Chat Settings replaces custom role widgets and reduces state plumbing.
* Steps & built-ins (feedback, elements, persistence, auth) shrink custom code.
* Concurrency fixes make the app responsive under load.
* One persona model + one prompt source eliminates drift.

If you want, I can turn the above into concrete PR-style patches (per file), but the P0 items (bug, session id, async wrappers, sanitizer/cleaner tweaks, weights centralization) will give you the biggest stability and security wins right away.
