I agree with going “streaming-only” and leaning on Chainlit. A few correctness bugs and small simplifications will make it solid.

TL;DR (what to fix)

Persona bugs in main.py: you read ui_settings["persona"] (doesn’t exist) and reference an undefined persona var inside on_message.

Non-streaming leftovers: ConversationManager.process_user_message and ResponseGenerator.generate_response are dead weight. One also has a bug (user_evidence referenced but not defined).

Persona source of truth: in ConversationManager._get_or_create_user_context, seed from chat_profile (header), not settings.

Gemini safety settings: the dict you pass isn’t the SDK’s shape; either use the official structure or pass None.

PDF import: PyPDF2 at module import can break environments without it—lazy import is safer.

Healthcheck: /health isn’t a Chainlit endpoint by default—this script will always fail unless you front it with a proxy.

Below are minimal diffs to address all of that while keeping the code small and streaming-only.

1) Streaming-only + persona fixes
/src/response_generator.py — remove the non-streaming method (and the bug)
@@
 class ResponseGenerator:
@@
-    async def generate_response(
-        self,
-        query: str,
-        retrieved_chunks: List[Dict[str, Any]],
-        user_persona: str
-    ) -> str:
-        """
-        Generate contextual response using retrieved CWE data.
-
-        Args:
-            query: User query string
-            retrieved_chunks: Retrieved chunks from hybrid search
-            user_persona: User persona for response adaptation
-
-        Returns:
-            Generated response string
-        """
-        try:
-            logger.info(f"Generating response for persona: {user_persona}")
-
-            if getattr(self, "offline", False):
-                return f"[offline-mode] {user_persona} response for: " + query[:120]
-
-            # Handle empty retrieval results uniformly for all personas
-            if not retrieved_chunks:
-                return self._generate_fallback_response(query, user_persona)
-
-            # Build structured context from retrieved chunks
-            context = self._build_context(retrieved_chunks)
-
-            # Select persona-specific prompt template
-            prompt_template = self.persona_prompts.get(user_persona, self.persona_prompts["Developer"])
-
-            # Generate response using provider with RAG context
-            prompt = prompt_template.format(
-                user_query=query,
-                cwe_context=context
-            )
-
-            parts: List[str] = []
-            async for token in self.generate_response_streaming(
-                query, retrieved_chunks, user_persona, user_evidence=user_evidence
-            ):
-                parts.append(token)
-            text = "".join(parts)
-            text = self._clean_response(text)
-            if user_persona == "CVE Creator":
-                text = self._format_cve_creator(text)
-            logger.info(f"Generated response length: {len(text)} characters")
-            return text
-
-        except Exception as e:
-            logger.error(f"Response generation failed: {e}")
-            return self._generate_error_response(user_persona)
-
@@
-    def _clean_response(self, response: str) -> str:
-        """
-        Clean and validate generated response.
-
-        Args:
-            response: Raw generated response
-
-        Returns:
-            Cleaned response string
-        """
-        # Remove only leading role labels; avoid nuking legitimate content
-        cleaned = re.sub(r'^(?:Instructions?|System|Assistant)\s*:\s*', '', response.strip(), flags=re.IGNORECASE)
-
-        # Ensure response is not empty
-        if not cleaned.strip():
-            return "I apologize, but I couldn't generate a proper response. Please try rephrasing your question about CWE topics."
-
-        return cleaned.strip()


(We also removed _clean_response because it’s only used by the deleted method. Keeping _format_cve_creator is fine for tests/compat, but it’s unused by the streaming path.)

/src/conversation.py — remove non-streaming entrypoint & seed persona from header
@@ class ConversationManager:
-    async def process_user_message(
-        self,
-        session_id: str,
-        message_content: str,
-        message_id: str
-    ) -> Dict[str, Any]:
-        """
-        Non-streaming wrapper that delegates to the core path.
-        """
-        ...
-        # (entire method deleted)
-
@@
     def _get_or_create_user_context(self, session_id: str) -> UserContext:
         """Back-compat shim: use central session helper and bind session id if missing."""
         ctx = get_user_context()
         if not getattr(ctx, "session_id", None):
             ctx.session_id = session_id
-        # Seed persona from stored UI settings if available (first touch only)
-        try:
-            ui_settings = cl.user_session.get("ui_settings") or {}
-            persona = ui_settings.get("persona")
-            if persona and ctx.persona != persona:
-                ctx.persona = persona
-        except Exception:
-            pass
+        # Seed persona from the header ChatProfile (single source of truth)
+        try:
+            selected = cl.user_session.get("chat_profile")
+            if isinstance(selected, str) and UserPersona.is_valid_persona(selected) and ctx.persona != selected:
+                ctx.persona = selected
+        except Exception:
+            pass
         ctx.update_activity()
         return ctx

2) Persona bugs in main.py
@@ async def main(message: cl.Message):
-    # Ensure conversation context exists with current persona (settings panel drives persona)
-    context = conversation_manager.get_session_context(session_id)
-    if not context or context.persona != ui_settings["persona"]:
-        await conversation_manager.update_user_persona(session_id, ui_settings["persona"])
+    # Ensure persona follows the top-bar ChatProfile (not settings)
+    context = conversation_manager.get_session_context(session_id)
+    selected_profile = cl.user_session.get("chat_profile")
+    if isinstance(selected_profile, str) and selected_profile in UserPersona.get_all_personas():
+        if not context or context.persona != selected_profile:
+            await conversation_manager.update_user_persona(session_id, selected_profile)
@@
-                current_ctx = conversation_manager.get_session_context(session_id)
-                current_persona = current_ctx.persona if current_ctx else persona
+                current_ctx = conversation_manager.get_session_context(session_id)
+                current_persona = (current_ctx.persona if current_ctx else UserPersona.DEVELOPER.value)
@@
-        current_ctx = conversation_manager.get_session_context(session_id)
-        current_persona = current_ctx.persona if current_ctx else persona
+        current_ctx = conversation_manager.get_session_context(session_id)
+        current_persona = (current_ctx.persona if current_ctx else UserPersona.DEVELOPER.value)
         logger.info(f"Processing user query: '{user_query[:100]}...' for persona: {current_persona}")


(This removes the ui_settings["persona"] dependency and the undefined persona variable.)

3) Gemini safety settings: use correct shape or None

The dict you pass likely won’t be accepted by the SDK. Easiest minimal fix: don’t pass safety_settings (let defaults apply) until you wire the official structure.

/src/llm_provider.py
 class GoogleProvider(LLMProvider):
@@
-        self._gen_cfg = generation_config or {}
-        self._safety = safety_settings or {}
+        self._gen_cfg = generation_config or {}
+        self._safety = safety_settings or None
@@
     async def generate_stream(self, prompt: str) -> AsyncGenerator[str, None]:
-        stream = await self._model.generate_content_async(
-            prompt,
-            generation_config=self._gen_cfg,
-            safety_settings=self._safety,
-            stream=True,
-        )
+        stream = await self._model.generate_content_async(
+            prompt,
+            generation_config=self._gen_cfg,
+            stream=True,
+        )
@@
     async def generate(self, prompt: str) -> str:
-        resp = await self._model.generate_content_async(
-            prompt,
-            generation_config=self._gen_cfg,
-            safety_settings=self._safety,
-        )
+        resp = await self._model.generate_content_async(
+            prompt,
+            generation_config=self._gen_cfg,
+        )
         return resp.text or ""


(If you really want relaxed safety, use the SDK’s SafetySetting list; happy to drop the exact snippet if you want it.)

4) Lazy-import PDF lib (optional but safer)
/src/file_processor.py
-import PyPDF2
@@
-    def _extract_pdf_content(self, pdf_content: bytes) -> str:
+    def _extract_pdf_content(self, pdf_content: bytes) -> str:
+        # Lazy import to avoid hard dependency if PDFs aren't used
+        import PyPDF2  # type: ignore

5) Healthcheck note

Your healthcheck.py hits /health, but Chainlit doesn’t expose that route by default. Either:

remove the script, or

front Chainlit with a tiny reverse proxy (nginx) that exposes /health, or

add a lightweight sidecar that checks DB connectivity instead.

Do I agree with the overall direction?

Agree: streaming-only path, Chainlit-native session state, evidence kept separate from RAG chunks, persona driven entirely by ChatProfile.

Disagree (softly): you reverted to “newing up” dependencies inside ConversationManager. If you want minimal, that’s fine; if you want testable, consider a tiny compromise:

class ConversationManager:
    def __init__(
        self,
        database_url: str,
        gemini_api_key: str,
        *,
        query_handler: CWEQueryHandler | None = None,
        response_generator: ResponseGenerator | None = None,
        query_processor: QueryProcessor | None = None,
        security_validator: SecurityValidator | None = None,
        input_sanitizer: InputSanitizer | None = None,
    ):
        self.input_sanitizer = input_sanitizer or InputSanitizer()
        self.security_validator = security_validator or SecurityValidator()
        self.query_handler = query_handler or CWEQueryHandler(database_url, gemini_api_key)
        self.response_generator = response_generator or ResponseGenerator(gemini_api_key)
        self.query_processor = query_processor or QueryProcessor()


That keeps main.py simple and gives you DI for tests.