1) kill the duplicate session manager (use only cl.user_session)

You already centralized around utils/session.py. Let’s remove the legacy manager and any remnants.

Delete UserContextManager class & param

File: src/user_context.py

Remove the entire UserContextManager class (from class UserContextManager: to end of class).

Nothing else in the repo truly needs it.

File: src/conversation.py

-    def __init__(
-        self,
-        database_url: str,
-        gemini_api_key: str,
-        context_manager: Optional[Any] = None  # kept for backward-compat; no longer used
-    ):
+    def __init__(self, database_url: str, gemini_api_key: str):
         try:
-            self.context_manager = context_manager  # deprecated; state now in cl.user_session
+            # no local context manager; state lives in cl.user_session


No other code changes needed because you’re already using get_user_context() everywhere.

2) fix direct-CWE routing bug in QueryProcessor

_determine_search_strategy() looks for has_direct_cwe on the dict you pass, but you pass cwe_analysis (which doesn’t have it). Two tiny edits make it correct and future-proof:

File: src/processing/query_processor.py

-            # Step 3: CWE extraction and analysis
+            # Step 3: CWE extraction and analysis
             cwe_analysis = self.cwe_extractor.enhance_query_for_search(sanitized_query)
             has_direct = self.cwe_extractor.has_direct_cwe_reference(sanitized_query)
 
             # Step 4: Build comprehensive result
-            result = {
+            analysis = {
                 # Original and processed queries
                 "original_query": query,
                 "sanitized_query": sanitized_query,
 
                 # Security analysis
                 "security_check": {
                     "is_potentially_malicious": is_malicious,
                     "detected_patterns": detected_patterns,
                     "sanitization_applied": sanitized_query != query
                 },
 
                 # CWE analysis
-                "cwe_ids": cwe_analysis['cwe_ids'],
-                "keyphrases": cwe_analysis['keyphrases'],
-                "query_type": cwe_analysis['query_type'],
-                "has_direct_cwe": has_direct,
-                "enhanced_query": cwe_analysis['enhanced_query'],
+                "cwe_ids": cwe_analysis['cwe_ids'],
+                "keyphrases": cwe_analysis['keyphrases'],
+                "query_type": cwe_analysis['query_type'],
+                "has_direct_cwe": has_direct,
+                "enhanced_query": cwe_analysis['enhanced_query'],
             }
 
             # Query routing information
-            "search_strategy": self._determine_search_strategy(cwe_analysis),
-            "boost_factors": self._calculate_boost_factors(cwe_analysis)
-            }
+            analysis["search_strategy"] = self._determine_search_strategy(analysis)
+            analysis["boost_factors"] = self._calculate_boost_factors(analysis)
 
-            logger.debug(f"Query preprocessing completed: {result['query_type']}")
-            return result
+            logger.debug(f"Query preprocessing completed: {analysis['query_type']}")
+            return analysis


And make the helpers expect that dict:

-    def _determine_search_strategy(self, cwe_analysis: Dict[str, Any]) -> str:
+    def _determine_search_strategy(self, analysis: Dict[str, Any]) -> str:
-        if cwe_analysis.get('has_direct_cwe'):
+        if analysis.get('has_direct_cwe'):
             return "direct_lookup"
-        query_type = cwe_analysis['query_type']
+        query_type = analysis['query_type']
-        if cwe_analysis['keyphrases']:
+        if analysis['keyphrases']:
             return "sparse_search"

-    def _calculate_boost_factors(self, cwe_analysis: Dict[str, Any]) -> Dict[str, float]:
+    def _calculate_boost_factors(self, analysis: Dict[str, Any]) -> Dict[str, float]:
         boost_factors = {"dense": 1.0, "sparse": 1.0}
-        if cwe_analysis['keyphrases']:
-            keyphrase_count = sum(len(phrases) for phrases in cwe_analysis['keyphrases'].values())
+        if analysis['keyphrases']:
+            keyphrase_count = sum(len(phrases) for phrases in analysis['keyphrases'].values())
             boost_factors["sparse"] = 1.0 + (keyphrase_count * 0.1)
-        query_type = cwe_analysis['query_type']
+        query_type = analysis['query_type']
         if query_type in ['general_security', 'prevention_guidance']:
             boost_factors["dense"] = 1.2
         return boost_factors

3) make follow-ups work without extra state (use last CWEs)

Tiny tweak: if there is no current_cwe in session context, use the most recent from last_cwes.

File: src/processing/query_processor.py

-            context_cwe = None
-            if session_context and session_context.get('current_cwe'):
-                context_cwe = session_context['current_cwe'].get('cwe_id')
+            context_cwe = None
+            if session_context:
+                # support either a dict ('current_cwe': {'cwe_id': 'CWE-79'}) or a simple string
+                cur = session_context.get('current_cwe')
+                if isinstance(cur, dict):
+                    context_cwe = cur.get('cwe_id')
+                elif isinstance(cur, str):
+                    context_cwe = cur
+                # fallback to the most recent from last_cwes
+                if not context_cwe:
+                    last = session_context.get('last_cwes') or []
+                    if last:
+                        context_cwe = last[-1]


This avoids adding more fields or storage—pure reuse of what you already have in UserContext.

4) remove persona conditionals in generation (policy is uniform)

You wanted no if persona == "CVE Creator" anywhere. The only remaining branch is cosmetic formatting. Let the prompt template drive formatting instead.

File: src/response_generator.py

-            # CVE Creator formatting: convert [segments] to **bold** (avoid markdown links)
-            if user_persona == "CVE Creator":
-                formatted = self._format_cve_creator(cleaned_response)
-                if formatted != cleaned_response:
-                    try:
-                        message.content = formatted
-                        await message.update()
-                    except Exception:
-                        pass
-                cleaned_response = formatted

-            # CVE Creator formatting: convert [segments] to **bold** (avoid markdown links)
-            if user_persona == "CVE Creator":
-                cleaned_response = self._format_cve_creator(cleaned_response)


(Optional) You can delete _format_cve_creator() entirely if not used elsewhere.

5) simplify ingestion imports (no sys.path hacks)

Rely on a single, clean import. Either install your ingestion as a package (recommended) or move it under src/. For minimal code, assume package cwe_ingestion is installed.

File: src/query_handler.py

-import asyncio
-import sys
-import os
-from pathlib import Path
+import asyncio
 import logging
 from typing import Dict, List, Any, Optional
 from src.security.secure_logging import get_secure_logger
-
-# Prefer package import; allow override via CWE_INGESTION_PATH
-try:
-    # If the repo is run from root, this works without hacks
-    from apps.cwe_ingestion.pg_chunk_store import PostgresChunkStore  # type: ignore
-    from apps.cwe_ingestion.embedder import GeminiEmbedder  # type: ignore
-except Exception:
-    ingestion_path = os.getenv("CWE_INGESTION_PATH")
-    if ingestion_path and os.path.isdir(ingestion_path):
-        sys.path.insert(0, ingestion_path)
-        try:
-            # Support pointing directly at the cwe_ingestion folder
-            from pg_chunk_store import PostgresChunkStore  # type: ignore
-            from embedder import GeminiEmbedder  # type: ignore
-        except Exception as e:  # pragma: no cover
-            logging.error(f"Failed to import ingestion modules from CWE_INGESTION_PATH={ingestion_path}: {e}")
-            raise ImportError(
-                "Unable to import ingestion modules. Set CWE_INGESTION_PATH to the 'apps/cwe_ingestion' directory, "
-                "or install the ingestion package so 'apps.cwe_ingestion' can be imported."
-            ) from e
-    else:  # pragma: no cover
-        raise ImportError(
-            "Ingestion modules not found. Either install the project so 'apps.cwe_ingestion' is importable, or set "
-            "CWE_INGESTION_PATH environment variable to point at the 'apps/cwe_ingestion' directory."
-        )
+from cwe_ingestion.pg_chunk_store import PostgresChunkStore  # type: ignore
+from cwe_ingestion.embedder import GeminiEmbedder  # type: ignore


That’s it. (If you can’t package it yet, keep your current code, but this is the minimal path.)

6) trim unused modules & dead code

Delete src/processing/embedding_service.py (unused; QueryHandler uses the ingestion embedder).

Delete src/prompts/role_templates.py (you aren’t importing it; ResponseGenerator uses its own templates).

(Optional) Delete VertexProvider from llm_provider.py if you don’t plan to run on Vertex. Keeps one codepath.

7) let Chainlit drive persona 100% (no duplication)

Right now persona is both in ChatProfile and stored in ui_settings. We can simplify and always trust the chat profile slot that Chainlit keeps for us.

File: src/main.py

In UISettings, remove persona field and all references. It’s not in the settings panel anyway.

-class UISettings(BaseModel):
-    persona: Literal["PSIRT Member", "Developer", "Academic Researcher", "Bug Bounty Hunter", "Product Manager", "CWE Analyzer", "CVE Creator"] = Field(
-        default="Developer",
-        description="Your cybersecurity role - determines response focus and depth"
-    )
+class UISettings(BaseModel):
     detail_level: Literal["basic", "standard", "detailed"] = Field(
         default="standard",
         description="Level of detail in responses"
     )


In on_chat_start, set persona from chat_profile only:

-    default_settings = UISettings()
-    selected_profile = cl.user_session.get("chat_profile")
-    if isinstance(selected_profile, str) and selected_profile in UserPersona.get_all_personas():
-        default_settings.persona = selected_profile
-    cl.user_session.set("ui_settings", default_settings.dict())
+    default_settings = UISettings()
+    cl.user_session.set("ui_settings", default_settings.dict())
+    selected_profile = cl.user_session.get("chat_profile")
+    persona = selected_profile if isinstance(selected_profile, str) and selected_profile in UserPersona.get_all_personas() else UserPersona.DEVELOPER.value
+    await conversation_manager.update_user_persona(cl.context.session.id, persona)


In on_message, don’t read persona from ui_settings:

-    ui_settings = cl.user_session.get("ui_settings")
+    ui_settings = cl.user_session.get("ui_settings")
     if not ui_settings:
         default_settings = UISettings()
         ui_settings = default_settings.dict()
         cl.user_session.set("ui_settings", ui_settings)

-    context = conversation_manager.get_session_context(session_id)
-    if not context or context.persona != ui_settings["persona"]:
-        await conversation_manager.update_user_persona(session_id, ui_settings["persona"])
+    # persona comes from Chat Profile and is already set on chat start; refresh if user changed header profile
+    selected_profile = cl.user_session.get("chat_profile")
+    if isinstance(selected_profile, str) and selected_profile in UserPersona.get_all_personas():
+        ctx = conversation_manager.get_session_context(session_id)
+        if not ctx or ctx.persona != selected_profile:
+            await conversation_manager.update_user_persona(session_id, selected_profile)


In on_settings_update, stop trying to update persona (it’s not in settings anymore).

-        # Update persona if it changed
-        current_context = conversation_manager.get_session_context(session_id)
-        if current_context and current_context.persona != model.persona:
-            success = await conversation_manager.update_user_persona(session_id, model.persona)
-            ...
+        # persona changes via ChatProfile only; nothing to do here


This removes a whole class of “persona drift” bugs and keeps persona management purely Chainlit-native.

8) tiny safety/UX polish (optional but easy)

In response_generator._build_context, tag evidence separately for readability (you already do via cwe_id="EVIDENCE"; nice). Consider prefixing the title consistently:

-            context_parts.append(f"\n--- {cid}: {name} ---")
+            title = "Uploaded Evidence" if cid == "EVIDENCE" else f"{cid}: {name}"
+            context_parts.append(f"\n--- {title} ---")


In conversation._process_message_core, your evidence wrapper markers are great for isolation. Keep them; no change needed.

sanity check (what this buys you)

Smaller surface area: no second session manager; no import hacks; fewer persona branches; fewer moving parts.

Bug fixes: direct-CWE detection now routes correctly; follow-ups work without adding new state.

Chainlit-first: persona is driven by Chat Profiles only; settings panel handles non-persona knobs.

Less code: delete 2 modules (or 3 if you drop Vertex), delete legacy manager, delete persona-specific formatting.




## Patch

here’s a minimal PR-style diff bundle you can drop in. It removes the legacy session manager, fixes direct-CWE routing, simplifies persona handling (no special CVE Creator branches), trims import hacks, leans on Chainlit for persona, and deletes dead modules.

Apply with git apply or copy/paste manually. If you haven’t packaged your ingestion lib yet, either install it as cwe_ingestion or skip the query_handler.py import simplification for now.

diff --git a/ingest/src/user_context.py b/ingest/src/user_context.py
--- a/ingest/src/user_context.py
+++ b/ingest/src/user_context.py
@@ -1,6 +1,5 @@
 #!/usr/bin/env python3
 """
 User Context and Persona Management - Story 2.1
-Manages user personas, context, and session state for personalized CWE responses.
+Manages user personas, context, and session state for personalized CWE responses.
 """
@@
 class UserContext:
@@
         return {
             "persona": self.persona,
             "last_cwes": self.last_cwes_discussed[-5:],
         }
 
-
-class UserContextManager:
-    """
-    Manages user contexts and session state for the CWE chatbot.
-
-    Provides session management, persona tracking, and context persistence
-    for personalized user experiences.
-    """
-
-    def __init__(self) -> None:
-        """Initialize context manager."""
-        self.active_sessions: Dict[str, UserContext] = {}
-        self.session_timeout_minutes = 30
-        logger.info("UserContextManager initialized")
-
-    def create_session(self, session_id: str = None, persona: str = UserPersona.DEVELOPER.value) -> UserContext:
-        """
-        Create new user session with specified persona.
-
-        Args:
-            session_id: Explicit session ID (uses Chainlit session ID)
-            persona: User persona for role-based responses
-
-        Returns:
-            New UserContext instance
-        """
-        if not UserPersona.is_valid_persona(persona):
-            logger.warning(f"Invalid persona '{persona}', defaulting to Developer")
-            persona = UserPersona.DEVELOPER.value
-
-        # Create context with explicit session_id if provided
-        if session_id:
-            context = UserContext(persona=persona)
-            context.session_id = session_id  # Override the auto-generated UUID
-        else:
-            context = UserContext(persona=persona)
-
-        # Set persona-specific defaults
-        persona_defaults = self._get_persona_defaults(persona)
-        for key, value in persona_defaults.items():
-            if hasattr(context, key):
-                setattr(context, key, value)
-
-        self.active_sessions[context.session_id] = context
-        logger.info(f"Created session {context.session_id} for persona: {persona}")
-
-        return context
-
-    def get_session(self, session_id: str) -> Optional[UserContext]:
-        """
-        Get existing session by ID.
-
-        Args:
-            session_id: Session identifier
-
-        Returns:
-            UserContext if found, None otherwise
-        """
-        context = self.active_sessions.get(session_id)
-        if context:
-            context.update_activity()
-
-        return context
-
-    def update_persona(self, session_id: str, new_persona: str) -> bool:
-        """
-        Update session persona.
-
-        Args:
-            session_id: Session identifier
-            new_persona: New persona to set
-
-        Returns:
-            True if updated successfully, False otherwise
-        """
-        if not UserPersona.is_valid_persona(new_persona):
-            logger.error(f"Invalid persona: {new_persona}")
-            return False
-
-        context = self.get_session(session_id)
-        if not context:
-            logger.error(f"Session not found: {session_id}")
-            return False
-
-        old_persona = context.persona
-        context.persona = new_persona
-
-        # Update persona-specific defaults
-        persona_defaults = self._get_persona_defaults(new_persona)
-        for key, value in persona_defaults.items():
-            if hasattr(context, key):
-                setattr(context, key, value)
-
-        context.update_activity()
-        logger.info(f"Updated session {session_id} persona: {old_persona} -> {new_persona}")
-
-        return True
-
-    def record_interaction(
-        self,
-        session_id: str,
-        query: str,
-        response: str,
-        retrieved_cwes: List[str],
-        feedback_rating: Optional[int] = None
-    ) -> bool:
-        """
-        Record user interaction for analytics and context.
-
-        Args:
-            session_id: Session identifier
-            query: User query
-            response: System response
-            retrieved_cwes: CWEs retrieved for response
-            feedback_rating: Optional user feedback rating (1-5)
-
-        Returns:
-            True if recorded successfully, False otherwise
-        """
-        context = self.get_session(session_id)
-        if not context:
-            logger.error(f"Session not found: {session_id}")
-            return False
-
-        context.add_conversation_entry(query, response, retrieved_cwes)
-
-        if feedback_rating is not None and 1 <= feedback_rating <= 5:
-            context.feedback_ratings.append(feedback_rating)
-            # Keep only last 20 ratings
-            if len(context.feedback_ratings) > 20:
-                context.feedback_ratings = context.feedback_ratings[-20:]
-
-        logger.debug(f"Recorded interaction for session {session_id}")
-        return True
-
-    def cleanup_expired_sessions(self) -> int:
-        """
-        Remove expired sessions based on timeout.
-
-        Returns:
-            Number of sessions cleaned up
-        """
-        current_time = datetime.now(timezone.utc)
-        expired_sessions = []
-
-        for session_id, context in self.active_sessions.items():
-            time_diff = current_time - context.last_active
-            if time_diff.total_seconds() > (self.session_timeout_minutes * 60):
-                expired_sessions.append(session_id)
-
-        for session_id in expired_sessions:
-            del self.active_sessions[session_id]
-
-        if expired_sessions:
-            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
-
-        return len(expired_sessions)
-
-    def get_session_analytics(self, session_id: str) -> Dict[str, Any]:
-        """
-        Get analytics data for a session.
-
-        Args:
-            session_id: Session identifier
-
-        Returns:
-            Analytics data dictionary
-        """
-        context = self.get_session(session_id)
-        if not context:
-            return {}
-
-        avg_rating = (
-            sum(context.feedback_ratings) / len(context.feedback_ratings)
-            if context.feedback_ratings else None
-        )
-
-        return {
-            "session_id": session_id,
-            "persona": context.persona,
-            "query_count": context.query_count,
-            "conversation_entries": len(context.conversation_history),
-            "average_feedback_rating": avg_rating,
-            "session_duration_minutes": (
-                (context.last_active - context.created_at).total_seconds() / 60
-            ),
-            "unique_cwes_discussed": len(set(context.last_cwes_discussed)),
-            "last_query": context.last_query
-        }
-
-    def _get_persona_defaults(self, persona: str) -> Dict[str, Any]:
-        """Get default settings for a persona."""
-        defaults = {
-            UserPersona.PSIRT_MEMBER.value: {
-                "section_boost": "Impact",
-                "response_detail_level": "detailed",
-                "include_examples": True,
-                "include_mitigations": True
-            },
-            UserPersona.DEVELOPER.value: {
-                "section_boost": "Mitigation",
-                "response_detail_level": "standard",
-                "include_examples": True,
-                "include_mitigations": True
-            },
-            UserPersona.ACADEMIC_RESEARCHER.value: {
-                "section_boost": "Description",
-                "response_detail_level": "detailed",
-                "include_examples": True,
-                "include_mitigations": False
-            },
-            UserPersona.BUG_BOUNTY_HUNTER.value: {
-                "section_boost": "Example",
-                "response_detail_level": "standard",
-                "include_examples": True,
-                "include_mitigations": False
-            },
-            UserPersona.PRODUCT_MANAGER.value: {
-                "section_boost": "Impact",
-                "response_detail_level": "standard",
-                "include_examples": False,
-                "include_mitigations": True
-            },
-            UserPersona.CWE_ANALYZER.value: {
-                "section_boost": "Description",
-                "response_detail_level": "detailed",
-                "include_examples": True,
-                "include_mitigations": False
-            },
-            UserPersona.CVE_CREATOR.value: {
-                "section_boost": "Description",
-                "response_detail_level": "standard",
-                "include_examples": True,
-                "include_mitigations": False
-            }
-        }
-
-        return defaults.get(persona, defaults[UserPersona.DEVELOPER.value])
-
-    def get_active_session_count(self) -> int:
-        """Get number of currently active sessions."""
-        return len(self.active_sessions)
-
-    def get_persona_distribution(self) -> Dict[str, int]:
-        """Get distribution of active sessions by persona."""
-        distribution: Dict[str, int] = {}
-        for context in self.active_sessions.values():
-            persona = context.persona
-            distribution[persona] = distribution.get(persona, 0) + 1
-
-        return distribution
+    # (Legacy UserContextManager removed; Chainlit's cl.user_session is the single source of truth.)
diff --git a/ingest/src/conversation.py b/ingest/src/conversation.py
--- a/ingest/src/conversation.py
+++ b/ingest/src/conversation.py
@@
 class ConversationManager:
@@
-    def __init__(
-        self,
-        database_url: str,
-        gemini_api_key: str,
-        context_manager: Optional[Any] = None  # kept for backward-compat; no longer used
-    ):
+    def __init__(self, database_url: str, gemini_api_key: str):
@@
-            self.context_manager = context_manager  # deprecated; state now in cl.user_session
+            # no local context manager; state now in cl.user_session
             self.input_sanitizer = InputSanitizer()
             self.security_validator = SecurityValidator()
             self.query_handler = CWEQueryHandler(database_url, gemini_api_key)
             self.response_generator = ResponseGenerator(gemini_api_key)
             self.query_processor = QueryProcessor()
diff --git a/ingest/src/processing/query_processor.py b/ingest/src/processing/query_processor.py
--- a/ingest/src/processing/query_processor.py
+++ b/ingest/src/processing/query_processor.py
@@
     def preprocess_query(self, query: str) -> Dict[str, Any]:
@@
-            # Step 4: Build comprehensive result
-            result = {
+            # Step 4: Build comprehensive result
+            analysis = {
                 # Original and processed queries
                 "original_query": query,
                 "sanitized_query": sanitized_query,
@@
                 # CWE analysis
-                "cwe_ids": cwe_analysis['cwe_ids'],
-                "keyphrases": cwe_analysis['keyphrases'],
-                "query_type": cwe_analysis['query_type'],
-                "has_direct_cwe": has_direct,
-                "enhanced_query": cwe_analysis['enhanced_query'],
+                "cwe_ids": cwe_analysis['cwe_ids'],
+                "keyphrases": cwe_analysis['keyphrases'],
+                "query_type": cwe_analysis['query_type'],
+                "has_direct_cwe": has_direct,
+                "enhanced_query": cwe_analysis['enhanced_query'],
 
                 # Query routing information
-                "search_strategy": self._determine_search_strategy(cwe_analysis),
-                "boost_factors": self._calculate_boost_factors(cwe_analysis)
-            }
+            }
+            analysis["search_strategy"] = self._determine_search_strategy(analysis)
+            analysis["boost_factors"] = self._calculate_boost_factors(analysis)
 
-            logger.debug(f"Query preprocessing completed: {result['query_type']}")
-            return result
+            logger.debug(f"Query preprocessing completed: {analysis['query_type']}")
+            return analysis
@@
-    def _determine_search_strategy(self, cwe_analysis: Dict[str, Any]) -> str:
+    def _determine_search_strategy(self, analysis: Dict[str, Any]) -> str:
@@
-        if cwe_analysis.get('has_direct_cwe'):
+        if analysis.get('has_direct_cwe'):
             return "direct_lookup"
 
-        query_type = cwe_analysis['query_type']
+        query_type = analysis['query_type']
         if query_type == 'direct_cwe_lookup':
             return "direct_lookup"
         if query_type in ['vulnerability_inquiry', 'prevention_guidance']:
             return "hybrid_search"
@@
-        if cwe_analysis['keyphrases']:
+        if analysis['keyphrases']:
             return "sparse_search"
@@
-    def _calculate_boost_factors(self, cwe_analysis: Dict[str, Any]) -> Dict[str, float]:
+    def _calculate_boost_factors(self, analysis: Dict[str, Any]) -> Dict[str, float]:
         boost_factors = {"dense": 1.0, "sparse": 1.0}
 
-        if cwe_analysis['keyphrases']:
-            keyphrase_count = sum(len(phrases) for phrases in cwe_analysis['keyphrases'].values())
+        if analysis['keyphrases']:
+            keyphrase_count = sum(len(phrases) for phrases in analysis['keyphrases'].values())
             boost_factors["sparse"] = 1.0 + (keyphrase_count * 0.1)
 
-        query_type = cwe_analysis['query_type']
+        query_type = analysis['query_type']
         if query_type in ['general_security', 'prevention_guidance']:
             boost_factors["dense"] = 1.2
 
         return boost_factors
@@
     def process_with_context(
         self, 
         query: str, 
         session_context: Optional[Dict[str, Any]] = None
     ) -> Dict[str, Any]:
@@
-            context_cwe = None
-            if session_context and session_context.get('current_cwe'):
-                context_cwe = session_context['current_cwe'].get('cwe_id')
+            context_cwe = None
+            if session_context:
+                cur = session_context.get('current_cwe')
+                if isinstance(cur, dict):
+                    context_cwe = cur.get('cwe_id')
+                elif isinstance(cur, str):
+                    context_cwe = cur
+                if not context_cwe:
+                    last = session_context.get('last_cwes') or []
+                    if last:
+                        context_cwe = last[-1]
 
             # Detect follow-up intent
             followup_intent = self.followup_processor.detect_followup_intent(query)
diff --git a/ingest/src/response_generator.py b/ingest/src/response_generator.py
--- a/ingest/src/response_generator.py
+++ b/ingest/src/response_generator.py
@@
     async def generate_response_streaming(
@@
-            # CVE Creator formatting: convert [segments] to **bold** (avoid markdown links)
-            if user_persona == "CVE Creator":
-                formatted = self._format_cve_creator(cleaned_response)
-                if formatted != cleaned_response:
-                    try:
-                        # Update streamed message with final formatted text
-                        message.content = formatted
-                        await message.update()
-                    except Exception:
-                        pass
-                cleaned_response = formatted
             logger.info(f"Generated streaming response length: {len(cleaned_response)} characters")
@@
     async def generate_response(
@@
-            # CVE Creator formatting: convert [segments] to **bold** (avoid markdown links)
-            if user_persona == "CVE Creator":
-                cleaned_response = self._format_cve_creator(cleaned_response)
-
             logger.info(f"Generated response length: {len(cleaned_response)} characters")
@@
     def _build_context(self, chunks: List[Dict[str, Any]]) -> str:
@@
-        for cid, group in by_cwe.items():
+        for cid, group in by_cwe.items():
             best = max(group, key=lambda g: float((g.get("scores") or {}).get("hybrid", 0.0)))
             name = (best.get("metadata") or {}).get("name", "")
-            context_parts.append(f"\n--- {cid}: {name} ---")
+            title = "Uploaded Evidence" if cid == "EVIDENCE" else f"{cid}: {name}"
+            context_parts.append(f"\n--- {title} ---")
@@
-    def _format_cve_creator(self, text: str) -> str:
-        """
-        For CVE Creator persona, replace bracketed segments with bold for easy copy-paste.
-        Avoid altering markdown links of the form [label](url).
-        """
-        # Replace [foo] with **foo** when not followed by '(' (to avoid links)
-        try:
-            return re.sub(r"\[([^\[\]]+)\](?!\()", r"**\1**", text)
-        except Exception:
-            return text
+    # (Removed persona-specific CVE formatting; policy is uniform across roles.)
diff --git a/ingest/src/query_handler.py b/ingest/src/query_handler.py
--- a/ingest/src/query_handler.py
+++ b/ingest/src/query_handler.py
@@
-import asyncio
-import sys
-import os
-from pathlib import Path
+import asyncio
 from typing import Dict, List, Any, Optional
 import logging
 from src.security.secure_logging import get_secure_logger
-
-# Prefer package import; allow override via CWE_INGESTION_PATH
-try:
-    # If the repo is run from root, this works without hacks
-    from apps.cwe_ingestion.pg_chunk_store import PostgresChunkStore  # type: ignore
-    from apps.cwe_ingestion.embedder import GeminiEmbedder  # type: ignore
-except Exception:
-    ingestion_path = os.getenv("CWE_INGESTION_PATH")
-    if ingestion_path and os.path.isdir(ingestion_path):
-        sys.path.insert(0, ingestion_path)
-        try:
-            # Support pointing directly at the cwe_ingestion folder
-            from pg_chunk_store import PostgresChunkStore  # type: ignore
-            from embedder import GeminiEmbedder  # type: ignore
-        except Exception as e:  # pragma: no cover
-            logging.error(f"Failed to import ingestion modules from CWE_INGESTION_PATH={ingestion_path}: {e}")
-            raise ImportError(
-                "Unable to import ingestion modules. Set CWE_INGESTION_PATH to the 'apps/cwe_ingestion' directory, "
-                "or install the ingestion package so 'apps.cwe_ingestion' can be imported."
-            ) from e
-    else:  # pragma: no cover
-        raise ImportError(
-            "Ingestion modules not found. Either install the project so 'apps.cwe_ingestion' is importable, or set "
-            "CWE_INGESTION_PATH environment variable to point at the 'apps/cwe_ingestion' directory."
-        )
+from cwe_ingestion.pg_chunk_store import PostgresChunkStore  # type: ignore
+from cwe_ingestion.embedder import GeminiEmbedder  # type: ignore
diff --git a/ingest/src/main.py b/ingest/src/main.py
--- a/ingest/src/main.py
+++ b/ingest/src/main.py
@@
 class UISettings(BaseModel):
-    persona: Literal["PSIRT Member", "Developer", "Academic Researcher", "Bug Bounty Hunter", "Product Manager", "CWE Analyzer", "CVE Creator"] = Field(
-        default="Developer",
-        description="Your cybersecurity role - determines response focus and depth"
-    )
     detail_level: Literal["basic", "standard", "detailed"] = Field(
         default="standard",
         description="Level of detail in responses"
     )
@@
 async def start():
@@
-    default_settings = UISettings()
-
-    # If a chat profile (top bar) is selected, use it as the persona
-    selected_profile = cl.user_session.get("chat_profile")
-    if isinstance(selected_profile, str) and selected_profile in UserPersona.get_all_personas():
-        default_settings.persona = selected_profile
-
-    cl.user_session.set("ui_settings", default_settings.dict())
+    default_settings = UISettings()
+    cl.user_session.set("ui_settings", default_settings.dict())
@@
-    # Initialize per-user context in Chainlit with default persona
-    session_id = cl.context.session.id
-    await conversation_manager.update_user_persona(session_id, default_settings.persona)
+    # Initialize per-user context persona from the selected Chat Profile (header)
+    session_id = cl.context.session.id
+    selected_profile = cl.user_session.get("chat_profile")
+    persona = selected_profile if isinstance(selected_profile, str) and selected_profile in UserPersona.get_all_personas() else UserPersona.DEVELOPER.value
+    await conversation_manager.update_user_persona(session_id, persona)
@@
 async def main(message: cl.Message):
@@
-    # Ensure conversation context exists with current persona (settings panel drives persona)
-    context = conversation_manager.get_session_context(session_id)
-    if not context or context.persona != ui_settings["persona"]:
-        await conversation_manager.update_user_persona(session_id, ui_settings["persona"])
+    # Ensure persona follows the Chat Profile (header). Update if changed.
+    selected_profile = cl.user_session.get("chat_profile")
+    if isinstance(selected_profile, str) and selected_profile in UserPersona.get_all_personas():
+        context = conversation_manager.get_session_context(session_id)
+        if not context or context.persona != selected_profile:
+            await conversation_manager.update_user_persona(session_id, selected_profile)
@@
 async def on_settings_update(settings: Dict[str, Any]):
@@
-        # Update persona in conversation manager if it changed
-        current_context = conversation_manager.get_session_context(session_id)
-        if current_context and current_context.persona != model.persona:
-            success = await conversation_manager.update_user_persona(session_id, model.persona)
-            if success:
-                logger.info(f"Updated persona to {model.persona} for session {session_id}")
-
-                # Send confirmation message
-                await cl.Message(
-                    content=f"✅ Settings updated! Now responding as **{model.persona}** with **{model.detail_level}** detail level.",
-                    author="System"
-                ).send()
-            else:
-                logger.error(f"Failed to update persona to {model.persona}")
+        # Persona is driven by Chat Profile; nothing to update here.
+        await cl.Message(
+            content=f"✅ Settings updated! Detail level: **{model.detail_level}**. Persona is controlled via the top profile selector.",
+            author="System"
+        ).send()
diff --git a/ingest/src/processing/embedding_service.py b/ingest/src/processing/embedding_service.py
deleted file mode 100644
--- a/ingest/src/processing/embedding_service.py
+++ /dev/null
@@ -1,132 +0,0 @@
-"""
-Gemini embedding service for generating query embeddings (3072-D).
-Wraps the ingestion GeminiEmbedder to standardize chatbot embeddings.
-"""
-# (Removed: not used. QueryHandler directly uses the ingestion embedder.)
diff --git a/ingest/src/prompts/role_templates.py b/ingest/src/prompts/role_templates.py
deleted file mode 100644
--- a/ingest/src/prompts/role_templates.py
+++ /dev/null
@@ -1,400 +0,0 @@
-#!/usr/bin/env python3
-"""
-Role-Based Prompt Templates
-Provides specialized prompt templates based on user roles for tailored CWE responses.
-"""
-# (Removed: not referenced by current pipeline; ResponseGenerator has its own minimal templates.)

one small note on imports

The query_handler.py patch assumes your ingestion code is importable as cwe_ingestion. If it isn’t yet, either:

install it (e.g., pip install -e apps/cwe_ingestion with a proper pyproject.toml), or

keep your existing env-var/sys.path logic for now and skip that hunk.