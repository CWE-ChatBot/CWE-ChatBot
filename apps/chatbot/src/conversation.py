#!/usr/bin/env python3
"""
Conversation Management - Story 2.1
Manages conversation flow, session state, and message handling for Chainlit integration.
"""

import logging
from typing import Dict, List, Any, Optional, AsyncGenerator
from dataclasses import dataclass, field
from datetime import datetime, timezone
import asyncio
import chainlit as cl

import os

from src.user_context import UserContext, UserPersona
from src.input_security import InputSanitizer, SecurityValidator
from src.query_handler import CWEQueryHandler
from src.response_generator import ResponseGenerator
from src.security.secure_logging import get_secure_logger
from src.processing.query_processor import QueryProcessor
from src.processing.pipeline import ProcessingPipeline
from src.utils.text_post import harmonize_cwe_names_in_table
from src.utils.session import get_user_context

from src.app_config_extended import config

logger = get_secure_logger(__name__)


@dataclass
class ConversationMessage:
    """Represents a single message in the conversation."""

    message_id: str
    session_id: str
    content: str
    message_type: str  # 'user', 'assistant', 'system'
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


class ConversationManager:
    """
    Manages conversation flow and integration with Chainlit.

    Handles:
    - Message processing and response generation
    - Session state management
    - Integration with query handler and response generator
    - Security validation and input sanitization
    - Error handling and graceful degradation
    """

    def __init__(self, database_url: str, gemini_api_key: str):
        """
        Initialize conversation manager with required components.

        Args:
            database_url: Database connection string for CWE retrieval
            gemini_api_key: Gemini API key for embeddings and response generation
            context_manager: Optional user context manager (creates new if None)
        """
        try:
            # Initialize core components
            # no local context manager; state now lives in cl.user_session
            self.input_sanitizer = InputSanitizer()
            self.security_validator = SecurityValidator()
            self.query_handler = CWEQueryHandler(database_url, gemini_api_key)
            self.response_generator = ResponseGenerator(gemini_api_key)
            self.query_processor = QueryProcessor()
            self.processing_pipeline = ProcessingPipeline()

            # No local message storage; rely on Chainlit's built-in persistence

            logger.info("ConversationManager initialized successfully")

        except Exception as e:
            logger.log_exception("Failed to initialize ConversationManager", e)
            raise

    # -----------------------------
    # Lightweight helpers
    # -----------------------------
    def _extract_key_phrases(self, text: str) -> Dict[str, str]:
        """Extract simple key phrases like Rootcause/Weakness from free text.

        This is a lightweight, regex-based extractor to improve retrieval hints
        for the CWE Analyzer persona. It complements, not replaces, the LLM
        extraction performed later in the prompt.
        """
        try:
            import re
            phrases: Dict[str, str] = {}
            # Accept variants like Rootcause/Root cause (case-insensitive)
            patterns = {
                'rootcause': r'(?im)^(?:root\s*cause|rootcause)\s*:\s*(.+)$',
                'weakness': r'(?im)^weakness\s*:\s*(.+)$',
            }
            for key, pat in patterns.items():
                m = re.search(pat, text)
                if m:
                    phrases[key] = m.group(1).strip()
            return phrases
        except Exception:
            return {}

    def get_user_context(self, session_id: str) -> UserContext:
        """
        Public accessor to retrieve or create the per-user context.
        Uses the centralized helper from src.utils.session.
        """
        ctx = get_user_context()
        # Bind session id if missing (back-compat)
        if not getattr(ctx, "session_id", None):
            ctx.session_id = session_id
        return ctx

    async def process_user_message_streaming(
        self,
        session_id: str,
        message_content: str,
        message_id: str
    ) -> Dict[str, Any]:
        """
        Streaming wrapper that delegates core logic to a single path.
        """
        try:
            logger.info(f"Processing streaming message for session {session_id}")

            # Get or create user context in cl.user_session
            context = self.get_user_context(session_id)

            # User message is automatically stored by Chainlit

            # Analyzer disambiguation (action-driven): support persistent modes and switching commands
            if context.persona == "CWE Analyzer":
                import re as _re
                # Command switches: /ask, /compare, /exit
                if _re.match(r"^\s*/ask\b", message_content, flags=_re.IGNORECASE):
                    context.analyzer_mode = "question"
                    out_msg = cl.Message(content="Question mode activated. Ask about the last analysis or type /exit to leave.")
                    await out_msg.send()
                    return {
                        "response": out_msg.content,
                        "session_id": session_id,
                        "is_safe": True,
                        "retrieved_cwes": [],
                        "chunk_count": 0,
                        "retrieved_chunks": [],
                        "persona": context.persona,
                        "message": out_msg,
                    }
                if _re.match(r"^\s*/compare\b", message_content, flags=_re.IGNORECASE):
                    context.analyzer_mode = "compare"
                    out_msg = cl.Message(content="Comparison mode activated. Provide candidate CWE ID(s) (e.g., CWE-79, CWE-80). Type /exit to leave.")
                    await out_msg.send()
                    return {
                        "response": out_msg.content,
                        "session_id": session_id,
                        "is_safe": True,
                        "retrieved_cwes": [],
                        "chunk_count": 0,
                        "retrieved_chunks": [],
                        "persona": context.persona,
                        "message": out_msg,
                    }
                # Allow '0' or /exit to exit any active follow-up mode
                if context.analyzer_mode in ("question", "compare") and (_re.match(r"^\s*0\b", message_content) or _re.match(r"^\s*/exit\b", message_content, flags=_re.IGNORECASE)):
                    context.analyzer_mode = None
                    hint = "Exited follow-up mode. Type /ask to ask a question or /compare to compare CWEs."
                    out_msg = cl.Message(content=hint)
                    await out_msg.send()
                    return {
                        "response": hint,
                        "session_id": session_id,
                        "is_safe": True,
                        "retrieved_cwes": [],
                        "chunk_count": 0,
                        "retrieved_chunks": [],
                        "persona": context.persona,
                        "message": out_msg,
                    }

            processed = self.query_processor.process_with_context(
                message_content, context.get_session_context_for_processing()
            )

            # NEW: Handle off-topic queries before processing
            if processed.get("query_type") == "off_topic":
                off_topic_response = (
                    "I'm a cybersecurity assistant focused on MITRE Common Weakness Enumeration (CWE) analysis. "
                    "Your question doesn't appear to be related to cybersecurity topics. "
                    "I can help you with:\n\n"
                    "• **CWE Analysis**: Understanding specific weaknesses like CWE-79 (XSS)\n"
                    "• **Vulnerability Assessment**: Mapping CVEs to CWEs\n"
                    "• **Security Best Practices**: Prevention and mitigation strategies\n"
                    "• **Threat Modeling**: Risk assessment and security guidance\n\n"
                    "What cybersecurity topic can I help you with today?"
                )

                msg = cl.Message(content=off_topic_response)
                await msg.send()

                return {
                    "response": off_topic_response,
                    "session_id": session_id,
                    "is_safe": True,
                    "retrieved_cwes": [],
                    "chunk_count": 0,
                    "retrieved_chunks": [],
                    "persona": context.persona,
                    "message": msg,
                    "query_type": "off_topic"
                }

            security_mode = os.getenv("SECURITY_MODE", "FLAG_ONLY").upper()
            if security_mode == "BLOCK" and processed.get("security_check", {}).get("is_potentially_malicious", False):
                flags = processed.get("security_check", {}).get("detected_patterns", [])
                fallback_response = self.input_sanitizer.generate_fallback_message(flags, context.persona)

                self.security_validator.log_security_event(
                    "unsafe_input_detected",
                    {"session_id": session_id, "security_flags": flags, "persona": context.persona},
                )

                msg = cl.Message(content=fallback_response)
                await msg.send()

                return {
                    "response": fallback_response,
                    "session_id": session_id,
                    "is_safe": False,
                    "security_flags": flags,
                    "retrieved_cwes": [],
                    "chunk_count": 0,
                    "retrieved_chunks": [],
                    "persona": context.persona,
                    "message": msg,
                }
            elif processed.get("security_check", {}).get("is_potentially_malicious", False):
                # In FLAG_ONLY mode, just log the event
                flags = processed.get("security_check", {}).get("detected_patterns", [])
                self.security_validator.log_security_event(
                    "unsafe_input_flagged",
                    {"session_id": session_id, "security_flags": flags, "persona": context.persona},
                )

            # Evidence
            file_ctx = cl.user_session.get("uploaded_file_context")
            if file_ctx and isinstance(file_ctx, str) and file_ctx.strip():
                context.set_evidence(file_ctx[:config.max_file_evidence_length])

            # Merge a brief attachment summary into the query to aid retrieval
            sanitized_q = processed.get("sanitized_query", message_content)
            combined_query = sanitized_q
            attachment_snippet = None
            if context.file_evidence:
                attachment_snippet = self._summarize_attachment(context.file_evidence)
                combined_query = f"{sanitized_q}\n\n[Attachment Summary]\n{attachment_snippet}"

            # Retrieve with combined query
            user_context_data = context.get_persona_preferences()

            # Step 1: Retrieve CWE context
            async with cl.Step(name="Retrieve CWE context") as step:
                # CVE Creator: keep direct creation mode (no retrieval)
                if context.persona == "CVE Creator":
                    retrieved_chunks = []
                    context.set_evidence(sanitized_q)
                    combined_query = "Create a structured CVE description from the provided text."
                    step.output = "CVE creation mode - no retrieval needed"
                elif context.persona == "CWE Analyzer":
                    # CWE Analyzer: perform targeted retrieval to improve mapping quality
                    context.set_evidence(sanitized_q)

                    # Extract lightweight key phrases to boost retrieval
                    key_phrases = self._extract_key_phrases(sanitized_q)
                    boost_terms = []
                    if key_phrases.get('rootcause'):
                        boost_terms.append(key_phrases['rootcause'])
                    if key_phrases.get('weakness'):
                        boost_terms.append(key_phrases['weakness'])

                    analyzer_seed = processed.get("enhanced_query") or sanitized_q
                    analyzer_query = analyzer_seed
                    if boost_terms:
                        analyzer_query = f"{analyzer_seed} " + " ".join(boost_terms)
                    # Add stable hints to emphasize classification
                    analyzer_query = f"{analyzer_query} root cause underlying weakness pattern classification mapping"

                    combined_query = analyzer_query

                    # If in explicit question mode, reuse prior context and avoid new analysis
                    prev_recs = context.last_recommendations or []
                    prev_chunks = context.last_chunks or []

                    if context.analyzer_mode == "question" and prev_chunks:
                        retrieved_chunks = prev_chunks
                        step.output = "Question mode - using prior analysis context"
                        # Build follow-up instruction unconditionally
                        prev_ids = [r.get('cwe_id') for r in prev_recs if r.get('cwe_id')]
                        if prev_ids:
                            followup_note = (
                                "\n\n[Follow-up Instruction]\n"
                                f"Prior recommendations: {', '.join(prev_ids)}\n"
                                "Task: Address the user’s follow-up by referencing and, if needed, revising prior recommendations with clear reasoning.\n"
                            )
                            combined_query = combined_query + followup_note
                    elif context.analyzer_mode == "compare":
                        # Expect candidate CWE IDs from the user input; compare against previous recs
                        candidates = list(processed.get("cwe_ids", set()) or [])
                        prev_ids = [r.get('cwe_id') for r in prev_recs if r.get('cwe_id')]
                        if not candidates:
                            step.output = "Comparison mode - awaiting candidate CWE IDs"
                            msg = cl.Message(content="Provide candidate CWE ID(s) to compare. You can type /exit to leave compare mode.")
                            await msg.send()
                            return {
                                "response": msg.content,
                                "session_id": session_id,
                                "is_safe": True,
                                "retrieved_cwes": [],
                                "chunk_count": 0,
                                "retrieved_chunks": [],
                                "persona": context.persona,
                                "message": msg,
                            }
                        # Build a comparison instruction: focus on suitability, not generic descriptions
                        if prev_ids:
                            compare_note = (
                                "\n\n[Follow-up Comparison]\n"
                                f"Candidate CWEs: {', '.join(candidates)}\n"
                                f"Prior recommendations: {', '.join(prev_ids)}\n"
                                "Task: For each candidate, decide suitability relative to the original evidence: "
                                "Primary / Secondary / Related / Not a fit. Provide concise justification referencing the original evidence. "
                                "Do NOT provide generic CWE descriptions.\n\n"
                                "Output Format (Markdown Table):\n"
                                "| Candidate CWE | Suitability | Rationale |\n"
                                "|---|---|---|\n"
                                "| CWE-XXX | Primary/Secondary/Related/Not a fit | 1-2 sentences citing specific evidence |\n\n"
                                "Then provide a one-paragraph summary stating whether the primary mapping should change.\n"
                            )
                            combined_query = "Use prior evidence for comparison." + compare_note

                        # Append canonical metadata (name, abstraction, status, policy label) for both prior and candidate CWEs
                        try:
                            scope_ids = prev_ids + candidates
                            if scope_ids:
                                canon = self.query_handler.get_canonical_cwe_metadata(scope_ids)
                                policies = self.query_handler.get_cwe_policy_labels(scope_ids)
                                lines = []
                                for cid in scope_ids:
                                    key = str(cid).upper()
                                    meta = canon.get(key, {})
                                    pol = policies.get(key, {})
                                    name = meta.get('name', '')
                                    abstraction = meta.get('abstraction', '')
                                    status = meta.get('status', '')
                                    mapping_label = pol.get('mapping_label', '')
                                    parts = [f"- {cid}"]
                                    if name:
                                        parts.append(f": {name}")
                                    if abstraction:
                                        parts.append(f" | Abstraction: {abstraction}")
                                    if status:
                                        parts.append(f" | Status: {status}")
                                    if mapping_label:
                                        parts.append(f" | Mapping Policy: {mapping_label}")
                                    lines.append("".join(parts))
                                if lines:
                                    combined_query += "\n\n[Canonical CWE Metadata]\n" + "\n".join(lines) + "\n"
                        except Exception as e:
                            logger.warning(f"Failed to append canonical metadata for comparison: {e}")

                        # Retrieve candidate sections and merge with prior analysis context
                        analyzer_weights = {"w_vec": 0.4, "w_fts": 0.2, "w_alias": 0.4}
                        priorities = ["Aliases", "Description", "Examples"]
                        candidate_chunks: List[Dict[str, Any]] = []
                        for cid in candidates:
                            for sect in priorities:
                                analyzer_context = dict(user_context_data)
                                analyzer_context['section_boost'] = sect
                                # Query per candidate id to pull canonical sections
                                chunks = await self.query_handler.process_query(
                                    cid,
                                    analyzer_context,
                                    hybrid_weights_override=analyzer_weights,
                                )
                                candidate_chunks.extend(chunks[:3])
                                if len(chunks) >= 3:
                                    break
                        # Merge with prior chunks, deduplicate by chunk_id
                        merged = []
                        seen = set()
                        for ch in (prev_chunks + candidate_chunks):
                            cid = (ch.get('chunk_id') or id(ch))
                            if cid in seen:
                                continue
                            seen.add(cid)
                            merged.append(ch)
                        retrieved_chunks = merged
                        step.output = f"Comparison mode - merged {len(retrieved_chunks)} chunks (prior + candidates)"
                    else:
                        # Per-request hybrid weights: bias aliases more heavily for Analyzer
                        analyzer_weights = {"w_vec": 0.4, "w_fts": 0.2, "w_alias": 0.4}

                        # Try prioritized section boosts: Aliases → Description → Examples
                        priorities = ["Aliases", "Description", "Examples"]
                        retrieved_chunks = []
                        for sect in priorities:
                            analyzer_context = dict(user_context_data)
                            analyzer_context['section_boost'] = sect
                            retrieved_chunks = await self.query_handler.process_query(
                                analyzer_query,
                                analyzer_context,
                                hybrid_weights_override=analyzer_weights,
                            )
                            if len(retrieved_chunks) >= 3:
                                break
                        step.output = f"Retrieved {len(retrieved_chunks)} CWE chunks for analysis (boost: {analyzer_context['section_boost']})"
                else:
                    retrieved_chunks = await self.query_handler.process_query(
                        combined_query, user_context_data
                    )
                    step.output = f"Retrieved {len(retrieved_chunks)} relevant CWE chunks"

            # Step 1.5: Process chunks into recommendations (new pipeline)
            recommendations = []
            if retrieved_chunks:
                async with cl.Step(name="Process recommendations") as step:
                    query_result = self.processing_pipeline.generate_recommendations(
                        combined_query, retrieved_chunks, user_context_data
                    )
                    recommendations = query_result['recommendations']
                    step.output = f"Generated {len(recommendations)} CWE recommendations"
            # Store recommendations for follow-up turns (e.g., Analyzer comparisons)
            context.last_recommendations = recommendations or []
            context.last_chunks = retrieved_chunks or []

            # Append canonical metadata for recommended CWEs from DB to assist generation (all personas)
            try:
                rec_ids = [r['cwe_id'] for r in recommendations] if recommendations else []
                if rec_ids:
                    canon = self.query_handler.get_canonical_cwe_metadata(rec_ids)
                    policies = self.query_handler.get_cwe_policy_labels(rec_ids)
                    # Enrich in-memory recommendations with canonical name and mapping policy (for UI/logic)
                    for rec in (recommendations or []):
                        key = str(rec.get('cwe_id', '')).upper()
                        meta = canon.get(key) or {}
                        if meta.get('name'):
                            # Ensure recommendation carries the canonical CWE name
                            rec['name'] = meta.get('name')
                        pol = policies.get(key) or {}
                        if pol.get('mapping_label'):
                            rec['policy_label'] = pol.get('mapping_label')
                    if canon or policies:
                        lines = []
                        for cid in rec_ids:
                            key = str(cid).upper()
                            meta = canon.get(key, {})
                            pol = policies.get(key, {})
                            name = meta.get('name', '')
                            abstraction = meta.get('abstraction', '')
                            status = meta.get('status', '')
                            mapping_label = pol.get('mapping_label', '')
                            parts = [f"- {cid}"]
                            if name:
                                parts.append(f": {name}")
                            if abstraction:
                                parts.append(f" | Abstraction: {abstraction}")
                            if status:
                                parts.append(f" | Status: {status}")
                            if mapping_label:
                                parts.append(f" | Mapping Policy: {mapping_label}")
                            lines.append("".join(parts))
                        if lines:
                            canonical_block = "\n\n[Canonical CWE Metadata]\n" + "\n".join(lines) + "\n"
                            combined_query += canonical_block
                            # Optional debug: echo canonical block to logs/UI to verify LLM sees it
                            try:
                                import os as _os
                                if _os.getenv("DEBUG_CANONICAL", "0") == "1":
                                    logger.info("Canonical CWE block appended to prompt:\n" + canonical_block)
                                    try:
                                        await cl.Message(content="[Debug] Canonical CWE Metadata Appended:\n" + canonical_block, author="System").send()
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                            combined_query += (
                                "\n[Policy Rules]\n"
                                "Use 'Name' and 'Mapping Policy' exactly as provided in Canonical CWE Metadata (authoritative DB values).\n"
                                "Prioritize the CWEs provided in the `[Canonical CWE Metadata]` block. You may override these recommendations if you have a strong, well-justified reason to do so.\n"
                                "- Prohibited: Not a fit for mapping.\n"
                                "- Discouraged: Generally not a fit; only Secondary if clearly justified.\n"
                                "- Allowed-with-Review: Allowed but call out review rationale.\n"
                                "- Allowed: Use without contradicting the policy.\n"
                                "Do NOT contradict the Mapping Policy or the canonical CWE Name in your output.\n"
                            )
            except Exception as e:
                logger.warning(f"Failed to append canonical metadata: {e}")

            # Create message and stream tokens
            # If the user explicitly mentioned a CWE id, echo it upfront for clarity in UI/tests
            preface = ""
            try:
                import re
                m = re.search(r"\bCWE[-_\s]?(\d{1,5})\b", message_content, flags=re.IGNORECASE)
                if m:
                    canonical = f"CWE-{m.group(1)}".upper()
                    preface = f"{canonical}\n\n"
                    # Also emit a small system hint to ensure visibility in UI/tests
                    try:
                        await cl.Message(content=f"Focusing on {canonical}", author="System").send()
                    except Exception:
                        pass
            except Exception:
                pass

            # Step 2: Generate answer - prepare but don't stream inside step
            # Compute mode tag for step clarity (no newlines)
            step_mode_tag = ""
            if context.persona == "CWE Analyzer":
                if context.analyzer_mode == "question":
                    step_mode_tag = " [Analyzer: Question Mode]"
                elif context.analyzer_mode == "compare":
                    step_mode_tag = " [Analyzer: Comparison Mode]"

            collected = ""
            async with cl.Step(name="Generate answer") as step:
                step.output = "Generating response..." + step_mode_tag

            # Build follow-up comparison context for CWE Analyzer
            if context.persona == "CWE Analyzer":
                prev_recs = context.last_recommendations or []
                prev_chunks = context.last_chunks or []
                # If the user proposes specific CWE ids, append a comparison instruction
                candidate_cwes = list(processed.get("cwe_ids", set()) or [])
                followup_intent = getattr(processed.get('followup_intent', None), 'intent_type', None)
                if candidate_cwes and prev_recs:
                    prev_ids = [r.get('cwe_id') for r in prev_recs if r.get('cwe_id')]
                    if prev_ids:
                        followup_note = (
                            "\n\n[Follow-up Comparison]\n"
                            f"Candidate CWEs: {', '.join(candidate_cwes)}\n"
                            f"Prior recommendations: {', '.join(prev_ids)}\n"
                            "Task: Compare the candidate(s) against prior recommendations. Decide if any candidate is a better primary fit; "
                            "if not, classify as Secondary/Related with rationale, and update confidence accordingly.\n"
                        )
                        combined_query = combined_query + followup_note
                elif followup_intent in ("comparison", "clarification", "tell_more") and prev_recs:
                    prev_ids = [r.get('cwe_id') for r in prev_recs if r.get('cwe_id')]
                    if prev_ids:
                        followup_note = (
                            "\n\n[Follow-up Instruction]\n"
                            f"Prior recommendations: {', '.join(prev_ids)}\n"
                            "Task: Address the user’s follow-up by referencing and, if needed, revising prior recommendations with clear reasoning.\n"
                        )
                        combined_query = combined_query + followup_note
            # Canonical CWE metadata should come from the database; no hardcoded overrides

            # Stream response outside of step context so it appears as final message
            # Add a small status tag for CWE Analyzer modes
            mode_tag = ""
            if context.persona == "CWE Analyzer":
                if context.analyzer_mode == "question":
                    mode_tag = "[Analyzer: Question Mode]\n\n"
                elif context.analyzer_mode == "compare":
                    mode_tag = "[Analyzer: Comparison Mode]\n\n"

            msg = cl.Message(content=(mode_tag + (preface or "")))
            await msg.send()
            logger.info(f"Combined query for LLM:\n{combined_query}")
            try:
                async for token in self.response_generator.generate_response_streaming(
                    combined_query,
                    retrieved_chunks or [],  # Provide raw chunks for context building
                    context.persona,
                    user_evidence=context.file_evidence,
                ):
                    if token:  # Ensure token is not None or empty
                        try:
                            await msg.stream_token(token)
                            collected += str(token)  # Ensure token is string
                        except Exception as e:
                            logger.warning(f"Failed to stream token: {e}")
                            collected += str(token)  # Still collect token for processing
            except Exception as e:
                logger.error(f"Streaming generation failed: {e}")
                # Fallback to basic error response if streaming completely fails
                if not collected:
                    collected = self.response_generator._generate_error_response(context.persona)

            # If streamed response is unexpectedly short, try a single non-stream completion
            try:
                import os as _os
                min_chars = int(_os.getenv("MIN_STREAM_CHARS", "480"))
                if len(collected.strip()) < min_chars and (retrieved_chunks or []):
                    full = await self.response_generator.generate_response_full_once(
                        combined_query,
                        retrieved_chunks or [],
                        context.persona,
                        user_evidence=context.file_evidence,
                    )
                    if full and len(full) > len(collected):
                        msg.content = (preface or "") + full
                        await msg.update()
                        collected = full
                        logger.info(f"Filled short streamed response with full generation ({len(full)} chars)")
            except Exception as e:
                logger.warning(f"Full-generation fill failed: {e}")

            # Validate final and update if masked
            validation_result = self.security_validator.validate_response(collected)
            final_response = validation_result["validated_response"]
            # Post-process: harmonize CWE names in Analyzer tables using canonical names from recommendations
            try:
                if context.persona == "CWE Analyzer":
                    # Extract all CWE IDs from the generated table
                    import re
                    all_cwe_ids = re.findall(r"CWE[-_\s]?(\d{1,5})", final_response, re.IGNORECASE)
                    all_cwe_ids = [f"CWE-{c}" for c in all_cwe_ids]

                    if all_cwe_ids:
                        canon = self.query_handler.get_canonical_cwe_metadata(all_cwe_ids)
                        policies = self.query_handler.get_cwe_policy_labels(all_cwe_ids)

                        id_to_name = {k.upper(): v['name'] for k, v in canon.items() if v.get('name')}
                        id_to_policy = {k.upper(): v['mapping_label'] for k, v in policies.items() if v.get('mapping_label')}

                        if id_to_name or id_to_policy:
                            final_response = harmonize_cwe_names_in_table(final_response, id_to_name, id_to_policy)
            except Exception as e:
                logger.warning(f"Failed to harmonize CWE table: {e}")
            if final_response != collected:
                # Preserve any preface (e.g., echoed CWE id) when updating content
                try:
                    new_content = (preface or "") + str(final_response)
                except Exception:
                    new_content = str(final_response)
                msg.content = new_content
                await msg.update()

            # Extract CWE IDs from processed recommendations (better than raw chunks)
            retrieved_cwes = [rec['cwe_id'] for rec in recommendations] if recommendations else []

            # FIX: Prioritize directly requested CWE in context storage
            # If user asked for a specific CWE, put it first in the context list
            direct_cwe_ids = processed.get("cwe_ids", set())
            if direct_cwe_ids and retrieved_cwes:
                # Put directly requested CWEs first, then others
                prioritized_cwes = []
                for cwe_id in direct_cwe_ids:
                    if cwe_id in retrieved_cwes:
                        prioritized_cwes.append(cwe_id)
                        retrieved_cwes.remove(cwe_id)
                prioritized_cwes.extend(retrieved_cwes)
                retrieved_cwes = prioritized_cwes

            # Record interaction directly on the per-user context
            context.add_conversation_entry(combined_query, final_response, retrieved_cwes)
            context.clear_evidence()

            # Assistant message is automatically stored by Chainlit

            # After CWE Analyzer analysis: maintain mode or present command hints
            if context.persona == "CWE Analyzer":
                try:
                    if context.analyzer_mode == "question":
                        await cl.Message(content="(Question mode active) Ask a question about the last analysis. Type /exit to leave.").send()
                    elif context.analyzer_mode == "compare":
                        await cl.Message(content="(Comparison mode active) Provide candidate CWE ID(s). Type /exit to leave.").send()
                    else:
                        # Fresh analysis finished; offer command hints
                        await cl.Message(content="Next: type /ask to ask a question about this analysis, or /compare to compare candidate CWEs.").send()
                except Exception:
                    pass

            return {
                "response": final_response,
                "session_id": session_id,
                "is_safe": validation_result["is_safe"],
                "retrieved_cwes": retrieved_cwes,
                "chunk_count": len(retrieved_chunks or []),
                "recommendations": recommendations,  # New: processed recommendations
                "persona": context.persona,
                "message": msg,
            }
        
        except Exception as e:
            return await self._handle_processing_error(session_id, e)

    # Non-streaming path removed (streaming-only)

    async def update_user_persona(self, session_id: str, new_persona: str) -> bool:
        """
        Update user persona for the session.

        Args:
            session_id: Session identifier
            new_persona: New persona to set

        Returns:
            True if successful, False otherwise
        """
        if not UserPersona.is_valid_persona(new_persona):
            logger.error(f"Invalid persona: {new_persona}")
            return False

        context = self.get_user_context(session_id)
        old_persona = context.persona
        context.persona = new_persona
        context.update_activity()
        logger.info(f"Persona updated from {old_persona} to {new_persona} for session {session_id}")
        return True


    def get_session_context(self, session_id: str) -> Optional[UserContext]:
        """
        Get user context for a session.

        Args:
            session_id: Session identifier

        Returns:
            UserContext if found, None otherwise
        """
        return cl.user_session.get("user_context")

    def record_feedback(self, session_id: str, message_id: str, rating: int) -> bool:
        """
        Record user feedback for a specific message.

        Args:
            session_id: Session identifier
            message_id: Message identifier
            rating: Feedback rating (1-5)

        Returns:
            True if recorded successfully, False otherwise
        """
        if not (1 <= rating <= 5):
            logger.error(f"Invalid rating: {rating}")
            return False

        context = self.get_user_context(session_id)
        if not context:
            logger.error(f"Session not found: {session_id}")
            return False

        context.feedback_ratings.append(rating)
        # Keep only last 20 ratings
        if len(context.feedback_ratings) > 20:
            context.feedback_ratings = context.feedback_ratings[-20:]

        logger.info(f"Recorded feedback for session {session_id}: {rating}")
        return True


    def get_system_health(self) -> Dict[str, Any]:
        """
        Get system health information.

        Returns:
            System health status
        """
        health: Dict[str, Any] = self.query_handler.health_check()
        # Per-user data now lives in cl.user_session; global counts are not available here
        health.update({
            "active_sessions": None,
            "persona_distribution": {}
        })
        return health


    def _summarize_attachment(self, text: str, *, limit: int = None) -> str:
        """Create a brief, safe attachment summary for retrieval/context."""
        if not text:
            return ""
        if limit is None:
            limit = config.max_attachment_summary_length
        t = text.strip()
        if len(t) > limit:
            t = t[:limit] + "..."
        return t

    # Removed actions helper; using slash-command hints instead.

    async def _handle_processing_error(self, session_id: str, error: Exception) -> Dict[str, Any]:
        """Handle processing errors with consistent response pattern."""
        logger.log_exception("Error processing message", error)
        error_response = "I apologize, but I'm experiencing technical difficulties. Please try your question again in a moment."

        msg = cl.Message(content=error_response)
        await msg.send()

        return {
            "response": error_response,
            "session_id": session_id,
            "is_safe": True,
            "error": str(error),
            "message": msg
        }

    # _process_message_core removed; streaming and non-stream paths call shared components directly
