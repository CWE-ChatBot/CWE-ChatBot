#!/usr/bin/env python3
"""
RAG Response Generator - Story 2.1
Generates context-aware responses using retrieved CWE content and persona-specific prompting.
"""

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.app_config import config

from .llm_provider import get_llm_provider
from .model_armor_guard import create_model_armor_guard_from_env

logger = logging.getLogger(__name__)


class ResponseGenerator:
    """
    Generates RAG responses using retrieved CWE content with persona-specific context.

    Features:
    - Persona-aware response adaptation
    - Structured context building from retrieved chunks
    - Security-focused prompting to prevent hallucination
    - Source attribution and confidence indicators
    """

    def __init__(self, gemini_api_key: str, model_name: Optional[str] = None):
        """
        Initialize response generator with configurable LLM settings.

        Args:
            gemini_api_key: Gemini API key
            model_name: Optional model override (uses config default if None)
        """
        try:
            # Allow offline mode (explicit opt-in)
            self.offline = (
                os.getenv("DISABLE_AI") == "1" or os.getenv("GEMINI_OFFLINE") == "1"
            )

            # Get LLM configuration from centralized config
            llm_config = config.get_llm_provider_config()

            # Allow override of model name
            if model_name is not None:
                llm_config["model_name"] = model_name

            # Load persona-specific prompt templates
            self.persona_prompts = self._load_persona_prompts()

            mode = "offline" if self.offline else llm_config["model_name"]
            # Initialize provider adapter with centralized configuration
            self.provider = get_llm_provider(
                provider=llm_config["provider"],
                api_key=gemini_api_key,
                model_name=llm_config["model_name"],
                generation_config=llm_config["generation_config"],
                safety_settings=llm_config["safety_settings"],
                offline=self.offline,
                persona=None,
            )

            logger.info(
                f"ResponseGenerator initialized with {mode} (configurable defaults)"
            )
            logger.info(
                f"LLM Config - Provider: {llm_config['provider']}, Temperature: {llm_config['generation_config']['temperature']}, Safety: {'permissive' if llm_config['safety_settings'] else 'default'}"
            )

            # Initialize Model Armor guard (optional - controlled by env var)
            self.model_armor = create_model_armor_guard_from_env()
            if self.model_armor:
                logger.info(
                    "Model Armor guard initialized (pre/post sanitization enabled)"
                )
            else:
                logger.info(
                    "Model Armor guard disabled (MODEL_ARMOR_ENABLED=false or not set)"
                )

        except Exception as e:
            logger.error(f"Failed to initialize ResponseGenerator: {e}")
            raise

    def _load_persona_prompts(self) -> Dict[str, str]:
        """Load persona-specific prompt templates from files, fallback to defaults."""
        base = Path(__file__).parent / "prompts"
        mapping = {}

        def load_prompt(name: str, fallback: str) -> None:
            p = base / f"{name.replace(' ', '_').lower()}.md"
            if p.exists():
                try:
                    mapping[name] = p.read_text(encoding="utf-8")
                    return
                except Exception:
                    pass
            mapping[name] = fallback

        # Fallback minimal templates (concise) to keep file small
        load_prompt(
            "PSIRT Member",
            """You are a PSIRT-focused assistant.
User Query: {user_query}

CWE Context:
{cwe_context}

User-Provided Evidence:
{user_evidence}

Instructions:
- Emphasize impact, severity, and advisory guidance.
- Cite CWE IDs. Be precise and factual.
Response:""",
        )
        load_prompt(
            "Developer",
            """You are a developer-focused security assistant.
User Query: {user_query}

CWE Context:
{cwe_context}

User-Provided Evidence:
{user_evidence}

Instructions:
- Provide remediation steps and code-level guidance.
- Cite CWE IDs. Keep it actionable.
Response:""",
        )
        load_prompt(
            "Academic Researcher",
            """You are an academic-focused assistant.
User Query: {user_query}

CWE Context:
{cwe_context}

User-Provided Evidence:
{user_evidence}

Instructions:
- Analyze relationships and taxonomies; cite CWEs.
Response:""",
        )
        load_prompt(
            "Bug Bounty Hunter",
            """You are a bug bounty/security researcher assistant.
User Query: {user_query}

CWE Context:
{cwe_context}

User-Provided Evidence:
{user_evidence}

Instructions:
- Highlight exploitation patterns, detection and testing methods.
Response:""",
        )
        load_prompt(
            "Product Manager",
            """You are a product manager-focused assistant.
User Query: {user_query}

CWE Context:
{cwe_context}

User-Provided Evidence:
{user_evidence}

Instructions:
- Focus on risk, prioritization, and prevention strategies.
Response:""",
        )
        load_prompt(
            "CWE Analyzer",
            """You are a CVE-to-CWE mapping assistant.
User Query: {user_query}

User-Provided Evidence:
{user_evidence}

Instructions:
- Analyze the user-provided evidence, which contains a description of a vulnerability.
- Based on your analysis, identify the most relevant Common Weakness Enumeration (CWE) IDs.
- Provide a mapping to the identified CWEs with a confidence score and a brief rationale for each mapping.
Response:""",
        )
        load_prompt(
            "CVE Creator",
            """You are an assistant that creates structured CVE descriptions.
User Query: {user_query}

User-Provided Evidence:
{user_evidence}

Instructions:
- Analyze the user-provided evidence, which contains information about a vulnerability.
- Use the information to create a structured CVE description in the standardized CVE format.
- Identify and format key segments as bold (e.g., **Impact**, **Product**, **Vendor**, **Version**, **Affected Platform**, **Attacker**, **Action**, **Vector**). Do not use square brackets.
- If any information is missing, note it in the description.
Response:""",
        )
        load_prompt(
            "CWE Analyzer Question",
            """You are an expert CWE analyst answering a follow-up question about a previous vulnerability analysis.

User Query: {user_query}

CWE Context:
{cwe_context}

User-Provided Evidence:
{user_evidence}

Instructions:
- Answer the user's question directly and comprehensively
- Reference relevant CWE information from the context
- Provide practical security guidance when appropriate
- Maintain your expertise in vulnerability-to-weakness mapping
- Do NOT perform a new full CWE analysis - just answer the specific question asked
- Cite specific CWE IDs when relevant to the answer

Response:""",
        )
        return mapping

    async def generate_response(
        self,
        query: str,
        retrieved_chunks: List[Dict[str, Any]],
        user_persona: str,
        *,
        user_evidence: Optional[str] = None,
        user_preferences: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Single-shot generation. Returns a cleaned & sanitized response string.

        Includes Model Armor pre/post sanitization if enabled.
        """
        try:
            # [1] Model Armor: Sanitize user prompt BEFORE LLM generation
            if self.model_armor:
                is_safe, message = await self.model_armor.sanitize_user_prompt(query)
                if not is_safe:
                    # BLOCKED - return generic error
                    return message

            context = self._build_context(retrieved_chunks or [])
            if not context and not (user_evidence and user_evidence.strip()):
                return ""

            prompt_template = self.persona_prompts.get(
                user_persona, self.persona_prompts["Developer"]
            )

            # Inject user preferences into prompt template
            prompt_template = self._apply_preferences_to_prompt(
                prompt_template, user_preferences or {}
            )

            if user_persona == "CVE Creator":
                prompt = prompt_template.replace("{user_query}", query).replace(
                    "{user_evidence}",
                    user_evidence or "No additional evidence provided.",
                )
            else:
                prompt = prompt_template.format(
                    user_query=query,
                    cwe_context=context,
                    user_evidence=(user_evidence or "No additional evidence provided."),
                )
            final = await self.provider.generate(prompt)
            final = self._clean_response(final)

            # [2] Model Armor: Sanitize model response AFTER LLM generation
            if self.model_armor and final and final.strip():
                is_safe, message = await self.model_armor.sanitize_model_response(final)
                if not is_safe:
                    # BLOCKED - return generic error
                    return message
                # Safe - return sanitized response
                return message

            return final
        except Exception as e:
            logger.error(f"Full generation (non-stream) failed: {e}")
            return ""

    def _build_context(self, chunks: Optional[List[Dict[str, Any]]]) -> str:
        """
        Build structured context from retrieved CWE chunks.

        Args:
            chunks: Retrieved chunks with metadata and scores

        Returns:
            Formatted context string
        """
        if not chunks:
            return "No relevant CWE information found."

        context_parts: List[str] = []

        # Group chunks by CWE ID safely
        by_cwe: Dict[str, List[Dict[str, Any]]] = {}
        for ch in chunks:
            mid = ch.get("metadata") or {}
            cid = mid.get("cwe_id", "CWE-UNKNOWN")
            by_cwe.setdefault(cid, []).append(ch)

        # Build per-CWE sections
        cwe_ids_in_context = list(by_cwe.keys())
        logger.info(
            f"[DEBUG_CONTEXT] Building context from {len(chunks)} chunks covering {len(cwe_ids_in_context)} CWEs: {cwe_ids_in_context}"
        )

        for cid, group in by_cwe.items():
            best = max(
                group, key=lambda g: float((g.get("scores") or {}).get("hybrid", 0.0))
            )
            name = (best.get("metadata") or {}).get("name", "")
            context_parts.append(f"\n--- {cid}: {name} ---")

            for ch in sorted(
                group,
                key=lambda g: (g.get("scores") or {}).get("hybrid", 0.0),
                reverse=True,
            ):
                md = ch.get("metadata") or {}
                section = md.get("section", "Content")
                doc = ch.get("document", "")
                snippet = doc[: config.max_document_snippet_length]
                suffix = "..." if len(doc) > config.max_document_snippet_length else ""
                context_parts.append(f"\n{section}:\n{snippet}{suffix}")
                # Cap sections per CWE when accumulating many parts
                if section != "Content" and len(context_parts) > 12:
                    break

        # Hard cap overall context size by characters to keep prompt size safe
        context_text = "\n".join(context_parts)
        final_context = context_text[: config.max_context_length]

        # Log context stats for debugging
        was_truncated = len(context_text) > config.max_context_length
        final_cwe_ids = []
        for line in final_context.split("\n"):
            if line.startswith("--- CWE-"):
                cwe_id = line.split(":")[0].replace("--- ", "").strip()
                final_cwe_ids.append(cwe_id)

        logger.info(
            f"[DEBUG_CONTEXT] Final context: {len(final_context)}/{config.max_context_length} chars, "
            f"truncated={was_truncated}, CWEs in final context: {final_cwe_ids}"
        )

        return final_context

    def _clean_response(self, response: str) -> str:
        """
        Clean and validate generated response.

        Args:
            response: Raw generated response

        Returns:
            Cleaned response string
        """
        # Remove only leading role labels; avoid nuking legitimate content
        cleaned = re.sub(
            r"^(?:Instructions?|System|Assistant)\s*:\s*",
            "",
            response.strip(),
            flags=re.IGNORECASE,
        )

        # Ensure response is not empty
        if not cleaned.strip():
            return "I apologize, but I couldn't generate a proper response. Please try rephrasing your question about CWE topics."

        return cleaned.strip()

    def _generate_fallback_response(self, query: str, user_persona: str) -> str:
        """Generate fallback response when no relevant CWE information is found."""
        persona_specific = {
            "PSIRT Member": "I couldn't find relevant CWE information for your security advisory inquiry.",
            "Developer": "I couldn't find relevant CWE information for your development question.",
            "Academic Researcher": "I couldn't find relevant CWE information for your research inquiry.",
            "Bug Bounty Hunter": "I couldn't find relevant CWE information for your security research question.",
            "Product Manager": "I couldn't find relevant CWE information for your strategic planning question.",
            "CWE Analyzer": "I couldn't find relevant CWE information for your CVE-to-CWE mapping analysis.",
            "CVE Creator": "I couldn't find relevant CWE information for your CVE description creation.",
        }

        specific_message = persona_specific.get(
            user_persona, "I couldn't find relevant CWE information for your question."
        )

        return f"{specific_message} Please try rephrasing your question or ask about specific Common Weakness Enumerations (CWEs). You can also ask about CWE categories, patterns, or request information about specific CWE IDs."

    def _generate_error_response(self, user_persona: str) -> str:
        """Generate safe error response without exposing system details."""
        return "I apologize, but I'm experiencing technical difficulties. Please try your question again in a moment. I'm here to help with Common Weakness Enumeration (CWE) topics."

    def _apply_preferences_to_prompt(
        self, prompt_template: str, user_preferences: Dict[str, Any]
    ) -> str:
        """
        Inject user preference instructions into the prompt template.

        Modifies the ## Instructions section of persona prompts to include/exclude:
        - Detail level (basic, standard, detailed)
        - Code examples
        - Mitigation guidance
        """
        # Extract preferences with defaults
        detail_level = user_preferences.get("response_detail_level", "standard")
        include_examples = user_preferences.get("include_examples", True)
        include_mitigations = user_preferences.get("include_mitigations", True)

        # Build dynamic instruction additions
        preference_instructions = []

        # Detail level instructions
        if detail_level == "basic":
            preference_instructions.append(
                "- Keep responses concise (2-3 paragraphs maximum)"
            )
            preference_instructions.append(
                "- Focus on key points and actionable takeaways"
            )
        elif detail_level == "detailed":
            preference_instructions.append(
                "- Provide comprehensive technical analysis and context"
            )
            preference_instructions.append(
                "- Include additional background and related concepts"
            )
        # standard = default behavior, no extra instructions

        # Examples preference
        if include_examples:
            preference_instructions.append(
                "- Include practical code examples and demonstrations where relevant"
            )
        else:
            preference_instructions.append(
                "- Omit code examples; focus on conceptual explanations"
            )

        # Mitigations preference
        if include_mitigations:
            preference_instructions.append(
                "- Provide remediation steps and mitigation guidance"
            )
        else:
            preference_instructions.append(
                "- Omit mitigation details; focus on problem description"
            )

        # Inject preference instructions after "## Instructions:" section
        if "## Instructions:" in prompt_template:
            # Find the instructions section and inject preferences
            instructions_marker = "## Instructions:"
            parts = prompt_template.split(instructions_marker, 1)
            if len(parts) == 2:
                # Add preferences right after the Instructions header
                preference_block = "\n".join(preference_instructions)
                modified_prompt = (
                    parts[0]
                    + instructions_marker
                    + "\n"
                    + preference_block
                    + "\n"
                    + parts[1]
                )
                return modified_prompt

        # Fallback: no modifications if Instructions section not found
        return prompt_template

    def _generate_contextual_fallback_answer(
        self,
        *,
        query: str,
        retrieved_chunks: List[Dict[str, Any]],
        user_persona: str,
        user_evidence: Optional[str] = None,
        max_cwes: int = 3,
    ) -> str:
        """
        Build a concise, deterministic answer from retrieved chunks when the LLM is unavailable.
        If a single CWE is dominant (or explicitly requested), provide a short explanation
        tailored to the persona; otherwise provide a brief multi-CWE summary.
        """
        if not retrieved_chunks:
            return self._generate_fallback_response(query, user_persona)

        # Group by CWE and pick the best chunk per CWE by hybrid score
        by_cwe: Dict[str, Dict[str, Any]] = {}
        for ch in retrieved_chunks:
            md = ch.get("metadata") or {}
            cid = md.get("cwe_id", "CWE-UNKNOWN")
            cur = by_cwe.get(cid)
            if not cur:
                by_cwe[cid] = ch
            else:
                prev_score = float((cur.get("scores") or {}).get("hybrid", 0.0))
                score = float((ch.get("scores") or {}).get("hybrid", 0.0))
                if score > prev_score:
                    by_cwe[cid] = ch

        # Order CWEs by the chosen best chunk score
        ranked = sorted(
            by_cwe.items(),
            key=lambda kv: float((kv[1].get("scores") or {}).get("hybrid", 0.0)),
            reverse=True,
        )[:max_cwes]

        # Detect explicit CWE mention in the query
        mention = None
        try:
            m = re.search(r"\bCWE[-\s]?(\d{1,5})\b", query, flags=re.IGNORECASE)
            if m:
                mention = f"CWE-{m.group(1)}"
        except Exception:
            pass

        dominant_id, dominant_chunk = ranked[0]
        if mention and any(cid == mention for cid, _ in ranked):
            # Prioritize explicitly requested CWE if present in results
            for cid, ch in ranked:
                if cid == mention:
                    dominant_id, dominant_chunk = cid, ch
                    break

        # If a single CWE stands out or was requested, produce a brief explanation
        try:
            # Gather top sections for the dominant CWE from available chunks
            group_chunks = [
                ch
                for ch in retrieved_chunks
                if (ch.get("metadata") or {}).get("cwe_id") == dominant_id
            ]
            # Prefer key sections (ordering handled by explicit picks below)
            section_map: Dict[str, str] = {}
            for ch in group_chunks:
                md = ch.get("metadata") or {}
                sec = md.get("section", "Content")
                doc = (ch.get("document") or "").strip()
                if not doc:
                    continue
                # Keep the best (longest) snippet per section
                prev = section_map.get(sec, "")
                candidate = doc if len(doc) > len(prev) else prev
                section_map[sec] = candidate

            md = dominant_chunk.get("metadata") or {}
            name = md.get("name", "")

            lines: List[str] = []
            header = f"{dominant_id}: {name} — {('Developer' if user_persona == 'Developer' else user_persona)} perspective"
            lines.append(header)
            lines.append("")

            # Compose short explanation (~2-4 lines) + mitigations if available
            def pick(sec_names: List[str]) -> Optional[str]:
                for s in sec_names:
                    if s in section_map:
                        return section_map[s]
                return None

            expl = pick(["Abstract", "Extended Description", "Description"])
            if expl:
                expl_snippet = expl[:500].replace("\n", " ") + (
                    "..." if len(expl) > 500 else ""
                )
                lines.append(expl_snippet)
                lines.append("")

            if user_persona in ("Developer", "PSIRT Member", "Product Manager"):
                mit = pick(["Mitigations", "Details"])
                if mit:
                    mit_snippet = mit[:400].replace("\n", " ") + (
                        "..." if len(mit) > 400 else ""
                    )
                    lines.append("Key Mitigations:")
                    lines.append(mit_snippet)

            # Add a small tail for guidance
            tail = {
                "Developer": "Emphasize input validation, output encoding, and safe framework APIs.",
                "PSIRT Member": "Use this to inform severity, impact, and advisory guidance.",
                "Product Manager": "Prioritize fixes based on exposure and business impact.",
            }.get(
                user_persona, "Consult official CWE documentation for further details."
            )
            lines.append("")
            lines.append(tail)
            return "\n".join(lines)
        except Exception:
            pass

        # Otherwise, provide a concise multi-CWE summary
        out_lines: List[str] = []
        out_lines.append("Here are the most relevant CWE findings based on your query:")
        for cid, ch in ranked:
            md = ch.get("metadata") or {}
            name = md.get("name", "")
            section = md.get("section", "Content")
            doc = (ch.get("document") or "").strip()
            snippet = doc[:280].replace("\n", " ") + ("..." if len(doc) > 280 else "")
            out_lines.append(f"- {cid}: {name}")
            if section:
                out_lines.append(f"  Section: {section}")
            if snippet:
                out_lines.append(f"  Snippet: {snippet}")

        persona_tail = {
            "Developer": "Focus on input validation, output encoding, and safe APIs.",
            "PSIRT Member": "Use this to inform impact assessment and advisories.",
            "Academic Researcher": "Consider taxonomy relationships across the listed CWEs.",
            "Bug Bounty Hunter": "Adapt tests to the attack surface suggested by these CWEs.",
            "Product Manager": "Prioritize mitigations according to risk and exposure.",
        }.get(user_persona, "Consult the referenced CWEs for details and mitigations.")
        out_lines.append("")
        out_lines.append(persona_tail)
        return "\n".join(out_lines)

    def _record_llm_fallback_marker(self) -> None:
        """Create a marker file indicating an LLM fallback occurred (for e2e diagnostics)."""
        try:
            marker_path = (
                os.getenv("LLM_FALLBACK_MARKER_PATH")
                or "test-results/llm_fallback_marker"
            )
            marker_dir = os.path.dirname(marker_path) or "."
            os.makedirs(marker_dir, exist_ok=True)
            with open(marker_path, "a", encoding="utf-8") as f:
                from time import time as _now

                f.write(f"fallback:{int(_now())}\n")
        except Exception:
            # Do not let diagnostics interfere with normal operation
            pass

    # Removed persona-specific formatting; rely on persona templates only
