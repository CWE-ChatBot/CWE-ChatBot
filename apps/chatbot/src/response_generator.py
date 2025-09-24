#!/usr/bin/env python3
"""
RAG Response Generator - Story 2.1
Generates context-aware responses using retrieved CWE content and persona-specific prompting.
"""

import logging
from typing import Dict, List, Any, Optional, AsyncGenerator
import os
import re
import sys
from pathlib import Path
from .llm_provider import get_llm_provider

from .app_config_extended import config

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

    def __init__(self, gemini_api_key: str, model_name: str = "gemini-1.5-flash"):
        """
        Initialize response generator with Gemini model.

        Args:
            gemini_api_key: Gemini API key
            model_name: Gemini model to use for generation
        """
        try:
            # Allow offline mode (explicit opt-in)
            self.offline = os.getenv("DISABLE_AI") == "1" or os.getenv("GEMINI_OFFLINE") == "1"

            # Configure generation for factual, security-focused responses
            self.generation_config = {
                "temperature": 0.1,  # Low temperature for factual responses
                "max_output_tokens": config.max_output_tokens,
                "top_p": 0.9,
                "top_k": 40,
            }
            # Permissive safety settings for security content (explicitly logged)
            self.safety_settings = {
                "HARASSMENT": "BLOCK_NONE",
                "HATE_SPEECH": "BLOCK_NONE",
                "SEXUAL": "BLOCK_NONE",
                "DANGEROUS_CONTENT": "BLOCK_NONE",
            }

            # Load persona-specific prompt templates
            self.persona_prompts = self._load_persona_prompts()

            mode = "offline" if self.offline else model_name
            # Initialize provider adapter
            provider_name = os.getenv("PROVIDER") or "google"
            self.provider = get_llm_provider(
                provider=provider_name,
                api_key=gemini_api_key,
                model_name=model_name,
                generation_config=self.generation_config,
                safety_settings=getattr(self, "safety_settings", None),
                offline=self.offline,
                persona=None,
            )

            logger.info(f"ResponseGenerator initialized with {mode}")

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

CWE Context:
{cwe_context}

User-Provided Evidence:
{user_evidence}

Instructions:
- Map to CWEs with confidence and rationale.
Response:""",
        )
        load_prompt(
            "CVE Creator",
            """You create structured CVE descriptions from provided info.
User Query: {user_query}

User-Provided Evidence:
{user_evidence}

Instructions:
- Use the standardized CVE format; note missing info.
- Format key segments as bold (e.g., **Impact**, **Product**, **Vendor**, **Version**, **Affected Platform**, **Attacker**, **Action**, **Vector**); do not use square brackets.
Response:""",
        )
        return mapping

    async def generate_response_streaming(
        self,
        query: str,
        retrieved_chunks: List[Dict[str, Any]],
        user_persona: str,
        *,
        user_evidence: Optional[str] = None,
    ) -> Any:
        """
        Async generator yielding response tokens for streaming.
        """
        try:
            logger.info(f"Generating streaming response for persona: {user_persona}")

            context = self._build_context(retrieved_chunks or [])
            if not context and not (user_evidence and user_evidence.strip()):
                yield self._generate_fallback_response(query, user_persona)
                return

            prompt_template = self.persona_prompts.get(user_persona, self.persona_prompts["Developer"])
            prompt = prompt_template.format(
                user_query=query,
                cwe_context=context,
                user_evidence=(user_evidence or "No additional evidence provided."),
            )

            async for chunk_text in self.provider.generate_stream(prompt):
                cleaned_chunk = self._clean_response_chunk(chunk_text)
                if cleaned_chunk:
                    yield cleaned_chunk

        except Exception as e:
            logger.error(f"Streaming response generation failed: {e}")
            yield self._generate_error_response(user_persona)

    # removed non-streaming generate_response (streaming-only)

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
            mid = (ch.get("metadata") or {})
            cid = mid.get("cwe_id", "CWE-UNKNOWN")
            by_cwe.setdefault(cid, []).append(ch)

        # Build per-CWE sections
        for cid, group in by_cwe.items():
            best = max(group, key=lambda g: float((g.get("scores") or {}).get("hybrid", 0.0)))
            name = (best.get("metadata") or {}).get("name", "")
            context_parts.append(f"\n--- {cid}: {name} ---")

            for ch in sorted(group, key=lambda g: (g.get("scores") or {}).get("hybrid", 0.0), reverse=True):
                md = (ch.get("metadata") or {})
                section = md.get("section", "Content")
                doc = ch.get("document", "")
                snippet = doc[:config.max_document_snippet_length]
                suffix = "..." if len(doc) > config.max_document_snippet_length else ""
                context_parts.append(f"\n{section}:\n{snippet}{suffix}")
                # Cap sections per CWE when accumulating many parts
                if section != "Content" and len(context_parts) > 12:
                    break

        # Hard cap overall context size by characters to keep prompt size safe
        context_text = "\n".join(context_parts)
        return context_text[:config.max_context_length]

    def _clean_response_chunk(self, chunk: str) -> str:
        """
        Clean individual streaming chunk.

        Args:
            chunk: Raw chunk text

        Returns:
            Cleaned chunk string
        """
        # For streaming, just return the chunk as-is
        # Don't filter out role labels in chunks as they might be split across chunks
        return chunk

    def _clean_response(self, response: str) -> str:
        """
        Clean and validate generated response.

        Args:
            response: Raw generated response

        Returns:
            Cleaned response string
        """
        # Remove only leading role labels; avoid nuking legitimate content
        cleaned = re.sub(r'^(?:Instructions?|System|Assistant)\s*:\s*', '', response.strip(), flags=re.IGNORECASE)

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
            "CVE Creator": "I couldn't find relevant CWE information for your CVE description creation."
        }

        specific_message = persona_specific.get(user_persona, "I couldn't find relevant CWE information for your question.")

        return f"{specific_message} Please try rephrasing your question or ask about specific Common Weakness Enumerations (CWEs). You can also ask about CWE categories, patterns, or request information about specific CWE IDs."

    def _generate_error_response(self, user_persona: str) -> str:
        """Generate safe error response without exposing system details."""
        return "I apologize, but I'm experiencing technical difficulties. Please try your question again in a moment. I'm here to help with Common Weakness Enumeration (CWE) topics."

    def _format_cve_creator(self, text: str) -> str:
        """
        Legacy helper retained for compatibility with tests.
        Replace [segments] with **bold** unless part of a markdown link.
        """
        try:
            return re.sub(r"\[([^\[\]]+)\](?!\()", r"**\1**", text)
        except Exception:
            return text

    # Removed persona-specific formatting; rely on persona templates only
