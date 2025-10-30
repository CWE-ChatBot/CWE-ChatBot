"""
Fallback response strategies for when LLM is unavailable.

Implements Strategy pattern to reduce cyclomatic complexity in ResponseGenerator.
"""

import re
from typing import Any, Dict, List, Optional, Protocol

from src.security.secure_logging import get_secure_logger

logger = get_secure_logger(__name__)


class FallbackStrategy(Protocol):
    """Protocol for fallback response strategies."""

    def supports(self, query: str, chunks: List[Dict[str, Any]]) -> bool:
        """Check if this strategy can handle the given query and chunks."""
        ...

    def respond(
        self, query: str, persona: str, chunks: List[Dict[str, Any]], max_cwes: int = 3
    ) -> str:
        """Generate fallback response for the given query."""
        ...


class ExplicitCWEStrategy:
    """
    Strategy for queries that explicitly mention a specific CWE.

    Example: "Tell me about CWE-79"
    """

    def supports(self, query: str, chunks: List[Dict[str, Any]]) -> bool:
        """Check if query mentions a CWE that's in our results."""
        if not chunks:
            return False

        # Extract CWE mention from query
        mention = self._extract_cwe_mention(query)
        if not mention:
            return False

        # Check if mentioned CWE is in results
        cwe_ids = {(ch.get("metadata") or {}).get("cwe_id", "") for ch in chunks}
        return mention in cwe_ids

    def respond(
        self, query: str, persona: str, chunks: List[Dict[str, Any]], max_cwes: int = 3
    ) -> str:
        """Generate response focused on the explicitly mentioned CWE."""
        mention = self._extract_cwe_mention(query)
        if not mention:
            return ""  # Should not reach here if supports() passed

        # Find chunks for the mentioned CWE
        target_chunks = [
            ch for ch in chunks if (ch.get("metadata") or {}).get("cwe_id") == mention
        ]

        if not target_chunks:
            return ""

        # Use the best scoring chunk
        best_chunk = max(
            target_chunks,
            key=lambda ch: float((ch.get("scores") or {}).get("hybrid", 0.0)),
        )

        return self._format_single_cwe_response(
            mention, best_chunk, persona, target_chunks
        )

    def _extract_cwe_mention(self, query: str) -> Optional[str]:
        """Extract CWE-### from query text."""
        try:
            m = re.search(r"\bCWE[-\s]?(\d{1,5})\b", query, flags=re.IGNORECASE)
            if m:
                return f"CWE-{m.group(1)}"
        except Exception as e:
            # Regex should not fail, but guard against unexpected issues
            logger.debug(f"Failed to extract CWE mention from query: {e}")
        return None

    def _format_single_cwe_response(
        self,
        cwe_id: str,
        chunk: Dict[str, Any],
        persona: str,
        all_chunks: List[Dict[str, Any]],
    ) -> str:
        """Format detailed response for a single CWE."""
        md = chunk.get("metadata") or {}
        name = md.get("name", "")

        lines: List[str] = []
        header = f"{cwe_id}: {name} — {persona} perspective"
        lines.append(header)
        lines.append("")

        # Gather sections from all chunks for this CWE
        section_map: Dict[str, str] = {}
        for ch in all_chunks:
            sec = (ch.get("metadata") or {}).get("section", "Content")
            doc = (ch.get("document") or "").strip()
            if doc:
                prev = section_map.get(sec, "")
                candidate = doc if len(doc) > len(prev) else prev
                section_map[sec] = candidate

        # Add description
        expl = self._pick_section(
            section_map, ["Abstract", "Extended Description", "Description"]
        )
        if expl:
            expl_snippet = expl[:500].replace("\n", " ")
            if len(expl) > 500:
                expl_snippet += "..."
            lines.append(expl_snippet)
            lines.append("")

        # Add mitigations for relevant personas
        if persona in ("Developer", "PSIRT Member", "Product Manager"):
            mit = self._pick_section(section_map, ["Mitigations", "Details"])
            if mit:
                mit_snippet = mit[:400].replace("\n", " ")
                if len(mit) > 400:
                    mit_snippet += "..."
                lines.append("Key Mitigations:")
                lines.append(mit_snippet)

        # Add persona-specific guidance
        tail = self._get_persona_tail(persona)
        lines.append("")
        lines.append(tail)

        return "\n".join(lines)

    def _pick_section(
        self, section_map: Dict[str, str], section_names: List[str]
    ) -> Optional[str]:
        """Pick first available section from list."""
        for s in section_names:
            if s in section_map:
                return section_map[s]
        return None

    def _get_persona_tail(self, persona: str) -> str:
        """Get persona-specific guidance tail."""
        tails = {
            "Developer": "Emphasize input validation, output encoding, and safe framework APIs.",
            "PSIRT Member": "Use this to inform severity, impact, and advisory guidance.",
            "Product Manager": "Prioritize fixes based on exposure and business impact.",
        }
        return tails.get(
            persona, "Consult official CWE documentation for further details."
        )


class DominantCWEStrategy:
    """
    Strategy for when a single CWE dominates the results.

    Used when one CWE has significantly higher scores than others.
    """

    def supports(self, query: str, chunks: List[Dict[str, Any]]) -> bool:
        """Check if results have a single dominant CWE."""
        if not chunks:
            return False

        # Group by CWE and count
        by_cwe: Dict[str, List[Dict[str, Any]]] = {}
        for ch in chunks:
            cid = (ch.get("metadata") or {}).get("cwe_id", "CWE-UNKNOWN")
            by_cwe.setdefault(cid, []).append(ch)

        # Single CWE case is dominant
        if len(by_cwe) == 1:
            return True

        # Check if one CWE has much higher score than others
        ranked = self._rank_cwes(by_cwe)
        if len(ranked) < 2:
            return False

        top_score = ranked[0][1]
        second_score = ranked[1][1]

        # Dominant if top score is 2x higher than second
        return top_score > (second_score * 2.0)

    def respond(
        self, query: str, persona: str, chunks: List[Dict[str, Any]], max_cwes: int = 3
    ) -> str:
        """Generate response for dominant CWE."""
        # Group by CWE
        by_cwe: Dict[str, List[Dict[str, Any]]] = {}
        for ch in chunks:
            cid = (ch.get("metadata") or {}).get("cwe_id", "CWE-UNKNOWN")
            by_cwe.setdefault(cid, []).append(ch)

        # Get dominant CWE
        ranked = self._rank_cwes(by_cwe)
        dominant_id, _ = ranked[0]
        dominant_chunks = by_cwe[dominant_id]

        # Use the best chunk for this CWE
        best_chunk = max(
            dominant_chunks,
            key=lambda ch: float((ch.get("scores") or {}).get("hybrid", 0.0)),
        )

        # Reuse single CWE formatting from ExplicitCWEStrategy
        explicit_strategy = ExplicitCWEStrategy()
        return explicit_strategy._format_single_cwe_response(
            dominant_id, best_chunk, persona, dominant_chunks
        )

    def _rank_cwes(
        self, by_cwe: Dict[str, List[Dict[str, Any]]]
    ) -> List[tuple[str, float]]:
        """Rank CWEs by their best chunk score."""
        ranked = []
        for cid, cwe_chunks in by_cwe.items():
            best_score = max(
                float((ch.get("scores") or {}).get("hybrid", 0.0)) for ch in cwe_chunks
            )
            ranked.append((cid, best_score))

        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked


class MultiCWEBriefStrategy:
    """
    Strategy for listing multiple CWEs with brief summaries.

    Used when results contain multiple relevant CWEs without clear dominance.
    """

    def supports(self, query: str, chunks: List[Dict[str, Any]]) -> bool:
        """Always supports as fallback - lists all CWEs."""
        return bool(chunks)

    def respond(
        self, query: str, persona: str, chunks: List[Dict[str, Any]], max_cwes: int = 3
    ) -> str:
        """Generate multi-CWE summary."""
        # Group by CWE and pick best chunk per CWE
        by_cwe: Dict[str, Dict[str, Any]] = {}
        for ch in chunks:
            md = ch.get("metadata") or {}
            cid = md.get("cwe_id", "CWE-UNKNOWN")

            if cid not in by_cwe:
                by_cwe[cid] = ch
            else:
                prev_score = float((by_cwe[cid].get("scores") or {}).get("hybrid", 0.0))
                score = float((ch.get("scores") or {}).get("hybrid", 0.0))
                if score > prev_score:
                    by_cwe[cid] = ch

        # Rank and limit
        ranked = sorted(
            by_cwe.items(),
            key=lambda kv: float((kv[1].get("scores") or {}).get("hybrid", 0.0)),
            reverse=True,
        )[:max_cwes]

        # Format output
        lines: List[str] = []
        lines.append("Here are the most relevant CWE findings based on your query:")

        for cid, ch in ranked:
            md = ch.get("metadata") or {}
            name = md.get("name", "")
            section = md.get("section", "Content")
            doc = (ch.get("document") or "").strip()

            snippet = doc[:280].replace("\n", " ")
            if len(doc) > 280:
                snippet += "..."

            lines.append(f"- {cid}: {name}")
            if section:
                lines.append(f"  Section: {section}")
            if snippet:
                lines.append(f"  Snippet: {snippet}")

        # Add persona-specific tail
        tail = self._get_persona_tail(persona)
        lines.append("")
        lines.append(tail)

        return "\n".join(lines)

    def _get_persona_tail(self, persona: str) -> str:
        """Get persona-specific guidance."""
        tails = {
            "Developer": "Focus on input validation, output encoding, and safe APIs.",
            "PSIRT Member": "Use this to inform impact assessment and advisories.",
            "Academic Researcher": "Consider taxonomy relationships across the listed CWEs.",
            "Bug Bounty Hunter": "Adapt tests to the attack surface suggested by these CWEs.",
            "Product Manager": "Prioritize mitigations according to risk and exposure.",
        }
        return tails.get(
            persona, "Consult the referenced CWEs for details and mitigations."
        )
