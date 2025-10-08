#!/usr/bin/env python3
"""
Explanation Builder - Story 3.2
Builds clear explanations for CWE mapping recommendations with snippet citations.
"""

import logging
import re
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

# Maximum snippet length to avoid overwhelming users
MAX_SNIPPET_LENGTH = 240
# Maximum number of snippets per explanation
MAX_SNIPPETS = 2


class ExplanationBuilder:
    """
    Builds explanations for CWE mapping recommendations.

    Features:
    - Extract relevant snippets from CWE chunks with section citations
    - Sanitize content to prevent security issues
    - Format explanations with bullet points and quotes
    - Limit snippet length and count to avoid information overload
    """

    def __init__(
        self,
        max_snippets: int = MAX_SNIPPETS,
        max_snippet_length: int = MAX_SNIPPET_LENGTH,
    ):
        """
        Initialize explanation builder with configuration.

        Args:
            max_snippets: Maximum number of snippets to include (default: 2)
            max_snippet_length: Maximum length per snippet in characters (default: 240)
        """
        self.max_snippets = max_snippets
        self.max_snippet_length = max_snippet_length

        logger.info(
            f"ExplanationBuilder initialized: max_snippets={max_snippets}, "
            f"max_snippet_length={max_snippet_length}"
        )

    def build(self, query: str, cwe_id: str, chunks: List[Dict]) -> Dict:
        """
        Build explanation for a CWE recommendation.

        Args:
            query: Original user query
            cwe_id: CWE identifier (e.g., "CWE-79")
            chunks: List of retrieved chunks with content and metadata

        Returns:
            Dictionary with explanation components:
            {
                "snippets": [{"text": str, "section": str}, ...],  # Up to max_snippets
                "bullets": [str, ...],                             # Key points
                "relevance": str,                                  # Why this CWE matches
                "section_coverage": Dict[str, int]                 # Section hit counts
            }
        """
        if not chunks:
            return {
                "snippets": [],
                "bullets": ["No detailed information available for this CWE."],
                "relevance": f"General match for query terms related to {cwe_id}",
                "section_coverage": {},
            }

        logger.debug(f"Building explanation for {cwe_id} with {len(chunks)} chunks")

        # Extract and rank snippets
        snippet_candidates = self._extract_snippet_candidates(query, chunks)
        selected_snippets = self._select_best_snippets(snippet_candidates)

        # Generate bullet points from chunk analysis
        bullets = self._generate_bullet_points(query, cwe_id, chunks)

        # Generate relevance explanation
        relevance = self._explain_relevance(query, cwe_id, chunks)

        # Count section coverage
        section_coverage = self._count_section_coverage(chunks)

        return {
            "snippets": selected_snippets,
            "bullets": bullets,
            "relevance": relevance,
            "section_coverage": section_coverage,
        }

    def _extract_snippet_candidates(self, query: str, chunks: List[Dict]) -> List[Dict]:
        """
        Extract potential snippets from chunks based on query relevance.

        Args:
            query: Original user query
            chunks: List of chunks to extract from

        Returns:
            List of snippet candidates with scores
        """
        candidates = []
        query_terms = set(query.lower().split())

        for chunk in chunks:
            # Standardized: primary text is under "document" in your pipeline
            content = chunk.get("document") or chunk.get("content", "")
            section = chunk.get("metadata", {}).get("section", "Unknown")
            score = chunk.get("score", chunk.get("hybrid_score", 0.0))

            if not content:
                continue

            # Clean and sanitize content
            clean_content = self._sanitize_content(content)

            # Calculate relevance to query
            content_terms = set(clean_content.lower().split())
            term_overlap = len(query_terms.intersection(content_terms))

            # Extract most relevant sentences
            sentences = self._extract_relevant_sentences(clean_content, query_terms)

            for sentence in sentences:
                candidates.append(
                    {
                        "text": sentence,
                        "section": section,
                        "score": score,
                        "term_overlap": term_overlap,
                        "length": len(sentence),
                    }
                )

        # Sort by relevance (score + term overlap)
        candidates.sort(
            key=lambda x: (x["score"] + x["term_overlap"] * 0.1), reverse=True
        )
        return candidates

    def _select_best_snippets(self, candidates: List[Dict]) -> List[Dict]:
        """
        Select the best snippets from candidates.

        Args:
            candidates: List of snippet candidates

        Returns:
            List of selected snippets with text and section
        """
        selected: List[Dict[str, str]] = []
        used_sections: Set[str] = set()

        for candidate in candidates:
            if len(selected) >= self.max_snippets:
                break

            # Prefer diversity in sections
            section = candidate["section"]
            text = candidate["text"]

            # Skip if text is too long
            if len(text) > self.max_snippet_length:
                text = text[: self.max_snippet_length - 3] + "..."

            # Skip very short or duplicate content
            if len(text) < 20 or any(text in s["text"] for s in selected):
                continue

            selected.append({"text": text, "section": section})

            used_sections.add(section)

        return selected

    def _generate_bullet_points(
        self, query: str, cwe_id: str, chunks: List[Dict]
    ) -> List[str]:
        """
        Generate bullet points explaining the CWE recommendation.

        Args:
            query: Original user query
            cwe_id: CWE identifier
            chunks: Retrieved chunks

        Returns:
            List of bullet point explanations
        """
        bullets = []

        # Get CWE name from chunks
        cwe_name = self._extract_cwe_name(chunks)
        if cwe_name:
            bullets.append(f"**{cwe_id}: {cwe_name}**")

        # Analyze query match reasons
        query_lower = query.lower()

        # Check for specific vulnerability patterns
        vulnerability_keywords = {
            "injection": "involves injection vulnerabilities",
            "xss": "relates to cross-site scripting issues",
            "buffer": "involves buffer management problems",
            "authentication": "concerns authentication mechanisms",
            "authorization": "involves authorization control issues",
            "crypto": "relates to cryptographic implementations",
            "input": "concerns input validation",
            "output": "involves output encoding issues",
        }

        for keyword, description in vulnerability_keywords.items():
            if keyword in query_lower:
                bullets.append(f"Query {description} covered by this CWE")
                break

        # Add section-based insights
        sections = set(chunk.get("metadata", {}).get("section", "") for chunk in chunks)
        if "Description" in sections:
            bullets.append("Core weakness definition matches query context")
        if "Common Consequences" in sections:
            bullets.append("Potential impacts align with vulnerability concerns")
        if "Potential Mitigations" in sections:
            bullets.append("Mitigation strategies available for this weakness")

        # Ensure minimum bullets
        if len(bullets) < 2:
            bullets.append("Semantic similarity indicates relevant weakness category")
            bullets.append("Retrieved from official MITRE CWE database")

        return bullets[:4]  # Limit to 4 bullets for readability

    def _explain_relevance(self, query: str, cwe_id: str, chunks: List[Dict]) -> str:
        """
        Generate relevance explanation for the CWE recommendation.

        Args:
            query: Original user query
            cwe_id: CWE identifier
            chunks: Retrieved chunks

        Returns:
            Relevance explanation string
        """
        # Analyze match strength
        chunk_count = len(chunks)
        avg_score = (
            sum(chunk.get("score", chunk.get("hybrid_score", 0.0)) for chunk in chunks)
            / chunk_count
            if chunks
            else 0
        )

        if avg_score >= 0.8:
            strength = "strong"
        elif avg_score >= 0.6:
            strength = "moderate"
        else:
            strength = "general"

        sections = set(chunk.get("metadata", {}).get("section", "") for chunk in chunks)
        section_coverage = len(sections)

        return (
            f"This CWE shows {strength} semantic similarity to your query "
            f"with {chunk_count} matching chunks across {section_coverage} different sections "
            f"of the weakness description."
        )

    def _count_section_coverage(self, chunks: List[Dict]) -> Dict[str, int]:
        """
        Count how many chunks came from each section.

        Args:
            chunks: List of chunks with metadata

        Returns:
            Dictionary mapping section names to hit counts
        """
        coverage: Dict[str, int] = {}
        for chunk in chunks:
            section = chunk.get("metadata", {}).get("section", "Unknown")
            coverage[section] = coverage.get(section, 0) + 1
        return coverage

    def _extract_cwe_name(self, chunks: List[Dict]) -> str:
        """
        Extract CWE name from chunks.

        Args:
            chunks: List of chunks

        Returns:
            CWE name if found, empty string otherwise
        """
        for chunk in chunks:
            cwe_name = chunk.get("metadata", {}).get("name") or chunk.get(
                "metadata", {}
            ).get("cwe_name")
            if cwe_name:
                return str(cwe_name)

        # Try to extract from content
        for chunk in chunks:
            content = chunk.get("content", "")
            # Look for pattern like "CWE-79: Cross-site Scripting"
            match = re.search(r"CWE-\d+:\s*(.+?)(?:\n|\.|$)", content)
            if match:
                return str(match.group(1)).strip()

        return ""

    def _extract_relevant_sentences(self, content: str, query_terms: set) -> List[str]:
        """
        Extract sentences most relevant to the query.

        Args:
            content: Text content to extract from
            query_terms: Set of query terms

        Returns:
            List of relevant sentences
        """
        # Split into sentences
        sentences = re.split(r"[.!?]+", content)
        scored_sentences = []

        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) < 20:  # Skip very short sentences
                continue

            # Score sentence based on query term overlap
            sentence_terms = set(sentence.lower().split())
            overlap = len(query_terms.intersection(sentence_terms))

            if overlap > 0:
                scored_sentences.append((sentence, overlap))

        # Sort by relevance and return top sentences
        scored_sentences.sort(key=lambda x: x[1], reverse=True)
        return [sent[0] for sent in scored_sentences[:3]]

    def _sanitize_content(self, content: str) -> str:
        """
        Sanitize content to prevent security issues.

        Args:
            content: Raw content to sanitize

        Returns:
            Sanitized content
        """
        if not content:
            return ""

        # Remove control characters except common whitespace
        content = re.sub(r"[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]", "", content)

        # Normalize whitespace
        content = re.sub(r"\s+", " ", content)

        # Remove potential markdown injection
        content = content.replace(
            "```", "ʼʼʼ"
        )  # Replace backticks with similar characters

        # Strip leading/trailing whitespace
        content = content.strip()

        return content
