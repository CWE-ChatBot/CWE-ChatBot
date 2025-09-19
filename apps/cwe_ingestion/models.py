# apps/cwe_ingestion/models.py
"""Pydantic models for CWE data structures based on the comprehensive CWE XML schema."""
from typing import Any, Dict, List, Optional, TypedDict

from pydantic import BaseModel, Field

class AlternateTerm(BaseModel):
    Term: str
    Description: Optional[str] = None

class ObservedExample(BaseModel):
    Reference: str
    Description: str
    Link: Optional[str] = None

class RelatedWeakness(BaseModel):
    Nature: str
    CweID: str
    ViewID: str
    Ordinal: Optional[str] = None

class Mitigation(BaseModel):
    Phase: Optional[str] = None  # Some CWE entries have None phase values
    Strategy: Optional[str] = None  # Some CWE entries have None strategy
    Description: str

class Consequence(BaseModel):
    Scope: Optional[str] = None
    Impact: Optional[str] = None
    Note: Optional[str] = None

class DetectionMethod(BaseModel):
    Method: Optional[str] = None
    Description: Optional[str] = None
    Effectiveness: Optional[str] = None

class ModeOfIntroduction(BaseModel):
    Phase: Optional[str] = None
    Description: Optional[str] = None
    Note: Optional[str] = None

class CapecReference(BaseModel):
    CAPECID: Optional[str] = None
    Name: Optional[str] = None

class MappingNote(BaseModel):
    Usage: str
    Rationale: Optional[str] = None
    Comments: Optional[str] = None

class Note(BaseModel):
    Type: str
    Text: str

class SectionDict(TypedDict):
    section: str
    section_rank: int
    text: str

def _split_text_into_chunks(text: str, target_tokens: int = 500, max_tokens: int = 700, overlap: int = 50) -> List[str]:
    """
    Lightweight, tokenizer-free sentence/word packer for adaptive chunking.
    Counts tokens by words; keeps ~target_tokens per chunk with small overlap.
    """
    if not text or len(text) <= 2000:  # ~ quick escape for short text
        return [text] if text else []
    # Normalize newlines and split by sentences-ish boundaries
    import re
    sentences = re.split(r'(?<=[.!?])\s+|\n{2,}', text.strip())
    chunks: List[str] = []
    buf: List[str] = []
    count = 0
    def words(s: str) -> int:
        return max(1, len(s.split()))
    for s in sentences:
        w = words(s)
        if count + w > max_tokens and buf:
            chunk = " ".join(buf).strip()
            chunks.append(chunk)
            # build overlap from tail
            if overlap > 0:
                tail_words = " ".join(chunk.split()[-overlap:])
                buf = [tail_words]
                count = words(tail_words)
            else:
                buf, count = [], 0
        buf.append(s)
        count += w
        if count >= target_tokens:
            chunk = " ".join(buf).strip()
            chunks.append(chunk)
            buf, count = [], 0
    if buf:
        chunks.append(" ".join(buf).strip())
    # Deduplicate tiny last chunk into previous if it's too small
    if len(chunks) >= 2 and words(chunks[-1]) < max(50, int(0.15 * target_tokens)):
        last = chunks.pop()
        chunks[-1] = (chunks[-1] + " " + last).strip()
    return [c for c in chunks if c]

def _split_text_into_chunks_tiktoken(
    text: str,
    model_name: str = "cl100k_base",
    target_tokens: int = 400,
    max_tokens: int = 512,
    overlap: int = 50,
) -> List[str]:
    """Tokenizer-aware chunker using tiktoken if available.

    Falls back to the regex/word-based chunker when tiktoken is unavailable
    or an error occurs.
    """
    if not text:
        return []

    try:
        import tiktoken  # type: ignore[reportMissingImports]

        try:
            encoding = tiktoken.get_encoding(model_name)
        except Exception:
            encoding = tiktoken.get_encoding("cl100k_base")

        tokens = encoding.encode(text)
        if len(tokens) <= max_tokens:
            return [text]

        chunks: List[str] = []
        step = max(1, target_tokens - overlap)
        for i in range(0, len(tokens), step):
            chunk_tokens = tokens[i : i + target_tokens]
            if not chunk_tokens:
                break
            chunk_text = encoding.decode(chunk_tokens).strip()
            if chunk_text:
                chunks.append(chunk_text)

        # Merge small trailing chunk into previous
        if len(chunks) > 1:
            last = chunks[-1]
            if len(encoding.encode(last)) < int(target_tokens * 0.2):
                chunks[-2] = (chunks[-2] + " " + last).strip()
                chunks.pop()

        return [c for c in chunks if c]

    except Exception:
        # Graceful fallback
        return _split_text_into_chunks(
            text, target_tokens=target_tokens, max_tokens=max_tokens, overlap=overlap
        )

def _split_text_chunks_adaptive(
    text: str,
    *,
    target_tokens: int,
    max_tokens: int,
    overlap: int,
    tokenizer_model: str = "cl100k_base",
) -> List[str]:
    """Try tokenizer-aware chunking; fallback to regex/word-based splitter."""
    return _split_text_into_chunks_tiktoken(
        text,
        model_name=tokenizer_model,
        target_tokens=target_tokens,
        max_tokens=max_tokens,
        overlap=overlap,
    )

def entry_to_sections(entry: "CWEEntry") -> List[SectionDict]:
    """Converts a CWEEntry into a list of dictionaries for chunking.
    Includes adaptive sub-chunking for long sections and additional CWE fields.
    """
    sections: List[SectionDict] = []
    rank = 0

    # 1. Title
    sections.append({
        "section": "Title", "section_rank": rank,
        "text": f"CWE-{entry.ID}: {entry.Name}"
    })
    rank += 1
    
    # 2. Abstract (Description)
    if entry.Description:
        sections.append({
            "section": "Abstract", "section_rank": rank,
            "text": entry.Description
        })
        rank += 1

    # 3. Extended Description
    if entry.ExtendedDescription:
        ext_chunks = _split_text_chunks_adaptive(
            entry.ExtendedDescription,
            target_tokens=500,
            max_tokens=750,
            overlap=50,
        )
        for ch in ext_chunks:
            sections.append({
                "section": "Extended", "section_rank": rank,
                "text": ch
            })
            rank += 1

    # 4. Mitigations
    if entry.PotentialMitigations:
        # Group by Phase to improve intent routing
        by_phase: Dict[str, List[Mitigation]] = {}
        for m in entry.PotentialMitigations:
            phase = (m.Phase or "General").strip()
            by_phase.setdefault(phase, []).append(m)
        for phase, items in by_phase.items():
            text = "Mitigation Strategies (" + phase + "):\n" + "\n".join(
                f"- {mi.Strategy or ''}: {mi.Description}".strip()
                for mi in items if (mi.Description or mi.Strategy)
            )
            for ch in _split_text_chunks_adaptive(
                text, target_tokens=450, max_tokens=700, overlap=40
            ):
                sections.append({
                    "section": "Mitigations", "section_rank": rank,
                    "text": ch
                })
                rank += 1
        
    # 5. Examples
    if entry.ObservedExamples:
        example_texts = [f"- {ex.Reference}: {ex.Description}" for ex in entry.ObservedExamples]
        examples_blob = "Real-World Examples (CVEs):\n" + "\n".join(example_texts)
        for ch in _split_text_chunks_adaptive(
            examples_blob, target_tokens=450, max_tokens=700, overlap=25
        ):
            sections.append({
                "section": "Examples", "section_rank": rank,
                "text": ch
            })
            rank += 1
        
    # 6. Prerequisites (from Notes/Prerequisites if available)
    prerequisites = getattr(entry, "Prerequisites", None)
    if prerequisites:
        prereq_lines = [f"- {p}" for p in prerequisites if p]
        if prereq_lines:
            sections.append({
                "section": "Prerequisites", "section_rank": rank,
                "text": "Prerequisites:\n" + "\n".join(prereq_lines)
            })
            rank += 1

    # 7. Modes of Introduction
    modes_of_introduction = getattr(entry, "ModesOfIntroduction", None)
    if modes_of_introduction:
        mode_lines = []
        for m in modes_of_introduction:
            line = f"- {m.Phase or 'Unspecified'}: {m.Description or ''}".strip()
            if m.Note:
                line += f" ({m.Note})"
            mode_lines.append(line)
        if mode_lines:
            sections.append({
                "section": "Modes", "section_rank": rank,
                "text": "Modes of Introduction:\n" + "\n".join(mode_lines)
            })
            rank += 1

    # 8. Common Consequences
    common_consequences = getattr(entry, "CommonConsequences", None)
    if common_consequences:
        cons_lines = []
        for c in common_consequences:
            parts = [c.Scope or "", c.Impact or ""]
            core = " → ".join([p for p in parts if p]).strip(" →")
            if c.Note:
                core += f" ({c.Note})"
            if core:
                cons_lines.append(f"- {core}")
        if cons_lines:
            sections.append({
                "section": "Common_Consequences", "section_rank": rank,
                "text": "Common Consequences:\n" + "\n".join(cons_lines)
            })
            rank += 1

    # 9. Detection Methods
    detection_methods = getattr(entry, "DetectionMethods", None)
    if detection_methods:
        det_lines = []
        for d in detection_methods:
            core = (d.Method or "Detection").strip()
            if d.Effectiveness:
                core += f" [{d.Effectiveness}]"
            if d.Description:
                core += f": {d.Description}"
            det_lines.append(f"- {core}")
        if det_lines:
            sections.append({
                "section": "Detection", "section_rank": rank,
                "text": "Detection Methods:\n" + "\n".join(det_lines)
            })
            rank += 1

    # 10–12. Related Weaknesses split into Parents/Children and SeeAlso/MappedTo
    if entry.RelatedWeaknesses:
        parents_children = []
        seealso_mapped = []
        for w in entry.RelatedWeaknesses:
            nature = (w.Nature or "").lower()
            line = f"- {w.Nature or 'Related'}: CWE-{w.CweID}"
            if "parent" in nature or "child" in nature:
                parents_children.append(line)
            else:
                seealso_mapped.append(line)
        if parents_children:
            sections.append({
                "section": "Parents_Children", "section_rank": rank,
                "text": "Parent/Child Relationships:\n" + "\n".join(parents_children)
            }); rank += 1
        if seealso_mapped:
            sections.append({
                "section": "SeeAlso_MappedTo", "section_rank": rank,
                "text": "See Also / Mapped To:\n" + "\n".join(seealso_mapped)
            }); rank += 1

    # 13. CAPEC (if available)
    related_attack_patterns = getattr(entry, "RelatedAttackPatterns", None)
    if related_attack_patterns:
        cap_lines = []
        for c in related_attack_patterns:
            if c.CAPECID or c.Name:
                cap_lines.append(f"- CAPEC-{c.CAPECID}: {c.Name}".strip(": "))
        if cap_lines:
            sections.append({
                "section": "CAPEC", "section_rank": rank,
                "text": "Related CAPEC Attack Patterns:\n" + "\n".join(cap_lines)
            })
            rank += 1

    # 14. Alternate Terms
    if entry.AlternateTerms:
        term_texts = [term.Term for term in entry.AlternateTerms if term.Term]
        if term_texts:
            sections.append({
                "section": "Aliases", "section_rank": rank,
                "text": "; ".join(sorted(set(term_texts)))
            })
            rank += 1

    return sections

class CWEEntry(BaseModel):
    """Represents a complete CWE entry with methods for data transformation."""
    ID: str
    Name: str
    Abstraction: str
    Status: str
    Description: str
    ExtendedDescription: Optional[str] = None
    AlternateTerms: Optional[List[AlternateTerm]] = None
    ObservedExamples: Optional[List[ObservedExample]] = None
    RelatedWeaknesses: Optional[List[RelatedWeakness]] = None
    PotentialMitigations: Optional[List[Mitigation]] = None
    MappingNotes: Optional[MappingNote] = None
    Notes: Optional[List[Note]] = None
    # Newly modeled fields (optional; populated by parser when present)
    CommonConsequences: Optional[List[Consequence]] = None
    DetectionMethods: Optional[List[DetectionMethod]] = None
    ModesOfIntroduction: Optional[List[ModeOfIntroduction]] = None
    Prerequisites: Optional[List[str]] = None
    RelatedAttackPatterns: Optional[List[CapecReference]] = None

    def to_searchable_text(self) -> str:
        """Converts the CWE entry into an optimized text block for high-quality embeddings."""
        sections = []
        
        # 1. Semantic Weighting: Repeat the most critical info (Name/Title)
        sections.append(f"## Title: CWE-{self.ID}: {self.Name}")
        sections.append(f"Weakness Name: {self.Name}")

        # 2. Structural Labels: Add clear headings for context
        sections.append(f"Abstraction Level: {self.Abstraction}")
        sections.append(f"CWE Status: {self.Status}")
        
        sections.append(f"## Abstract\n{self.Description}")
        
        if self.ExtendedDescription:
            sections.append(f"## Extended Description\n{self.ExtendedDescription}")
        
        if self.PotentialMitigations:
            mitigation_texts = [f"- Phase: {m.Phase}\n  Strategy: {m.Description}" for m in self.PotentialMitigations]
            sections.append("## Mitigation Strategies\n" + "\n".join(mitigation_texts))

        if self.RelatedWeaknesses:
            weakness_texts = [f"- {w.Nature} of CWE-{w.CweID}" for w in self.RelatedWeaknesses]
            sections.append("## Related Weaknesses\n" + "\n".join(weakness_texts))

        if self.ObservedExamples:
            example_texts = [f"- {ex.Reference}: {ex.Description}" for ex in self.ObservedExamples]
            sections.append("## Real-World Examples (CVEs)\n" + "\n".join(example_texts))
            
        if self.AlternateTerms:
            term_texts = [f"- {term.Term}" + (f": {term.Description}" if term.Description else "") for term in self.AlternateTerms]
            sections.append("## Alternative Terminology\n" + "\n".join(term_texts))

        text = "\n\n".join(sections)
        # Normalize whitespace for cleaner embeddings
        text = "\n".join(line.rstrip() for line in text.splitlines())
        return text

    def to_embedding_data(self) -> Dict[str, Any]:
        """Generates a structured dictionary of the CWE data for metadata storage."""
        return {
            'id': f"CWE-{self.ID}",
            'name': self.Name,
            'abstraction': self.Abstraction,
            'status': self.Status,
            'description': self.Description,
            'extended_description': self.ExtendedDescription,
            'metadata': self.model_dump(exclude={'ID', 'Name', 'Abstraction', 'Status', 'Description', 'ExtendedDescription'})
        }
        
        
__all__ = [
    "AlternateTerm",
    "ObservedExample",
    "RelatedWeakness",
    "Mitigation",
    "Consequence",
    "DetectionMethod",
    "ModeOfIntroduction",
    "CapecReference",
    "MappingNote",
    "Note",
    "CWEEntry",
    "entry_to_sections",
    "_split_text_into_chunks",
    "_split_text_into_chunks_tiktoken",
    "_split_text_chunks_adaptive",
]
