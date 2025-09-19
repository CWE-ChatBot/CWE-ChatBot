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

def entry_to_sections(entry: "CWEEntry") -> List[SectionDict]:
    """Converts a CWEEntry into a list of dictionaries for chunking."""
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
        sections.append({
            "section": "Extended", "section_rank": rank,
            "text": entry.ExtendedDescription
        })
        rank += 1

    # 4. Mitigations
    if entry.PotentialMitigations:
        mitigation_texts = [
            f"- Phase: {m.Phase}\n  Strategy: {m.Description}" 
            for m in entry.PotentialMitigations
        ]
        sections.append({
            "section": "Mitigations", "section_rank": rank,
            "text": "Mitigation Strategies:\n" + "\n".join(mitigation_texts)
        })
        rank += 1
        
    # 5. Examples
    if entry.ObservedExamples:
        example_texts = [f"- {ex.Reference}: {ex.Description}" for ex in entry.ObservedExamples]
        sections.append({
            "section": "Examples", "section_rank": rank,
            "text": "Real-World Examples (CVEs):\n" + "\n".join(example_texts)
        })
        rank += 1
        
    # 6. Related Weaknesses
    if entry.RelatedWeaknesses:
        weakness_texts = [f"- {w.Nature} of CWE-{w.CweID}" for w in entry.RelatedWeaknesses]
        sections.append({
            "section": "Related", "section_rank": rank,
            "text": "Related Weaknesses:\n" + "\n".join(weakness_texts)
        })
        rank += 1

    # 7. Alternate Terms
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
    "MappingNote",
    "Note",
    "CWEEntry",
    "entry_to_sections",   # make discoverable to Pylance
]