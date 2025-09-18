# apps/cwe_ingestion/models.py
"""
Pydantic models for CWE data structures.
Based on the comprehensive CWE XML schema.
"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AlternateTerm(BaseModel):
    """Represents alternative terminology."""
    Term: str = Field(..., description="The alternate term")
    Description: Optional[str] = Field(None, description="Description of the term")

class ObservedExample(BaseModel):
    """Represents a real-world example (e.g., a CVE)."""
    Reference: str = Field(..., description="Reference ID, often a CVE")
    Description: str = Field(..., description="Description of the example")
    Link: Optional[str] = Field(None, description="Link for more information")

class RelatedWeakness(BaseModel):
    """Represents a relationship to another CWE."""
    Nature: str = Field(..., description="Nature of the relationship (e.g., ChildOf)")
    CweID: str = Field(..., description="ID of the related CWE")
    ViewID: str = Field(..., description="View ID for context")
    Ordinal: Optional[str] = Field(None, description="Ordinal value, if applicable")

class Mitigation(BaseModel):
    """Represents a potential mitigation strategy."""
    Phase: str = Field(
        ..., description="The phase in which this mitigation can be applied"
    )
    Strategy: str = Field(
        ..., description="The overall mitigation strategy"
    )
    Description: str = Field(..., description="Detailed description of the mitigation")

class MappingNote(BaseModel):
    """Represents mapping usage notes for a CWE."""
    Usage: str = Field(..., description="Whether this CWE is allowed for mapping")
    Rationale: Optional[str] = Field(None, description="Reasoning for the usage status")
    Comments: Optional[str] = Field(None, description="Additional comments")

class Note(BaseModel):
    """Represents a general note."""
    Type: str = Field(
        ..., description="Type of the note (e.g., Maintenance, Research Gap)"
    )
    Text: str = Field(..., description="Content of the note")

class CWEEntry(BaseModel):
    """Represents a complete CWE entry with methods for data transformation."""
    ID: str = Field(..., description="CWE identifier (e.g., '79')")
    Name: str = Field(..., description="Name of the weakness")
    Abstraction: str = Field(..., description="Abstraction level (e.g., 'Class')")
    Status: str = Field(..., description="Current status (e.g., 'Incomplete')")
    Description: str = Field(..., description="Main description of the weakness")
    ExtendedDescription: Optional[str] = Field(None, description="Extended details")

    AlternateTerms: Optional[List[AlternateTerm]] = Field(
        None, description="Alternative terms"
    )
    ObservedExamples: Optional[List[ObservedExample]] = Field(
        None, description="Observed real-world examples"
    )
    RelatedWeaknesses: Optional[List[RelatedWeakness]] = Field(
        None, description="Related CWEs"
    )
    PotentialMitigations: Optional[List[Mitigation]] = Field(
        None, description="Potential mitigations"
    )
    MappingNotes: Optional[MappingNote] = Field(
        None, description="Notes on mapping usage"
    )
    Notes: Optional[List[Note]] = Field(None, description="Additional general notes")

    def to_searchable_text(self) -> str:
        """Convert CWE entry into unified, human-readable text for searching."""
        sections = []

        # Core Information
        sections.append(f"CWE-{self.ID}: {self.Name}")
        sections.append(f"Type: {self.Abstraction} | Status: {self.Status}")

        # Primary Content
        sections.append("## Description\n" + self.Description)
        if self.ExtendedDescription:
            sections.append("## Extended Details\n" + self.ExtendedDescription)

        # Mitigations
        if self.PotentialMitigations:
            mitigation_texts = [
                f"- **{m.Phase} ({m.Strategy})**: {m.Description}"
                for m in self.PotentialMitigations
            ]
            sections.append(
                "## Potential Mitigations\n" + "\n".join(mitigation_texts)
            )

        # Related Weaknesses
        if self.RelatedWeaknesses:
            weakness_texts = [
                f"- CWE-{w.CweID} ({w.Nature})" for w in self.RelatedWeaknesses
            ]
            sections.append("## Related Weaknesses\n" + "\n".join(weakness_texts))

        # Examples
        if self.ObservedExamples:
            example_texts = [
                f"- {ex.Reference}: {ex.Description}" for ex in self.ObservedExamples
            ]
            sections.append("## Real-World Examples\n" + "\n".join(example_texts))

        # Alternate Terms
        if self.AlternateTerms:
            term_texts = [
                f"- {term.Term}"
                + (f" - {term.Description}" if term.Description else "")
                for term in self.AlternateTerms
            ]
            sections.append("## Alternative Terms\n" + "\n".join(term_texts))

        return "\n\n".join(sections)

    def to_embedding_data(self) -> Dict[str, Any]:
        """Generates a structured dictionary of the CWE data for metadata storage."""
        return {
            'id': f"CWE-{self.ID}",
            'name': self.Name,
            'abstraction': self.Abstraction,
            'status': self.Status,
            'description': self.Description,
            'extended_description': self.ExtendedDescription,
            'metadata': self.model_dump(exclude={
                'ID', 'Name', 'Abstraction', 'Status', 'Description',
                'ExtendedDescription'
            })
        }
