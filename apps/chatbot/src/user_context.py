#!/usr/bin/env python3
"""
User Context and Persona Management - Story 2.1
Manages user personas, context, and session state for personalized CWE responses.
"""

import logging
from typing import Dict, List, Any, Optional, Literal
from enum import Enum
from dataclasses import dataclass, field
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class UserPersona(Enum):
    """Supported user personas with specific CWE information needs."""

    PSIRT_MEMBER = "PSIRT Member"
    DEVELOPER = "Developer"
    ACADEMIC_RESEARCHER = "Academic Researcher"
    BUG_BOUNTY_HUNTER = "Bug Bounty Hunter"
    PRODUCT_MANAGER = "Product Manager"
    CWE_ANALYZER = "CWE Analyzer"
    CVE_CREATOR = "CVE Creator"

    @classmethod
    def get_all_personas(cls) -> List[str]:
        """Get list of all persona values."""
        return [persona.value for persona in cls]

    @classmethod
    def is_valid_persona(cls, persona: str) -> bool:
        """Check if persona string is valid."""
        return persona in cls.get_all_personas()


@dataclass
class UserContext:
    """
    User context information for personalizing CWE responses.

    Contains persona information, preferences, and session state
    to enable role-based response adaptation.
    """

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    persona: str = UserPersona.DEVELOPER.value
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_active: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Persona-specific preferences
    section_boost: Optional[str] = None
    response_detail_level: str = "standard"  # basic, standard, detailed
    include_examples: bool = True
    include_mitigations: bool = True

    # Session state
    conversation_history: List[Dict[str, Any]] = field(default_factory=list)
    last_query: Optional[str] = None
    last_cwes_discussed: List[str] = field(default_factory=list)
    # User-provided evidence (short-lived; cleared after each answer)
    file_evidence: Optional[str] = None

    # OAuth authentication data
    oauth_provider: Optional[str] = None  # "google" or "github"
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    avatar_url: Optional[str] = None

    # Analytics and preferences
    query_count: int = 0
    preferred_cwe_categories: List[str] = field(default_factory=list)
    feedback_ratings: List[int] = field(default_factory=list)

    # Analyzer follow-up state and cached context
    last_recommendations: List[Dict[str, Any]] = field(default_factory=list)
    last_chunks: List[Dict[str, Any]] = field(default_factory=list)
    analyzer_mode: Optional[Literal["question", "compare"]] = None

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_active = datetime.now(timezone.utc)

    def set_oauth_data(self, provider: str, email: str, name: str, avatar_url: Optional[str] = None) -> None:
        """Set OAuth authentication data from provider."""
        self.oauth_provider = provider
        self.user_email = email
        self.user_name = name
        self.avatar_url = avatar_url
        logger.info(f"OAuth data set for user {email} via {provider}")

    @property
    def is_authenticated(self) -> bool:
        """Check if user is authenticated via OAuth."""
        return bool(self.oauth_provider and self.user_email)

    def add_conversation_entry(self, query: str, response: str, retrieved_cwes: List[str]) -> None:
        """Add conversation entry to history."""
        self.conversation_history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "query": query,
            "response_length": len(response),
            "retrieved_cwes": retrieved_cwes,
            "persona": self.persona
        })

        # Keep only last 10 conversations for memory efficiency
        if len(self.conversation_history) > 10:
            self.conversation_history = self.conversation_history[-10:]

        self.last_query = query
        self.last_cwes_discussed = retrieved_cwes
        self.query_count += 1
        self.update_activity()

    def get_persona_preferences(self) -> Dict[str, Any]:
        """Get persona-specific preferences and context."""
        base_preferences = {
            "persona": self.persona,
            "section_boost": self.section_boost,
            "response_detail_level": self.response_detail_level,
            "include_examples": self.include_examples,
            "include_mitigations": self.include_mitigations
        }

        # Add persona-specific defaults and preferences
        persona_configs = {
            UserPersona.PSIRT_MEMBER.value: {
                "section_boost": "Impact",
                "preferred_sections": ["Impact", "Likelihood", "Detection", "Mitigation"],
                "response_focus": "advisory_creation",
                "include_cvss": True,
                "include_exploitability": True
            },
            UserPersona.DEVELOPER.value: {
                "section_boost": "Mitigation",
                "preferred_sections": ["Mitigation", "Description", "Example"],
                "response_focus": "remediation",
                "include_code_examples": True,
                "include_prevention": True
            },
            UserPersona.ACADEMIC_RESEARCHER.value: {
                "section_boost": "Description",
                "preferred_sections": ["Description", "Relationships", "Taxonomy"],
                "response_focus": "comprehensive_analysis",
                "include_relationships": True,
                "include_taxonomy": True
            },
            UserPersona.BUG_BOUNTY_HUNTER.value: {
                "section_boost": "Example",
                "preferred_sections": ["Example", "Detection", "Exploitation"],
                "response_focus": "exploitation_patterns",
                "include_detection_methods": True,
                "include_real_world_examples": True
            },
            UserPersona.PRODUCT_MANAGER.value: {
                "section_boost": "Impact",
                "preferred_sections": ["Impact", "Likelihood", "Mitigation"],
                "response_focus": "business_impact",
                "include_trend_analysis": True,
                "include_prevention_strategies": True
            },
            UserPersona.CWE_ANALYZER.value: {
                "section_boost": "Description",
                "preferred_sections": ["Description", "Example", "Relationships"],
                "response_focus": "cve_mapping_analysis",
                "include_confidence_scores": True,
                "include_relationship_analysis": True,
                "include_vulnerability_chains": True
            },
            UserPersona.CVE_CREATOR.value: {
                "section_boost": "Description",
                "preferred_sections": ["Description", "Example", "Detection"],
                "response_focus": "cve_description_creation",
                "include_structured_format": True,
                "include_component_breakdown": True,
                "include_severity_assessment": True
            }
        }

        if self.persona in persona_configs:
            persona_config: Dict[str, Any] = persona_configs[self.persona]
            base_preferences.update(persona_config)

        return base_preferences

    def get_conversation_context(self) -> str:
        """Get formatted conversation context for RAG enhancement."""
        if not self.conversation_history:
            return ""

        # Get recent CWEs discussed for context
        recent_cwes = []
        for entry in self.conversation_history[-3:]:  # Last 3 conversations
            recent_cwes.extend(entry.get("retrieved_cwes", []))

        unique_recent_cwes = list(dict.fromkeys(recent_cwes))  # Preserve order, remove duplicates

        if unique_recent_cwes:
            return f"Recently discussed CWEs: {', '.join(unique_recent_cwes[:5])}"

        return ""

    def get_session_context_for_processing(self) -> Dict[str, Any]:
        """Minimal session hint for processors (persona + recent CWEs)."""
        return {
            "persona": self.persona,
            "last_cwes": self.last_cwes_discussed[-5:],
        }

    def set_evidence(self, text: Optional[str]) -> None:
        self.file_evidence = text

    def clear_evidence(self) -> None:
        self.file_evidence = None
