#!/usr/bin/env python3
"""
User Context and Persona Management - Story 2.1
Manages user personas, context, and session state for personalized CWE responses.
"""

import logging
from typing import Dict, List, Any, Optional
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

    # Analytics and preferences
    query_count: int = 0
    preferred_cwe_categories: List[str] = field(default_factory=list)
    feedback_ratings: List[int] = field(default_factory=list)

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_active = datetime.now(timezone.utc)

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


class UserContextManager:
    """
    Manages user contexts and session state for the CWE chatbot.

    Provides session management, persona tracking, and context persistence
    for personalized user experiences.
    """

    def __init__(self) -> None:
        """Initialize context manager."""
        self.active_sessions: Dict[str, UserContext] = {}
        self.session_timeout_minutes = 30
        logger.info("UserContextManager initialized")

    def create_session(self, session_id: str = None, persona: str = UserPersona.DEVELOPER.value) -> UserContext:
        """
        Create new user session with specified persona.

        Args:
            session_id: Explicit session ID (uses Chainlit session ID)
            persona: User persona for role-based responses

        Returns:
            New UserContext instance
        """
        if not UserPersona.is_valid_persona(persona):
            logger.warning(f"Invalid persona '{persona}', defaulting to Developer")
            persona = UserPersona.DEVELOPER.value

        # Create context with explicit session_id if provided
        if session_id:
            context = UserContext(persona=persona)
            context.session_id = session_id  # Override the auto-generated UUID
        else:
            context = UserContext(persona=persona)

        # Set persona-specific defaults
        persona_defaults = self._get_persona_defaults(persona)
        for key, value in persona_defaults.items():
            if hasattr(context, key):
                setattr(context, key, value)

        self.active_sessions[context.session_id] = context
        logger.info(f"Created session {context.session_id} for persona: {persona}")

        return context

    def get_session(self, session_id: str) -> Optional[UserContext]:
        """
        Get existing session by ID.

        Args:
            session_id: Session identifier

        Returns:
            UserContext if found, None otherwise
        """
        context = self.active_sessions.get(session_id)
        if context:
            context.update_activity()

        return context

    def update_persona(self, session_id: str, new_persona: str) -> bool:
        """
        Update session persona.

        Args:
            session_id: Session identifier
            new_persona: New persona to set

        Returns:
            True if updated successfully, False otherwise
        """
        if not UserPersona.is_valid_persona(new_persona):
            logger.error(f"Invalid persona: {new_persona}")
            return False

        context = self.get_session(session_id)
        if not context:
            logger.error(f"Session not found: {session_id}")
            return False

        old_persona = context.persona
        context.persona = new_persona

        # Update persona-specific defaults
        persona_defaults = self._get_persona_defaults(new_persona)
        for key, value in persona_defaults.items():
            if hasattr(context, key):
                setattr(context, key, value)

        context.update_activity()
        logger.info(f"Updated session {session_id} persona: {old_persona} -> {new_persona}")

        return True

    def record_interaction(
        self,
        session_id: str,
        query: str,
        response: str,
        retrieved_cwes: List[str],
        feedback_rating: Optional[int] = None
    ) -> bool:
        """
        Record user interaction for analytics and context.

        Args:
            session_id: Session identifier
            query: User query
            response: System response
            retrieved_cwes: CWEs retrieved for response
            feedback_rating: Optional user feedback rating (1-5)

        Returns:
            True if recorded successfully, False otherwise
        """
        context = self.get_session(session_id)
        if not context:
            logger.error(f"Session not found: {session_id}")
            return False

        context.add_conversation_entry(query, response, retrieved_cwes)

        if feedback_rating is not None and 1 <= feedback_rating <= 5:
            context.feedback_ratings.append(feedback_rating)
            # Keep only last 20 ratings
            if len(context.feedback_ratings) > 20:
                context.feedback_ratings = context.feedback_ratings[-20:]

        logger.debug(f"Recorded interaction for session {session_id}")
        return True

    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions based on timeout.

        Returns:
            Number of sessions cleaned up
        """
        current_time = datetime.now(timezone.utc)
        expired_sessions = []

        for session_id, context in self.active_sessions.items():
            time_diff = current_time - context.last_active
            if time_diff.total_seconds() > (self.session_timeout_minutes * 60):
                expired_sessions.append(session_id)

        for session_id in expired_sessions:
            del self.active_sessions[session_id]

        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")

        return len(expired_sessions)

    def get_session_analytics(self, session_id: str) -> Dict[str, Any]:
        """
        Get analytics data for a session.

        Args:
            session_id: Session identifier

        Returns:
            Analytics data dictionary
        """
        context = self.get_session(session_id)
        if not context:
            return {}

        avg_rating = (
            sum(context.feedback_ratings) / len(context.feedback_ratings)
            if context.feedback_ratings else None
        )

        return {
            "session_id": session_id,
            "persona": context.persona,
            "query_count": context.query_count,
            "conversation_entries": len(context.conversation_history),
            "average_feedback_rating": avg_rating,
            "session_duration_minutes": (
                (context.last_active - context.created_at).total_seconds() / 60
            ),
            "unique_cwes_discussed": len(set(context.last_cwes_discussed)),
            "last_query": context.last_query
        }

    def _get_persona_defaults(self, persona: str) -> Dict[str, Any]:
        """Get default settings for a persona."""
        defaults = {
            UserPersona.PSIRT_MEMBER.value: {
                "section_boost": "Impact",
                "response_detail_level": "detailed",
                "include_examples": True,
                "include_mitigations": True
            },
            UserPersona.DEVELOPER.value: {
                "section_boost": "Mitigation",
                "response_detail_level": "standard",
                "include_examples": True,
                "include_mitigations": True
            },
            UserPersona.ACADEMIC_RESEARCHER.value: {
                "section_boost": "Description",
                "response_detail_level": "detailed",
                "include_examples": True,
                "include_mitigations": False
            },
            UserPersona.BUG_BOUNTY_HUNTER.value: {
                "section_boost": "Example",
                "response_detail_level": "standard",
                "include_examples": True,
                "include_mitigations": False
            },
            UserPersona.PRODUCT_MANAGER.value: {
                "section_boost": "Impact",
                "response_detail_level": "standard",
                "include_examples": False,
                "include_mitigations": True
            },
            UserPersona.CWE_ANALYZER.value: {
                "section_boost": "Description",
                "response_detail_level": "detailed",
                "include_examples": True,
                "include_mitigations": False
            },
            UserPersona.CVE_CREATOR.value: {
                "section_boost": "Description",
                "response_detail_level": "standard",
                "include_examples": True,
                "include_mitigations": False
            }
        }

        return defaults.get(persona, defaults[UserPersona.DEVELOPER.value])

    def get_active_session_count(self) -> int:
        """Get number of currently active sessions."""
        return len(self.active_sessions)

    def get_persona_distribution(self) -> Dict[str, int]:
        """Get distribution of active sessions by persona."""
        distribution: Dict[str, int] = {}
        for context in self.active_sessions.values():
            persona = context.persona
            distribution[persona] = distribution.get(persona, 0) + 1

        return distribution
