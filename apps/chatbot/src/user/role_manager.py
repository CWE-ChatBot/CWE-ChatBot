#!/usr/bin/env python3
"""
Role Management Module
Handles user role selection, validation, and session storage.
"""

import logging
from typing import Optional, Dict, Any
import chainlit as cl
from src.security.secure_logging import get_secure_logger
from src.user_context import UserPersona, UserContext

logger = get_secure_logger(__name__)


def _persona_description(persona: UserPersona) -> str:
    descriptions = {
        UserPersona.PSIRT_MEMBER: "Focus on impact assessment, advisory language, and risk evaluation",
        UserPersona.DEVELOPER: "Emphasis on code-level remediation, examples, and technical fixes",
        UserPersona.ACADEMIC_RESEARCHER: "Comprehensive analysis, relationships, and research-oriented information",
        UserPersona.BUG_BOUNTY_HUNTER: "Exploitation patterns, proof-of-concept examples, and reporting guidance",
        UserPersona.PRODUCT_MANAGER: "Trend analysis, prevention strategies, and business impact",
        UserPersona.CWE_ANALYZER: "CVE-to-CWE mapping analysis and confidence scoring",
        UserPersona.CVE_CREATOR: "Structured CVE description creation from vulnerability info",
    }
    return descriptions.get(persona, "General cybersecurity information")


class RoleManager:
    """Manages user role selection and validation with session storage."""
    
    ROLE_SESSION_KEY = "user_role"
    ROLE_SET_FLAG = "role_selection_completed"
    
    def __init__(self):
        """Initialize the role manager."""
        logger.debug("RoleManager initialized")

    def _get_or_create_user_context(self) -> UserContext:
        """
        Retrieve per-user context from Chainlit session or create it.
        This becomes the single source of truth for the persona.
        """
        ctx: Optional[UserContext] = cl.user_session.get("user_context")
        if not ctx:
            ctx = UserContext()
            cl.user_session["user_context"] = ctx
            logger.info("Created UserContext in cl.user_session")
        ctx.update_activity()
        return ctx
    
    def get_current_role(self) -> Optional[UserPersona]:
        """
        Get the current user's role from session.

        Returns:
            UserPersona or None if no role is set
        """
        try:
            # Prefer the persona on user_context (source of truth)
            ctx = self._get_or_create_user_context()
            persona_value = getattr(ctx, "persona", None)
            if persona_value:
                try:
                    return UserPersona(persona_value)
                except ValueError:
                    logger.warning("Invalid persona on user_context; clearing")
                    self._clear_corrupted_session_data()
                    return None
            # Fallback to legacy key for backward-compat
            stored_value = cl.user_session.get(self.ROLE_SESSION_KEY)
            if stored_value:
                try:
                    return UserPersona(stored_value)
                except ValueError as e:
                    logger.warning(f"Invalid legacy role value in session: {e}")
                    self._clear_corrupted_session_data()
                    return None
            return None
                
        except (ValueError, AttributeError) as e:
            logger.warning(f"Invalid role value in session: {e}")
            return None
    
    def set_user_role(self, role: UserPersona | str) -> bool:
        """
        Set the user's role in session storage.

        Args:
            role: UserPersona or display-name string to set

        Returns:
            True if successful, False otherwise
        """
        try:
            # Normalize and validate using UserPersona as source of truth
            role_value = role.value if isinstance(role, UserPersona) else role
            try:
                UserPersona(role_value)
            except ValueError:
                raise ValueError(f"Invalid role value: {role}")
            # Update user_context persona (single source of truth)
            ctx = self._get_or_create_user_context()
            ctx.persona = role_value
            ctx.update_activity()
            # Keep legacy flags for compatibility with any remaining callers
            cl.user_session[self.ROLE_SESSION_KEY] = role_value
            cl.user_session[self.ROLE_SET_FLAG] = True
            logger.info(f"User role set on user_context: {role_value}")
            return True
        except Exception as e:
            logger.error(f"Failed to set user role: {e}")
            return False
    
    def is_role_selected(self) -> bool:
        """
        Check if user has selected a role for this session.
        
        Returns:
            True if role is selected, False otherwise
        """
        ctx = cl.user_session.get("user_context")
        if ctx and getattr(ctx, "persona", None):
            return True
        return bool(cl.user_session.get(self.ROLE_SET_FLAG))
    
    def clear_role(self) -> bool:
        """
        Clear the user's role (for role changes).
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Reset persona on user_context (keep context object)
            ctx = cl.user_session.get("user_context")
            if ctx:
                ctx.persona = UserPersona.DEVELOPER.value
                ctx.update_activity()
            # Also clean legacy keys
            cl.user_session.pop(self.ROLE_SESSION_KEY, None)
            cl.user_session.pop(self.ROLE_SET_FLAG, None)
            logger.info("User role cleared (user_context + legacy keys)")
            return True
        except Exception as e:
            logger.error(f"Failed to clear user role: {e}")
            return False
    
    def get_role_actions(self) -> list:
        """
        Get Chainlit action buttons for role selection.
        
        Returns:
            List of cl.Action objects for role selection
        """
        actions = []
        
        for persona in UserPersona:
            actions.append(
                cl.Action(
                    name=f"select_role_{persona.name.lower()}",
                    value=persona.value,
                    label=persona.value,
                    description=_persona_description(persona),
                )
            )
        
        return actions
    
    def validate_role_integrity(self) -> bool:
        """
        Validate that the role stored in session hasn't been tampered with.
        This provides defense against session manipulation attacks.
        
        Returns:
            True if role is valid, False if compromised
        """
        try:
            ctx = cl.user_session.get("user_context")
            role_value = getattr(ctx, "persona", None) if ctx else None
            role_set_flag = cl.user_session.get(self.ROLE_SET_FLAG, False)

            # Validate role is legitimate (prefer user_context)
            if role_value:
                try:
                    UserPersona(role_value)
                except ValueError:
                    logger.warning("Role integrity check failed: invalid persona on user_context")
                    return False
                return True

            # Fall back to legacy keys if no persona on user_context
            legacy_value = cl.user_session.get(self.ROLE_SESSION_KEY)
            if legacy_value:
                try:
                    UserPersona(legacy_value)
                except ValueError:
                    logger.warning("Role integrity check failed: invalid legacy role value")
                    return False
                # Accept legacy even if flag missing (migration window)
                return True

            # No role at all
            return not role_set_flag
            
        except Exception as e:
            logger.error(f"Role integrity check failed with exception: {e}")
            return False
    
    def get_role_context(self) -> Dict[str, Any]:
        """
        Get role context information for prompt templating.
        
        Returns:
            Dictionary with role context data
        """
        current_role = self.get_current_role()
        
        if not current_role:
            return {"role": None, "role_name": "General User", "focus_areas": []}
        
        # Define focus areas for each role
        focus_areas = {
            UserPersona.PSIRT_MEMBER: [
                "Impact assessment and severity analysis",
                "Advisory language and communication",
                "Risk evaluation and business impact",
                "Incident response considerations"
            ],
            UserPersona.DEVELOPER: [
                "Code-level remediation steps",
                "Secure coding practices",
                "Technical implementation details",
                "Code examples and patterns"
            ],
            UserPersona.ACADEMIC_RESEARCHER: [
                "Comprehensive technical analysis",
                "CWE relationships and taxonomy",
                "Research methodologies",
                "Historical context and evolution"
            ],
            UserPersona.BUG_BOUNTY_HUNTER: [
                "Exploitation techniques and patterns",
                "Proof-of-concept development",
                "Vulnerability discovery methods",
                "Reporting and disclosure practices"
            ],
            UserPersona.PRODUCT_MANAGER: [
                "Business impact and cost analysis",
                "Prevention strategies and planning",
                "Trend analysis and metrics",
                "Resource allocation decisions"
            ]
        }
        
        return {
            "role": current_role.value,
            "role_name": current_role.value,
            "focus_areas": focus_areas.get(current_role, []),
            "description": _persona_description(current_role)
        }
    
    def _clear_corrupted_session_data(self) -> None:
        """
        Clear corrupted session data when validation fails.
        This provides defense against session tampering attacks.
        """
        try:
            cl.user_session.pop(self.ROLE_SESSION_KEY, None)
            cl.user_session.pop(self.ROLE_SET_FLAG, None)
            ctx = cl.user_session.get("user_context")
            if ctx:
                ctx.persona = UserPersona.DEVELOPER.value
                ctx.update_activity()
            logger.warning("Cleared corrupted session data after validation failure")
        except Exception as e:
            logger.error(f"Failed to clear corrupted session data: {e}")
    
