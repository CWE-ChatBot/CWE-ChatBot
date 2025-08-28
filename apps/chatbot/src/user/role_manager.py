#!/usr/bin/env python3
"""
Role Management Module
Handles user role selection, validation, and secure session storage.
"""

import logging
from enum import Enum
from typing import Optional, Dict, Any
import chainlit as cl
from src.security.secure_logging import get_secure_logger
from src.security.session_encryption import SessionEncryption, EncryptionError, DecryptionError

logger = get_secure_logger(__name__)


class UserRole(Enum):
    """Enumeration of supported user roles with descriptions."""
    
    PSIRT = "psirt"
    DEVELOPER = "developer"
    ACADEMIC = "academic"
    BUG_BOUNTY = "bug_bounty"
    PRODUCT_MANAGER = "product_manager"
    
    def get_display_name(self) -> str:
        """Get human-readable display name for the role."""
        role_names = {
            UserRole.PSIRT: "PSIRT Member",
            UserRole.DEVELOPER: "Developer", 
            UserRole.ACADEMIC: "Academic Researcher",
            UserRole.BUG_BOUNTY: "Bug Bounty Hunter",
            UserRole.PRODUCT_MANAGER: "Product Manager"
        }
        return role_names.get(self, self.value.title())
    
    def get_description(self) -> str:
        """Get description of what this role focuses on."""
        descriptions = {
            UserRole.PSIRT: "Focus on impact assessment, advisory language, and risk evaluation",
            UserRole.DEVELOPER: "Emphasis on code-level remediation, examples, and technical fixes",
            UserRole.ACADEMIC: "Comprehensive analysis, relationships, and research-oriented information",
            UserRole.BUG_BOUNTY: "Exploitation patterns, proof-of-concept examples, and reporting guidance",
            UserRole.PRODUCT_MANAGER: "Trend analysis, prevention strategies, and business impact"
        }
        return descriptions.get(self, "General cybersecurity information")


class RoleManager:
    """Manages user role selection and validation with session security."""
    
    ROLE_SESSION_KEY = "user_role"
    ROLE_SET_FLAG = "role_selection_completed"
    
    def __init__(self):
        """Initialize the role manager with session encryption."""
        self.session_encryptor = SessionEncryption()
        logger.debug("RoleManager initialized with session encryption")
    
    def get_current_role(self) -> Optional[UserRole]:
        """
        Get the current user's role from session with decryption.
        
        Addresses MED-006 by decrypting role data stored in session.
        
        Returns:
            UserRole or None if no role is set
        """
        try:
            stored_value = cl.user_session.get(self.ROLE_SESSION_KEY)
            if not stored_value:
                return None
            
            # Decrypt the stored role value
            try:
                decrypted_value = self.session_encryptor.decrypt_session_data(stored_value)
                logger.debug("Successfully decrypted role data from session")
                return UserRole(decrypted_value)
            except DecryptionError as e:
                logger.error(f"Failed to decrypt role data: {e}")
                # Clear corrupted session data
                self._clear_corrupted_session_data()
                return None
                
        except (ValueError, AttributeError) as e:
            logger.warning(f"Invalid role value in session: {e}")
            return None
    
    def set_user_role(self, role: UserRole) -> bool:
        """
        Set the user's role in session storage with encryption.
        
        Addresses MED-006 by encrypting role data before storage to prevent
        information disclosure if session storage is compromised.
        
        Args:
            role: UserRole to set
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Input validation
            if not isinstance(role, UserRole):
                raise ValueError(f"Invalid role type: {type(role)}")
            
            # Encrypt role value before storage
            encrypted_role = self.session_encryptor.encrypt_session_data(role.value)
            
            # Store encrypted role in session
            cl.user_session[self.ROLE_SESSION_KEY] = encrypted_role
            cl.user_session[self.ROLE_SET_FLAG] = True
            
            logger.info(f"User role set with encryption: {role.get_display_name()}")
            logger.debug(f"Encrypted role data length: {len(encrypted_role)} characters")
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
        return cl.user_session.get(self.ROLE_SET_FLAG, False)
    
    def clear_role(self) -> bool:
        """
        Clear the user's role (for role changes).
        
        Returns:
            True if successful, False otherwise
        """
        try:
            cl.user_session.pop(self.ROLE_SESSION_KEY, None)
            cl.user_session.pop(self.ROLE_SET_FLAG, None)
            logger.info("User role cleared")
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
        
        for role in UserRole:
            action = cl.Action(
                name=f"select_role_{role.value}",
                value=role.value,
                label=role.get_display_name(),
                description=role.get_description()
            )
            actions.append(action)
        
        return actions
    
    def validate_role_integrity(self) -> bool:
        """
        Validate that the role stored in session hasn't been tampered with.
        This provides defense against session manipulation attacks.
        
        Returns:
            True if role is valid, False if compromised
        """
        try:
            role_value = cl.user_session.get(self.ROLE_SESSION_KEY)
            role_set_flag = cl.user_session.get(self.ROLE_SET_FLAG, False)
            
            # Check consistency
            if role_set_flag and not role_value:
                logger.warning("Role integrity check failed: flag set but no role value")
                return False
            
            if role_value and not role_set_flag:
                logger.warning("Role integrity check failed: role value but no flag")
                return False
            
            # Validate role is legitimate
            if role_value:
                try:
                    UserRole(role_value)
                except ValueError:
                    logger.warning(f"Role integrity check failed: invalid role value {role_value}")
                    return False
            
            return True
            
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
            UserRole.PSIRT: [
                "Impact assessment and severity analysis",
                "Advisory language and communication",
                "Risk evaluation and business impact",
                "Incident response considerations"
            ],
            UserRole.DEVELOPER: [
                "Code-level remediation steps",
                "Secure coding practices",
                "Technical implementation details",
                "Code examples and patterns"
            ],
            UserRole.ACADEMIC: [
                "Comprehensive technical analysis",
                "CWE relationships and taxonomy",
                "Research methodologies",
                "Historical context and evolution"
            ],
            UserRole.BUG_BOUNTY: [
                "Exploitation techniques and patterns",
                "Proof-of-concept development",
                "Vulnerability discovery methods",
                "Reporting and disclosure practices"
            ],
            UserRole.PRODUCT_MANAGER: [
                "Business impact and cost analysis",
                "Prevention strategies and planning",
                "Trend analysis and metrics",
                "Resource allocation decisions"
            ]
        }
        
        return {
            "role": current_role.value,
            "role_name": current_role.get_display_name(),
            "focus_areas": focus_areas.get(current_role, []),
            "description": current_role.get_description()
        }
    
    def _clear_corrupted_session_data(self) -> None:
        """
        Clear corrupted session data when decryption fails.
        This provides defense against session tampering attacks.
        """
        try:
            cl.user_session.pop(self.ROLE_SESSION_KEY, None)
            cl.user_session.pop(self.ROLE_SET_FLAG, None)
            logger.warning("Cleared corrupted session data after decryption failure")
        except Exception as e:
            logger.error(f"Failed to clear corrupted session data: {e}")
    
