#!/usr/bin/env python3
"""
Tests for Role Manager functionality.
Tests role selection, validation, and session security.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Mock chainlit before importing role_manager
sys.modules['chainlit'] = MagicMock()

# Add src to path for imports  
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.user.role_manager import RoleManager
from src.user_context import UserPersona


class TestRoleManager:
    """Test suite for RoleManager functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.role_manager = RoleManager()
    
    def test_user_persona_enum(self):
        """Test UserPersona enum values and usage."""
        # Test all role values exist
        assert UserPersona.PSIRT_MEMBER.value == "PSIRT Member"
        assert UserPersona.DEVELOPER.value == "Developer"
        
        # Test display names
        assert UserPersona.PSIRT_MEMBER.value == "PSIRT Member"
        assert UserPersona.DEVELOPER.value == "Developer"
        
        # Persona enum is source of truth; descriptions are generated internally
    
    @patch('chainlit.user_session')
    def test_role_selection_and_retrieval(self, mock_session):
        """Test setting and getting user roles."""
        mock_session.__getitem__ = Mock()
        mock_session.__setitem__ = Mock()
        mock_session.get = Mock(return_value=None)
        
        # Test initial state - no role selected
        assert self.role_manager.get_current_role() is None
        assert not self.role_manager.is_role_selected()
        
        # Test setting a role
        success = self.role_manager.set_user_role(UserPersona.DEVELOPER)
        assert success
        
        # Verify keys were set with plaintext value
        calls = dict((c.args[0], c.args[1]) for c in mock_session.__setitem__.call_args_list)
        assert calls[RoleManager.ROLE_SESSION_KEY] == 'Developer'
        assert calls[RoleManager.ROLE_SET_FLAG] is True
    
    @patch('chainlit.user_session')
    def test_get_current_role_with_valid_data(self, mock_session):
        """Test retrieving current role with valid session data."""
        mock_session.get = Mock(side_effect=lambda key, default=None: {
            RoleManager.ROLE_SESSION_KEY: "PSIRT Member"
        }.get(key, default))
        role = self.role_manager.get_current_role()
        assert role == UserPersona.PSIRT_MEMBER
    
    @patch('chainlit.user_session')
    def test_get_current_role_with_invalid_data(self, mock_session):
        """Test retrieving current role with invalid session data."""
        mock_session.get = Mock(side_effect=lambda key, default=None: {
            RoleManager.ROLE_SESSION_KEY: "invalid_role"
        }.get(key, default))
        role = self.role_manager.get_current_role()
        assert role is None
    
    def test_set_user_role_invalid_input(self):
        """Test setting role with invalid input."""
        # Test with invalid input types/values
        success = self.role_manager.set_user_role("invalid")
        assert not success
        
        success = self.role_manager.set_user_role(None)
        assert not success
        
        success = self.role_manager.set_user_role(123)
        assert not success
    
    @patch('chainlit.user_session')
    def test_clear_role(self, mock_session):
        """Test clearing user role."""
        mock_session.pop = Mock()
        
        success = self.role_manager.clear_role()
        assert success
        
        # Verify both session keys were cleared
        mock_session.pop.assert_any_call(RoleManager.ROLE_SESSION_KEY, None)
        mock_session.pop.assert_any_call(RoleManager.ROLE_SET_FLAG, None)
    
    def test_get_role_actions(self):
        """Test generation of Chainlit action buttons."""
        with patch('chainlit.Action') as mock_action:
            actions = self.role_manager.get_role_actions()
            
            # Should create one action per persona
            from src.user_context import UserPersona
            assert mock_action.call_count == len(UserPersona)
            
            # Verify action parameters for first call (PSIRT)
            first_call = mock_action.call_args_list[0]
            args, kwargs = first_call
            assert kwargs['name'] == 'select_role_psirt_member'
            assert kwargs['value'] == 'PSIRT Member'
            assert kwargs['label'] == 'PSIRT Member'
            assert len(kwargs['description']) > 0
    
    @patch('chainlit.user_session')
    def test_validate_role_integrity_valid(self, mock_session):
        """Test role integrity validation with valid data."""
        mock_session.get = Mock(side_effect=lambda key, default=None: {
            RoleManager.ROLE_SESSION_KEY: "developer",
            RoleManager.ROLE_SET_FLAG: True
        }.get(key, default))
        is_valid = self.role_manager.validate_role_integrity()
        assert is_valid
    
    @patch('chainlit.user_session') 
    def test_validate_role_integrity_inconsistent_flag(self, mock_session):
        """Test role integrity validation with inconsistent flag."""
        # Flag set but no role value
        mock_session.get = Mock(side_effect=lambda key, default=None: {
            RoleManager.ROLE_SET_FLAG: True
        }.get(key, default))
        
        is_valid = self.role_manager.validate_role_integrity()
        assert not is_valid
        
        # Role value but no flag
        mock_session.get = Mock(side_effect=lambda key, default=None: {
            RoleManager.ROLE_SESSION_KEY: "developer"
        }.get(key, default))
        
        is_valid = self.role_manager.validate_role_integrity()
        assert not is_valid
    
    @patch('chainlit.user_session')
    def test_validate_role_integrity_invalid_role(self, mock_session):
        """Test role integrity validation with invalid role value."""
        mock_session.get = Mock(side_effect=lambda key, default=None: {
            RoleManager.ROLE_SESSION_KEY: "hacker_role",
            RoleManager.ROLE_SET_FLAG: True
        }.get(key, default))
        is_valid = self.role_manager.validate_role_integrity()
        assert not is_valid
    
    @patch('chainlit.user_session')
    def test_get_role_context(self, mock_session):
        """Test getting role context for prompt templating."""
        # Test with no role selected
        mock_session.get = Mock(return_value=None)
        
        context = self.role_manager.get_role_context()
        assert context['role'] is None
        assert context['role_name'] == "General User"
        assert context['focus_areas'] == []
        
        # Test with PSIRT role selected
        mock_session.get = Mock(side_effect=lambda key, default=None: {
            RoleManager.ROLE_SESSION_KEY: "psirt"
        }.get(key, default))
        context = self.role_manager.get_role_context()
        assert context['role'] == "PSIRT Member"
        assert context['role_name'] == "PSIRT Member"
        assert len(context['focus_areas']) > 0
        assert "Impact assessment" in context['focus_areas'][0]


class TestRoleManagerSecurity:
    """Security-focused tests for RoleManager."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.role_manager = RoleManager()
    
    @patch('chainlit.user_session')
    def test_session_isolation(self, mock_session):
        """Test that role data is properly isolated per session."""
        # This test ensures roles don't leak between sessions
        # In a real scenario, each session would have its own cl.user_session
        mock_session.get = Mock(return_value=None)
        
        # Fresh session should have no role
        assert self.role_manager.get_current_role() is None
        assert not self.role_manager.is_role_selected()
    
    def test_role_enumeration_protection(self):
        """Test that only valid roles can be set."""
        # Should reject arbitrary string values
        success = self.role_manager.set_user_role("admin")
        assert not success
        
        success = self.role_manager.set_user_role("superuser")
        assert not success
        
        success = self.role_manager.set_user_role("<script>alert('xss')</script>")
        assert not success
    
    @patch('chainlit.user_session')
    def test_tamper_detection(self, mock_session):
        """Test detection of tampered session data."""
        # Simulate tampered session: flag set but invalid role
        mock_session.get = Mock(side_effect=lambda key, default=None: {
            RoleManager.ROLE_SESSION_KEY: "tampered_role",
            RoleManager.ROLE_SET_FLAG: True  
        }.get(key, default))
        
        # Integrity check should fail
        is_valid = self.role_manager.validate_role_integrity()
        assert not is_valid
    
    @patch('chainlit.user_session')
    def test_session_key_consistency(self, mock_session):
        """Test consistency between session keys."""
        # Both keys should be set together or not at all
        test_cases = [
            ({RoleManager.ROLE_SESSION_KEY: "Developer", RoleManager.ROLE_SET_FLAG: True}, True),
            ({}, True),
            ({RoleManager.ROLE_SESSION_KEY: "Developer"}, False),
            ({RoleManager.ROLE_SET_FLAG: True}, False)
        ]
        
        for session_data, expected_valid in test_cases:
            mock_session.get = Mock(side_effect=lambda key, default=None: session_data.get(key, default))
            is_valid = self.role_manager.validate_role_integrity()
            assert is_valid == expected_valid


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
