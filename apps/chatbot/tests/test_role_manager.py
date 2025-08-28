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

from src.user.role_manager import RoleManager, UserRole


class TestRoleManager:
    """Test suite for RoleManager functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.role_manager = RoleManager()
    
    def test_user_role_enum(self):
        """Test UserRole enum values and methods."""
        # Test all role values exist
        assert UserRole.PSIRT.value == "psirt"
        assert UserRole.DEVELOPER.value == "developer"
        assert UserRole.ACADEMIC.value == "academic"
        assert UserRole.BUG_BOUNTY.value == "bug_bounty"
        assert UserRole.PRODUCT_MANAGER.value == "product_manager"
        
        # Test display names
        assert UserRole.PSIRT.get_display_name() == "PSIRT Member"
        assert UserRole.DEVELOPER.get_display_name() == "Developer"
        
        # Test descriptions exist and are non-empty
        for role in UserRole:
            description = role.get_description()
            assert isinstance(description, str)
            assert len(description) > 0
    
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
        success = self.role_manager.set_user_role(UserRole.DEVELOPER)
        assert success
        
        # Verify role was stored correctly
        mock_session.__setitem__.assert_any_call(RoleManager.ROLE_SESSION_KEY, "developer")
        mock_session.__setitem__.assert_any_call(RoleManager.ROLE_SET_FLAG, True)
    
    @patch('chainlit.user_session')
    def test_get_current_role_with_valid_data(self, mock_session):
        """Test retrieving current role with valid session data."""
        mock_session.get = Mock(side_effect=lambda key, default=None: {
            RoleManager.ROLE_SESSION_KEY: "psirt"
        }.get(key, default))
        
        role = self.role_manager.get_current_role()
        assert role == UserRole.PSIRT
    
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
        # Test with non-UserRole input
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
            
            # Should create one action per role
            assert mock_action.call_count == len(UserRole)
            
            # Verify action parameters for first call (PSIRT)
            first_call = mock_action.call_args_list[0]
            args, kwargs = first_call
            assert kwargs['name'] == 'select_role_psirt'
            assert kwargs['value'] == 'psirt'
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
            RoleManager.ROLE_SESSION_KEY: "hacker_role",  # Invalid role
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
        assert context['role'] == "psirt"
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
            # Valid: both set
            ({RoleManager.ROLE_SESSION_KEY: "developer", RoleManager.ROLE_SET_FLAG: True}, True),
            # Valid: both unset  
            ({}, True),
            # Invalid: only role set
            ({RoleManager.ROLE_SESSION_KEY: "developer"}, False),
            # Invalid: only flag set
            ({RoleManager.ROLE_SET_FLAG: True}, False)
        ]
        
        for session_data, expected_valid in test_cases:
            mock_session.get = Mock(side_effect=lambda key, default=None: session_data.get(key, default))
            is_valid = self.role_manager.validate_role_integrity()
            assert is_valid == expected_valid


if __name__ == "__main__":
    pytest.main([__file__, "-v"])