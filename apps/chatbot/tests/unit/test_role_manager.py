"""
Unit tests for user role management functionality.
Tests role validation, context switching, and persona management.
"""

import pytest
from src.user.role_manager import RoleManager


class TestRoleManager:
    """Test suite for role management functionality."""

    @pytest.fixture
    def role_manager(self):
        """Provide a RoleManager instance for testing."""
        return RoleManager()

    @pytest.fixture
    def valid_roles(self):
        """Provide list of valid user roles."""
        return [
            "PSIRT Member",
            "Developer",
            "Academic Researcher",
            "Bug Bounty Hunter",
            "Product Manager",
            "CWE Analyzer",
            "CVE Creator"
        ]

    def test_valid_role_validation(self, role_manager, valid_roles):
        """Test validation of legitimate user roles."""
        for role in valid_roles:
            assert role_manager.is_valid_role(role), \
                f"Valid role rejected: {role}"

    def test_invalid_role_validation(self, role_manager):
        """Test rejection of invalid user roles."""
        invalid_roles = [
            "Hacker",
            "Attacker",
            "Malicious User",
            "System Administrator",
            "Root User",
            "",
            None,
            "   ",
            "Random Role"
        ]

        for role in invalid_roles:
            assert not role_manager.is_valid_role(role), \
                f"Invalid role accepted: {role}"

    def test_role_context_retrieval(self, role_manager, valid_roles):
        """Test retrieval of role-specific context information."""
        for role in valid_roles:
            context = role_manager.get_role_context(role)

            assert isinstance(context, dict), f"Context not dict for role: {role}"

            # Check required context fields
            required_fields = ["focus_areas", "expertise_level", "output_style"]
            for field in required_fields:
                assert field in context, \
                    f"Missing context field '{field}' for role: {role}"

    def test_developer_role_context(self, role_manager):
        """Test specific context for Developer role."""
        context = role_manager.get_role_context("Developer")

        # Developer should focus on code and implementation
        focus_areas = [area.lower() for area in context["focus_areas"]]
        assert any("code" in area or "implementation" in area for area in focus_areas)

        # Should have appropriate expertise level
        assert context["expertise_level"] in ["intermediate", "advanced", "expert"]

    def test_psirt_member_role_context(self, role_manager):
        """Test specific context for PSIRT Member role."""
        context = role_manager.get_role_context("PSIRT Member")

        # PSIRT should focus on impact assessment and advisories
        focus_areas = [area.lower() for area in context["focus_areas"]]
        expected_terms = ["impact", "advisory", "assessment", "response"]
        assert any(term in " ".join(focus_areas) for term in expected_terms)

    def test_academic_researcher_role_context(self, role_manager):
        """Test specific context for Academic Researcher role."""
        context = role_manager.get_role_context("Academic Researcher")

        # Academic should focus on comprehensive analysis and research
        focus_areas = [area.lower() for area in context["focus_areas"]]
        expected_terms = ["research", "analysis", "comprehensive", "academic"]
        assert any(term in " ".join(focus_areas) for term in expected_terms)

    def test_role_switching(self, role_manager, valid_roles):
        """Test switching between different user roles."""
        # Start with first role
        initial_role = valid_roles[0]
        role_manager.set_current_role(initial_role)
        assert role_manager.get_current_role() == initial_role

        # Switch to different roles
        for role in valid_roles[1:]:
            role_manager.set_current_role(role)
            assert role_manager.get_current_role() == role

            # Context should update accordingly
            context = role_manager.get_current_role_context()
            expected_context = role_manager.get_role_context(role)
            assert context == expected_context

    def test_invalid_role_switching(self, role_manager):
        """Test that invalid role switching is rejected."""
        invalid_roles = ["Invalid Role", None, "", "   "]

        for invalid_role in invalid_roles:
            with pytest.raises((ValueError, TypeError)):
                role_manager.set_current_role(invalid_role)

    def test_default_role_behavior(self, role_manager):
        """Test default role assignment when none specified."""
        # Before any role is set, should have a default
        current_role = role_manager.get_current_role()
        assert current_role is not None
        assert role_manager.is_valid_role(current_role)

        # Default role should have valid context
        context = role_manager.get_current_role_context()
        assert isinstance(context, dict)
        assert len(context) > 0

    def test_role_persistence(self, role_manager, valid_roles):
        """Test that role settings persist during session."""
        test_role = valid_roles[2]  # Pick a middle role

        role_manager.set_current_role(test_role)

        # Should persist across multiple calls
        for _ in range(5):
            assert role_manager.get_current_role() == test_role

    def test_role_context_immutability(self, role_manager):
        """Test that role context cannot be accidentally modified."""
        role = "Developer"
        context1 = role_manager.get_role_context(role)
        context2 = role_manager.get_role_context(role)

        # Should get independent copies
        if isinstance(context1, dict):
            context1["test_modification"] = "should not affect original"
            assert "test_modification" not in context2

    def test_get_available_roles(self, role_manager, valid_roles):
        """Test retrieval of all available roles."""
        available = role_manager.get_available_roles()

        assert isinstance(available, list)
        assert len(available) > 0

        # Should include all valid roles
        for role in valid_roles:
            assert role in available

    def test_role_case_sensitivity(self, role_manager):
        """Test handling of role name case variations."""
        base_role = "Developer"

        # Test different case variations
        case_variations = [
            "developer",
            "DEVELOPER",
            "Developer",
            "dEvElOpEr"
        ]

        for variation in case_variations:
            # Should handle case insensitively or reject consistently
            is_valid = role_manager.is_valid_role(variation)
            if variation == base_role:
                assert is_valid  # Exact match should work
            # Other cases may or may not work depending on implementation

    def test_role_context_completeness(self, role_manager, valid_roles):
        """Test that all roles have complete context information."""
        required_fields = ["focus_areas", "expertise_level", "output_style"]

        for role in valid_roles:
            context = role_manager.get_role_context(role)

            for field in required_fields:
                assert field in context, \
                    f"Role '{role}' missing context field: {field}"
                assert context[field] is not None, \
                    f"Role '{role}' has null context field: {field}"

                # Check that fields have appropriate content
                if field == "focus_areas":
                    assert isinstance(context[field], list)
                    assert len(context[field]) > 0
                elif field == "expertise_level":
                    assert isinstance(context[field], str)
                    assert len(context[field]) > 0
                elif field == "output_style":
                    assert isinstance(context[field], str)
                    assert len(context[field]) > 0

    def test_concurrent_role_access(self, role_manager, valid_roles):
        """Test that role manager handles concurrent access safely."""
        # Simulate multiple rapid role changes
        for i in range(10):
            role = valid_roles[i % len(valid_roles)]
            role_manager.set_current_role(role)

            # Should always return valid state
            current = role_manager.get_current_role()
            assert current in valid_roles

            context = role_manager.get_current_role_context()
            assert isinstance(context, dict)

    def test_role_context_contains_expected_fields(self, role_manager):
        """Test that role contexts contain expected security-relevant fields."""
        role = "Developer"
        context = role_manager.get_role_context(role)

        # Should contain security-relevant guidance
        all_values = str(context).lower()
        security_terms = [
            "security", "secure", "vulnerability", "mitigation",
            "code", "implementation", "best practice"
        ]

        # At least some security-related terms should be present
        assert any(term in all_values for term in security_terms), \
            f"Role context lacks security-relevant content: {context}"

    def test_role_manager_state_consistency(self, role_manager):
        """Test that role manager maintains consistent internal state."""
        # Set a role and verify all related methods return consistent results
        test_role = "Bug Bounty Hunter"
        role_manager.set_current_role(test_role)

        current_role = role_manager.get_current_role()
        current_context = role_manager.get_current_role_context()
        direct_context = role_manager.get_role_context(test_role)

        assert current_role == test_role
        assert current_context == direct_context