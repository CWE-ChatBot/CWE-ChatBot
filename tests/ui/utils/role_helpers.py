"""
Helper utilities for role-based testing scenarios.
Provides role-specific test data and validation functions.
"""

from enum import Enum
from typing import Any, Dict, List

# Role definitions (will import from actual code when available)
try:
    import os
    import sys

    sys.path.insert(
        0,
        os.path.join(
            os.path.dirname(__file__), "..", "..", "..", "apps", "chatbot", "src"
        ),
    )
    from user.role_manager import UserRole
except ImportError:
    # Fallback definitions for testing
    class UserRole(Enum):
        PSIRT = "psirt"
        DEVELOPER = "developer"
        ACADEMIC = "academic"
        BUG_BOUNTY = "bug_bounty"
        PRODUCT_MANAGER = "product_manager"


class RoleTestHelper:
    """Helper class for role-based testing operations."""

    # Role-specific test queries
    ROLE_TEST_QUERIES = {
        UserRole.PSIRT: [
            "Tell me about CWE-79 for vulnerability assessment",
            "What's the CVSS score impact of XSS vulnerabilities?",
            "How should I describe CWE-89 in a security advisory?",
        ],
        UserRole.DEVELOPER: [
            "Show me code examples to prevent SQL injection",
            "How do I fix CWE-79 in my React application?",
            "What are secure coding practices for CWE-22?",
        ],
        UserRole.ACADEMIC: [
            "What research has been done on XSS attack patterns?",
            "How do CWE-79 and CWE-89 relate to each other?",
            "What are the statistical trends for web vulnerabilities?",
        ],
        UserRole.BUG_BOUNTY: [
            "Where should I look for XSS vulnerabilities?",
            "What's the typical payout for CWE-89 findings?",
            "How do I write a good vulnerability report for path traversal?",
        ],
        UserRole.PRODUCT_MANAGER: [
            "What's the business impact of having CWE-79 vulnerabilities?",
            "How can we prioritize fixing these security weaknesses?",
            "What metrics should I track for vulnerability management?",
        ],
    }

    # Expected keywords/phrases in role-specific responses
    ROLE_RESPONSE_INDICATORS = {
        UserRole.PSIRT: [
            "vulnerability",
            "advisory",
            "impact",
            "severity",
            "CVSS",
            "affected systems",
            "mitigation",
            "disclosure",
        ],
        UserRole.DEVELOPER: [
            "code",
            "fix",
            "implement",
            "prevent",
            "secure coding",
            "validation",
            "sanitization",
            "best practices",
        ],
        UserRole.ACADEMIC: [
            "research",
            "study",
            "analysis",
            "relationship",
            "trend",
            "statistical",
            "comparative",
            "taxonomy",
        ],
        UserRole.BUG_BOUNTY: [
            "exploit",
            "finding",
            "report",
            "bounty",
            "detection",
            "payload",
            "reconnaissance",
            "proof of concept",
        ],
        UserRole.PRODUCT_MANAGER: [
            "business",
            "impact",
            "priority",
            "risk",
            "cost",
            "timeline",
            "resource",
            "strategy",
            "roadmap",
        ],
    }

    # Progressive disclosure actions by role
    ROLE_PROGRESSIVE_ACTIONS = {
        UserRole.PSIRT: ["show_consequences", "show_related", "tell_more"],
        UserRole.DEVELOPER: ["show_prevention", "tell_more", "show_examples"],
        UserRole.ACADEMIC: ["show_related", "show_research", "tell_more"],
        UserRole.BUG_BOUNTY: ["show_exploitation", "show_detection", "tell_more"],
        UserRole.PRODUCT_MANAGER: [
            "show_business_impact",
            "show_priority",
            "tell_more",
        ],
    }

    @classmethod
    def get_test_query_for_role(cls, role: UserRole, index: int = 0) -> str:
        """Get a test query appropriate for the specified role."""
        queries = cls.ROLE_TEST_QUERIES.get(role, ["Tell me about CWE-79"])
        return queries[index % len(queries)]

    @classmethod
    def get_all_test_queries_for_role(cls, role: UserRole) -> List[str]:
        """Get all test queries for the specified role."""
        return cls.ROLE_TEST_QUERIES.get(role, [])

    @classmethod
    def validate_role_response_format(cls, response: str, role: UserRole) -> bool:
        """Validate that a response matches the expected format for a role."""
        if not response or len(response.strip()) < 10:
            return False

        indicators = cls.ROLE_RESPONSE_INDICATORS.get(role, [])
        response_lower = response.lower()

        # Check if at least 30% of role indicators are present
        matches = sum(
            1 for indicator in indicators if indicator.lower() in response_lower
        )
        required_matches = max(1, len(indicators) * 0.3)

        return matches >= required_matches

    @classmethod
    def get_expected_progressive_actions(cls, role: UserRole) -> List[str]:
        """Get the progressive disclosure actions expected for a role."""
        return cls.ROLE_PROGRESSIVE_ACTIONS.get(role, ["tell_more"])

    @classmethod
    def validate_progressive_actions_present(
        cls, page_content: str, role: UserRole
    ) -> bool:
        """Validate that expected progressive actions are present for a role."""
        expected_actions = cls.get_expected_progressive_actions(role)
        content_lower = page_content.lower()

        # Check if at least half of the expected actions are present
        present_actions = sum(
            1
            for action in expected_actions
            if action.replace("_", " ").lower() in content_lower
        )

        return present_actions >= len(expected_actions) * 0.5

    @classmethod
    def get_role_context_data(cls, role: UserRole) -> Dict[str, Any]:
        """Get context data for role-based testing."""
        return {
            "role": role,
            "test_queries": cls.get_all_test_queries_for_role(role),
            "response_indicators": cls.ROLE_RESPONSE_INDICATORS.get(role, []),
            "progressive_actions": cls.get_expected_progressive_actions(role),
            "role_display_name": role.value.replace("_", " ").title(),
        }


# Utility functions
def get_all_test_roles() -> List[UserRole]:
    """Get all available test roles."""
    return list(UserRole)


def get_role_by_name(name: str) -> UserRole:
    """Get a UserRole enum by string name."""
    name_upper = name.upper()
    for role in UserRole:
        if role.name == name_upper or role.value == name.lower():
            return role
    raise ValueError(f"Unknown role: {name}")


def create_role_test_matrix() -> List[Dict[str, Any]]:
    """Create a test matrix for all roles with their test data."""
    return [RoleTestHelper.get_role_context_data(role) for role in UserRole]


# Test data for specific scenarios
CWE_TEST_SCENARIOS = {
    "xss_basic": {
        "cwe_id": "CWE-79",
        "query": "Tell me about cross-site scripting vulnerabilities",
        "expected_keywords": ["XSS", "script", "input validation", "output encoding"],
    },
    "sql_injection": {
        "cwe_id": "CWE-89",
        "query": "How do I prevent SQL injection attacks?",
        "expected_keywords": [
            "parameterized queries",
            "prepared statements",
            "input validation",
        ],
    },
    "path_traversal": {
        "cwe_id": "CWE-22",
        "query": "What is directory traversal vulnerability?",
        "expected_keywords": [
            "path traversal",
            "directory",
            "file access",
            "input validation",
        ],
    },
}
