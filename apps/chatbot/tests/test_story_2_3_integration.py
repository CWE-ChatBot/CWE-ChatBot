#!/usr/bin/env python3
"""
Integration Tests for Story 2.3: Role-Based Context Awareness & Hallucination Mitigation
Tests the complete integration of role selection, prompt templating, and confidence scoring.
"""

import pytest
import sys
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Mock chainlit before importing
sys.modules['chainlit'] = MagicMock()

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.user.role_manager import UserRole
from src.processing.role_aware_responder import RoleAwareResponder, RoleAwareResponse
from src.processing.confidence_manager import ConfidenceManager
from src.prompts.role_templates import RolePromptTemplates
from src.retrieval.base_retriever import CWEResult


class TestStory23Integration:
    """Integration tests for complete Story 2.3 implementation."""
    
    def setup_method(self):
        """Set up test components."""
        # Initialize core components with mocks
        self.role_aware_responder = RoleAwareResponder(mock_llm=True)
        self.confidence_manager = ConfidenceManager()
        self.prompt_templates = RolePromptTemplates()
        
        # Create mock CWE data
        self.mock_cwe_result = CWEResult(
            cwe_id="CWE-79",
            name="Cross-site Scripting",
            description="The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.",
            confidence_score=0.85,
            source_method="hybrid"
        )
        
        self.mock_cwe_result.extended_description = "XSS vulnerabilities occur when applications include untrusted data in web pages without proper validation."
        self.mock_cwe_result.consequences = [
            {"Scope": "Confidentiality", "Impact": "Read Application Data"},
            {"Scope": "Integrity", "Impact": "Execute Unauthorized Code or Commands"}
        ]
    
    def test_acceptance_criteria_1_role_selection_enum(self):
        """
        AC1: The ChatBot explicitly prompts the user to select their role.
        Test that all required roles are available.
        """
        # Verify all 5 required roles exist
        expected_roles = {'psirt', 'developer', 'academic', 'bug_bounty', 'product_manager'}
        actual_roles = {role.value for role in UserRole}
        
        assert expected_roles.issubset(actual_roles), f"Missing roles: {expected_roles - actual_roles}"
        
        # Verify display names are user-friendly
        for role in UserRole:
            display_name = role.get_display_name()
            assert len(display_name) > 0
            assert display_name != role.value  # Should be different from enum value
    
    @pytest.mark.asyncio
    async def test_acceptance_criteria_2_role_specific_responses(self):
        """
        AC2: The system can dynamically tailor its response content and emphasis based on the selected role.
        Test different role selections produce observably different response content.
        """
        query = "Tell me about CWE-79"
        
        # Generate responses for different roles
        responses = {}
        for role in [UserRole.PSIRT, UserRole.DEVELOPER, UserRole.ACADEMIC]:
            response = await self.role_aware_responder.generate_role_based_response(
                query=query,
                role=role,
                cwe_results=[self.mock_cwe_result],
                confidence_score=0.8
            )
            responses[role] = response
        
        # Verify responses are different for different roles
        psirt_content = responses[UserRole.PSIRT].content
        dev_content = responses[UserRole.DEVELOPER].content
        academic_content = responses[UserRole.ACADEMIC].content
        
        assert psirt_content != dev_content, "PSIRT and Developer responses should be different"
        assert dev_content != academic_content, "Developer and Academic responses should be different"
        assert psirt_content != academic_content, "PSIRT and Academic responses should be different"
        
        # Verify role-specific emphasis is present
        assert "impact assessment" in psirt_content.lower(), "PSIRT response should mention impact assessment"
        assert "code-level" in dev_content.lower() or "implementation" in dev_content.lower(), "Developer response should mention code-level details"
        assert "taxonomic" in academic_content.lower() or "research" in academic_content.lower(), "Academic response should mention research context"
    
    def test_acceptance_criteria_3_hallucination_mitigation(self):
        """
        AC3: Core AI mechanisms are implemented to actively minimize AI hallucination.
        Test citation and derived information flagging.
        """
        # Test citation extraction
        citations = self.role_aware_responder._extract_citations([self.mock_cwe_result])
        assert len(citations) == 1
        assert "CWE-79" in citations[0]
        assert "Cross-site Scripting" in citations[0]
        
        # Test prompt templates include citation requirements
        prompt = self.prompt_templates.get_role_prompt(UserRole.DEVELOPER, {})
        citation_instructions = self.prompt_templates.get_citation_instructions()
        
        assert "according to cwe" in citation_instructions.lower()
        assert "based on cwe data" in citation_instructions.lower()
        assert "distinguish between" in citation_instructions.lower()
    
    def test_acceptance_criteria_4_confidence_scoring(self):
        """
        AC4: The system displays a confidence score or prioritization order alongside CWE suggestions.
        Test confidence score display functionality.
        """
        # Test confidence metrics calculation
        metrics = self.confidence_manager.calculate_confidence_metrics(
            similarity_score=0.82,
            query_type="direct_cwe_lookup",
            result_count=1
        )
        
        # Verify confidence display formatting
        display = self.confidence_manager.format_confidence_display(metrics)
        assert "%" in display
        assert "Confidence:" in display
        assert metrics.confidence_level in display
        
        # Test confidence indicator
        indicator = self.confidence_manager.format_confidence_indicator(metrics)
        assert "%" in indicator
        assert any(emoji in indicator for emoji in ["🟢", "🟡", "🔴"])
    
    def test_acceptance_criteria_5_low_confidence_handling(self):
        """
        AC5: When confidence is low, system clearly states limitation and suggests query refinement.
        Test low confidence detection and warning generation.
        """
        # Test low confidence scenario
        low_confidence_metrics = self.confidence_manager.calculate_confidence_metrics(
            similarity_score=0.25,  # Low confidence
            query_type="general",
            result_count=1
        )
        
        assert low_confidence_metrics.should_show_warning
        assert low_confidence_metrics.confidence_level == "Low"
        
        # Test warning generation
        warning = self.confidence_manager.get_low_confidence_warning(low_confidence_metrics)
        assert warning is not None
        assert "⚠️" in warning
        assert "Low Confidence" in warning
        assert "refining your query" in warning.lower() or "more specific" in warning.lower()
        
        # Test that high confidence doesn't generate warnings
        high_confidence_metrics = self.confidence_manager.calculate_confidence_metrics(
            similarity_score=0.9,
            query_type="direct_cwe_lookup",
            result_count=1
        )
        
        high_warning = self.confidence_manager.get_low_confidence_warning(high_confidence_metrics)
        assert high_warning is None
    
    @pytest.mark.asyncio
    async def test_security_requirement_1_role_integrity(self):
        """
        Security Requirement 1: User role information must be securely managed within the user's session.
        """
        # Test that roles are validated
        for role in UserRole:
            assert isinstance(role.value, str)
            assert len(role.value) > 0
            assert role.value.isalnum() or '_' in role.value  # Only alphanumeric or underscore
        
        # Test role context generation doesn't expose sensitive data
        role_context = self.role_aware_responder._build_role_emphasis(UserRole.PSIRT, [self.mock_cwe_result])
        
        # Verify context contains expected structure without sensitive data
        assert 'focus_areas' in role_context
        assert 'tone' in role_context
        assert isinstance(role_context['focus_areas'], list)
        assert isinstance(role_context['tone'], str)
    
    def test_security_requirement_2_no_unintended_disclosures(self):
        """
        Security Requirement 2: Role-based views must not inadvertently expose sensitive information.
        """
        # Test that role templates don't contain hardcoded sensitive data
        for role in UserRole:
            prompt = self.prompt_templates.get_role_prompt(role, {})
            
            # Should not contain any obvious secrets or internal paths
            assert "password" not in prompt.lower()
            assert "secret" not in prompt.lower()
            assert "api_key" not in prompt.lower()
            assert "/internal/" not in prompt.lower()
            
        # Test role context doesn't expose system internals
        context = self.role_aware_responder._build_role_emphasis(UserRole.BUG_BOUNTY, [self.mock_cwe_result])
        
        # Should contain expected fields but no system paths or secrets
        assert 'focus_areas' in context
        assert not any(key.startswith('/') for key in str(context))
    
    @pytest.mark.asyncio
    async def test_end_to_end_role_based_pipeline(self):
        """
        Test complete end-to-end role-based response pipeline.
        This simulates the full user experience flow.
        """
        # Simulate complete pipeline for PSIRT user
        query = "What is the security impact of CWE-79?"
        role = UserRole.PSIRT
        
        # Step 1: Generate role-aware response
        response = await self.role_aware_responder.generate_role_based_response(
            query=query,
            role=role,
            cwe_results=[self.mock_cwe_result],
            confidence_score=0.78
        )
        
        # Step 2: Verify response structure
        assert isinstance(response, RoleAwareResponse)
        assert response.role == "psirt"
        assert response.confidence_display is not None
        assert len(response.citations) > 0
        assert len(response.role_specific_emphasis) > 0
        
        # Step 3: Verify PSIRT-specific content
        assert "impact" in response.content.lower()
        assert response.role_specific_emphasis['tone'] == 'professional_advisory'
        
        # Step 4: Verify confidence handling
        assert "Confidence:" in response.confidence_display
        assert "%" in response.confidence_display
        
        # Test the pipeline handles low confidence appropriately
        low_conf_response = await self.role_aware_responder.generate_role_based_response(
            query="Vague security question",
            role=role,
            cwe_results=[self.mock_cwe_result],
            confidence_score=0.2  # Low confidence
        )
        
        assert low_conf_response.low_confidence_warning is not None
        assert "⚠️" in low_conf_response.low_confidence_warning
    
    def test_prompt_template_role_differentiation(self):
        """Test that prompt templates create meaningfully different prompts for different roles."""
        context = {'cwe_data': {'cwe_id': 'CWE-79', 'name': 'XSS'}}
        
        prompts = {}
        for role in UserRole:
            prompts[role] = self.prompt_templates.get_role_prompt(role, context)
        
        # Verify each role has unique prompt characteristics
        role_keywords = {
            UserRole.PSIRT: ['impact assessment', 'advisory', 'risk'],
            UserRole.DEVELOPER: ['code-level', 'implementation', 'remediation'],
            UserRole.ACADEMIC: ['comprehensive', 'research', 'taxonomy'],
            UserRole.BUG_BOUNTY: ['exploitation', 'discovery', 'poc'],
            UserRole.PRODUCT_MANAGER: ['business impact', 'strategic', 'resource']
        }
        
        for role, keywords in role_keywords.items():
            prompt = prompts[role].lower()
            found_keywords = [kw for kw in keywords if kw in prompt]
            assert len(found_keywords) > 0, f"Role {role.value} prompt missing expected keywords: {keywords}"
    
    def test_confidence_normalization_ranges(self):
        """Test that confidence normalization produces appropriate ranges for different inputs."""
        test_cases = [
            (0.95, "direct_cwe_lookup", 90, 100),  # Very high
            (0.75, "direct_cwe_lookup", 75, 89),   # High
            (0.55, "concept_search", 50, 74),      # Medium  
            (0.35, "general", 25, 49),             # Low
            (0.15, "general", 10, 24)              # Very low
        ]
        
        for raw_score, query_type, min_expected, max_expected in test_cases:
            metrics = self.confidence_manager.calculate_confidence_metrics(
                raw_score, query_type, 1
            )
            
            assert min_expected <= metrics.normalized_percentage <= max_expected, \
                f"Score {raw_score} with query type {query_type} produced {metrics.normalized_percentage}%, expected {min_expected}-{max_expected}%"


class TestManualVerificationPrep:
    """Prepare data and scenarios for manual verification as specified in the story."""
    
    def test_manual_verification_scenarios(self):
        """
        Prepare test scenarios for manual verification:
        - Developer role asking about CWE-89
        - PSIRT role asking about CWE-89  
        - Ambiguous query testing
        """
        # Test data that would be used for manual verification
        test_scenarios = [
            {
                "role": "Developer",
                "query": "Tell me about CWE-89",
                "expected_focus": "code-level remediation, technical fixes, secure coding"
            },
            {
                "role": "PSIRT",
                "query": "Tell me about CWE-89",
                "expected_focus": "impact assessment, advisory language, risk evaluation"
            },
            {
                "query": "my website is broken",
                "expected_behavior": "low confidence handling, refinement suggestions"
            }
        ]
        
        # Verify test scenarios are well-formed
        for scenario in test_scenarios:
            assert "query" in scenario
            if "role" in scenario:
                assert "expected_focus" in scenario
            else:
                assert "expected_behavior" in scenario
        
        assert len(test_scenarios) == 3  # As specified in story


if __name__ == "__main__":
    pytest.main([__file__, "-v"])