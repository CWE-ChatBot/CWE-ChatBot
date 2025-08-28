#!/usr/bin/env python3
"""
Tests for Role-Aware Response Generator
Tests role-based prompt generation and response formatting.
"""

import pytest
import sys
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Mock dependencies before importing
sys.modules['chainlit'] = MagicMock()

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.processing.role_aware_responder import RoleAwareResponder, RoleAwareResponse
from src.user.role_manager import UserRole
from src.retrieval.base_retriever import CWEResult


class TestRoleAwareResponder:
    """Test suite for RoleAwareResponder functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.responder = RoleAwareResponder(mock_llm=True)
        
        # Create mock CWE results
        self.mock_cwe_result = CWEResult(
            cwe_id="CWE-79",
            name="Cross-site Scripting",
            description="The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.",
            confidence_score=0.95,
            source_method="hybrid"
        )
        
        # Add extended attributes for comprehensive testing
        self.mock_cwe_result.extended_description = "XSS vulnerabilities occur when..."
        self.mock_cwe_result.consequences = ["Execute unauthorized code", "Bypass protection mechanisms"]
        self.mock_cwe_result.likelihood = "High"
        self.mock_cwe_result.impact = "Complete compromise of user session"
    
    @pytest.mark.asyncio
    async def test_generate_role_based_response_no_role(self):
        """Test response generation without a selected role."""
        response = await self.responder.generate_role_based_response(
            query="What is XSS?",
            role=None,
            cwe_results=[self.mock_cwe_result],
            confidence_score=0.9
        )
        
        assert isinstance(response, RoleAwareResponse)
        assert response.role is None
        assert response.confidence_score == 0.9
        assert len(response.citations) == 1
        assert "CWE-79" in response.citations[0]
        assert "general overview" in response.content.lower()
    
    @pytest.mark.asyncio
    async def test_generate_role_based_response_psirt(self):
        """Test PSIRT role-specific response generation."""
        response = await self.responder.generate_role_based_response(
            query="Tell me about CWE-79",
            role=UserRole.PSIRT,
            cwe_results=[self.mock_cwe_result],
            confidence_score=0.85
        )
        
        assert response.role == "psirt"
        assert response.confidence_score == 0.85
        assert "impact assessment" in response.content.lower()
        assert "communication strategy" in response.content.lower()
        assert response.role_specific_emphasis['focus_areas'] == ['impact_assessment', 'advisory_language', 'risk_evaluation']
    
    @pytest.mark.asyncio
    async def test_generate_role_based_response_developer(self):
        """Test Developer role-specific response generation."""
        response = await self.responder.generate_role_based_response(
            query="How do I fix XSS?",
            role=UserRole.DEVELOPER,
            cwe_results=[self.mock_cwe_result],
            confidence_score=0.92
        )
        
        assert response.role == "developer"
        assert "code-level remediation" in response.content.lower()
        assert "implementation notes" in response.content.lower()
        assert response.role_specific_emphasis['tone'] == 'technical_practical'
    
    @pytest.mark.asyncio
    async def test_generate_role_based_response_academic(self):
        """Test Academic role-specific response generation."""
        response = await self.responder.generate_role_based_response(
            query="Research on XSS vulnerabilities",
            role=UserRole.ACADEMIC,
            cwe_results=[self.mock_cwe_result],
            confidence_score=0.88
        )
        
        assert response.role == "academic"
        assert "taxonomic context" in response.content.lower()
        assert "research implications" in response.content.lower()
        assert response.role_specific_emphasis['tone'] == 'scholarly_comprehensive'
    
    @pytest.mark.asyncio
    async def test_generate_role_based_response_bug_bounty(self):
        """Test Bug Bounty Hunter role-specific response generation."""
        response = await self.responder.generate_role_based_response(
            query="How to find XSS vulnerabilities",
            role=UserRole.BUG_BOUNTY,
            cwe_results=[self.mock_cwe_result],
            confidence_score=0.91
        )
        
        assert response.role == "bug_bounty"
        assert "exploitation notes" in response.content.lower()
        assert "testing methodology" in response.content.lower()
        assert response.role_specific_emphasis['focus_areas'] == ['exploitation_techniques', 'discovery_methods', 'poc_development']
    
    @pytest.mark.asyncio
    async def test_generate_role_based_response_product_manager(self):
        """Test Product Manager role-specific response generation."""
        response = await self.responder.generate_role_based_response(
            query="XSS impact on our product",
            role=UserRole.PRODUCT_MANAGER,
            cwe_results=[self.mock_cwe_result],
            confidence_score=0.87
        )
        
        assert response.role == "product_manager"
        assert "business impact" in response.content.lower()
        assert "resource planning" in response.content.lower()
        assert response.role_specific_emphasis['tone'] == 'business_strategic'
    
    @pytest.mark.asyncio
    async def test_low_confidence_handling(self):
        """Test handling of low confidence scores."""
        response = await self.responder.generate_role_based_response(
            query="Vague security question",
            role=UserRole.DEVELOPER,
            cwe_results=[self.mock_cwe_result],
            confidence_score=0.3  # Low confidence
        )
        
        assert response.confidence_score == 0.3
        assert "confidence:" in response.content.lower() or "refine" in response.content.lower()
    
    @pytest.mark.asyncio
    async def test_no_results_handling(self):
        """Test handling when no CWE results are provided."""
        response = await self.responder.generate_role_based_response(
            query="Unknown security topic",
            role=UserRole.PSIRT,
            cwe_results=[],
            confidence_score=0.1
        )
        
        assert response.confidence_score == 0.1
        assert "no relevant" in response.content.lower()
        assert len(response.citations) == 0
    
    def test_get_role_context_summary(self):
        """Test role context summary generation."""
        # Test all roles
        for role in UserRole:
            summary = self.responder.get_role_context_summary(role)
            assert isinstance(summary, str)
            assert len(summary) > 20  # Should be descriptive
            assert role.value.replace('_', ' ').lower() in summary.lower() or \
                   role.get_display_name().lower() in summary.lower()
        
        # Test no role
        summary = self.responder.get_role_context_summary(None)
        assert "general" in summary.lower()
    
    def test_build_context(self):
        """Test context building for prompt generation."""
        query = "Tell me about CWE-79"
        context = self.responder._build_context(query, [self.mock_cwe_result], 0.85)
        
        assert context['query'] == query
        assert context['confidence_score'] == 0.85
        assert context['num_results'] == 1
        assert context['cwe_data']['cwe_id'] == "CWE-79"
        assert context['query_type'] == 'direct_cwe_lookup'  # CWE-79 is in the query
    
    def test_extract_citations(self):
        """Test citation extraction from CWE results."""
        results = [
            self.mock_cwe_result,
            CWEResult(cwe_id="CWE-89", name="SQL Injection", description="SQL injection occurs...", confidence_score=0.9, source_method="sparse")
        ]
        
        citations = self.responder._extract_citations(results)
        assert len(citations) == 2
        assert "CWE-CWE-79" in citations[0]  # Note: format includes CWE- prefix
        assert "Cross-site Scripting" in citations[0]
    
    def test_build_role_emphasis(self):
        """Test role-specific emphasis metadata generation."""
        # Test PSIRT emphasis
        emphasis = self.responder._build_role_emphasis(UserRole.PSIRT, [self.mock_cwe_result])
        assert emphasis['focus_areas'] == ['impact_assessment', 'advisory_language', 'risk_evaluation']
        assert emphasis['tone'] == 'professional_advisory'
        
        # Test Developer emphasis
        emphasis = self.responder._build_role_emphasis(UserRole.DEVELOPER, [self.mock_cwe_result])
        assert emphasis['focus_areas'] == ['code_remediation', 'technical_implementation', 'testing']
        assert emphasis['tone'] == 'technical_practical'
        
        # Test no role/results
        emphasis = self.responder._build_role_emphasis(None, [])
        assert emphasis == {}


class TestRolePromptTemplates:
    """Test suite for RolePromptTemplates functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        with patch('src.prompts.role_templates.get_secure_logger'):
            from src.prompts.role_templates import RolePromptTemplates
            self.templates = RolePromptTemplates()
    
    def test_get_role_prompt_generic(self):
        """Test generic prompt template generation."""
        prompt = self.templates.get_role_prompt(None, {})
        
        assert "cybersecurity" in prompt.lower()
        assert "balanced information" in prompt.lower() or "accurate" in prompt.lower()
        assert "general" in prompt.lower() or "technical audience" in prompt.lower()
    
    def test_get_role_prompt_psirt(self):
        """Test PSIRT-specific prompt template."""
        context = {'cwe_data': {'cwe_id': 'CWE-79', 'name': 'XSS'}}
        prompt = self.templates.get_role_prompt(UserRole.PSIRT, context)
        
        assert "psirt" in prompt.lower() or "incident response" in prompt.lower()
        assert "impact assessment" in prompt.lower()
        assert "advisory language" in prompt.lower()
        assert "risk evaluation" in prompt.lower()
    
    def test_get_role_prompt_developer(self):
        """Test Developer-specific prompt template."""
        context = {'query_type': 'direct_cwe_lookup'}
        prompt = self.templates.get_role_prompt(UserRole.DEVELOPER, context)
        
        assert "code-level remediation" in prompt.lower()
        assert "technical implementation" in prompt.lower()
        assert "secure coding" in prompt.lower()
    
    def test_get_role_prompt_academic(self):
        """Test Academic-specific prompt template."""
        prompt = self.templates.get_role_prompt(UserRole.ACADEMIC, {})
        
        assert "academic" in prompt.lower() or "research" in prompt.lower()
        assert "comprehensive" in prompt.lower()
        assert "taxonomic" in prompt.lower() or "taxonomy" in prompt.lower()
    
    def test_get_role_prompt_bug_bounty(self):
        """Test Bug Bounty-specific prompt template."""
        prompt = self.templates.get_role_prompt(UserRole.BUG_BOUNTY, {})
        
        assert "exploitation" in prompt.lower()
        assert "discovery" in prompt.lower()
        assert "proof-of-concept" in prompt.lower() or "poc" in prompt.lower()
    
    def test_get_role_prompt_product_manager(self):
        """Test Product Manager-specific prompt template."""
        prompt = self.templates.get_role_prompt(UserRole.PRODUCT_MANAGER, {})
        
        assert "business impact" in prompt.lower()
        assert "strategic" in prompt.lower() or "strategy" in prompt.lower()
        assert "resource" in prompt.lower()
    
    def test_get_confidence_guidance_low(self):
        """Test low confidence guidance."""
        guidance = self.templates.get_confidence_guidance_prompt(0.2)
        
        assert "low confidence" in guidance.lower()
        assert "refine their query" in guidance.lower()
        assert "limitations" in guidance.lower()
    
    def test_get_confidence_guidance_moderate(self):
        """Test moderate confidence guidance."""
        guidance = self.templates.get_confidence_guidance_prompt(0.5)
        
        assert "moderate confidence" in guidance.lower()
        assert "uncertainty" in guidance.lower()
    
    def test_get_confidence_guidance_high(self):
        """Test high confidence guidance."""
        guidance = self.templates.get_confidence_guidance_prompt(0.9)
        
        assert "high confidence" in guidance.lower()
        assert "comprehensive information" in guidance.lower()
    
    def test_get_citation_instructions(self):
        """Test citation instructions generation."""
        instructions = self.templates.get_citation_instructions()
        
        assert "according to cwe" in instructions.lower()
        assert "based on cwe data" in instructions.lower()
        assert "distinguish between" in instructions.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])