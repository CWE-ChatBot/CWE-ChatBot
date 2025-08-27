"""
Unit tests for Story 2.2 CWE Relationship Manager components.

Tests comprehensive CWE data retrieval and relationship management functionality.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Optional

from src.retrieval.cwe_relationship_manager import CWERelationshipManager
from src.retrieval.base_retriever import CWEResult


class TestCWERelationshipManager:
    """Test CWE relationship management functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Mock the hybrid RAG manager
        self.mock_hybrid_rag = Mock()
        self.relationship_manager = CWERelationshipManager(self.mock_hybrid_rag)
        
        # Sample comprehensive CWE result
        self.sample_comprehensive_result = CWEResult(
            cwe_id='CWE-79',
            name='Cross-site Scripting (XSS)',
            description='The software does not neutralize user input',
            confidence_score=1.0,
            extended_description='Detailed description of XSS vulnerabilities and their mechanisms.',
            abstraction='Base',
            status='Stable',
            relationships={
                'ChildOf': ['CWE-20', 'CWE-707'],
                'ParentOf': ['CWE-80', 'CWE-81'],
                'CanPrecede': ['CWE-94']
            },
            consequences=[
                {'scope': 'Confidentiality', 'impact': 'Information disclosure'},
                {'scope': 'Integrity', 'impact': 'Data modification'},
                {'scope': 'Availability', 'impact': 'System disruption'}
            ]
        )
    
    def test_initialization(self):
        """Test CWERelationshipManager initialization."""
        manager = CWERelationshipManager(self.mock_hybrid_rag)
        assert manager.hybrid_rag_manager == self.mock_hybrid_rag
        assert hasattr(manager, '_relationship_cache')
        assert hasattr(manager, '_mock_relationships')
        assert hasattr(manager, '_mock_consequences')
    
    def test_get_comprehensive_cwe_success(self):
        """Test successful comprehensive CWE data retrieval."""
        # Mock the hybrid RAG manager response
        base_result = CWEResult(
            cwe_id='CWE-79',
            name='Cross-site Scripting (XSS)',
            description='The software does not neutralize user input',
            confidence_score=1.0
        )
        self.mock_hybrid_rag.search_direct.return_value = [base_result]
        
        result = self.relationship_manager.get_comprehensive_cwe('CWE-79')
        
        assert result is not None
        assert result.cwe_id == 'CWE-79'
        assert result.name == 'Cross-site Scripting (XSS)'
        assert result.extended_description is not None
        assert result.relationships is not None
        assert result.consequences is not None
        assert result.abstraction is not None
        assert result.status is not None
        
        # Verify hybrid RAG was called correctly
        self.mock_hybrid_rag.search_direct.assert_called_once_with('CWE-79')
    
    def test_get_comprehensive_cwe_not_found(self):
        """Test comprehensive CWE data retrieval when CWE not found."""
        self.mock_hybrid_rag.search_direct.return_value = []
        
        result = self.relationship_manager.get_comprehensive_cwe('CWE-999999')
        
        assert result is None
        self.mock_hybrid_rag.search_direct.assert_called_once_with('CWE-999999')
    
    def test_get_comprehensive_cwe_with_cache(self):
        """Test comprehensive CWE retrieval uses caching."""
        base_result = CWEResult(
            cwe_id='CWE-79',
            name='XSS',
            description='XSS description',
            confidence_score=1.0
        )
        self.mock_hybrid_rag.search_direct.return_value = [base_result]
        
        # First call
        result1 = self.relationship_manager.get_comprehensive_cwe('CWE-79')
        
        # Second call should use cache
        result2 = self.relationship_manager.get_comprehensive_cwe('CWE-79')
        
        assert result1.cwe_id == result2.cwe_id
        # Should only call hybrid RAG once due to caching
        assert self.mock_hybrid_rag.search_direct.call_count == 1
    
    def test_enhance_with_relationships(self):
        """Test enhancement of CWE result with relationship data."""
        base_result = CWEResult(
            cwe_id='CWE-79',
            name='XSS',
            description='XSS description',
            confidence_score=1.0
        )
        
        enhanced_result = self.relationship_manager._enhance_with_relationships(base_result)
        
        assert enhanced_result.cwe_id == 'CWE-79'
        assert enhanced_result.extended_description is not None
        assert enhanced_result.relationships is not None
        assert enhanced_result.consequences is not None
        assert enhanced_result.abstraction in ['Base', 'Variant', 'Class', 'Pillar']
        assert enhanced_result.status in ['Stable', 'Draft', 'Deprecated']
    
    def test_get_mock_relationships_known_cwe(self):
        """Test mock relationship generation for known CWE patterns."""
        # Test XSS CWE
        relationships = self.relationship_manager._get_mock_relationships('CWE-79')
        
        assert isinstance(relationships, dict)
        assert 'ChildOf' in relationships
        assert 'ParentOf' in relationships
        assert len(relationships['ChildOf']) > 0
        assert len(relationships['ParentOf']) > 0
        
        # Verify realistic relationships
        child_relationships = relationships['ChildOf']
        assert any('CWE-20' in rel for rel in child_relationships)  # Input validation
    
    def test_get_mock_relationships_unknown_cwe(self):
        """Test mock relationship generation for unknown CWE."""
        relationships = self.relationship_manager._get_mock_relationships('CWE-999999')
        
        assert isinstance(relationships, dict)
        assert 'ChildOf' in relationships
        assert len(relationships['ChildOf']) >= 1  # Should have at least generic parent
    
    def test_get_mock_consequences_known_cwe(self):
        """Test mock consequence generation for known CWE patterns."""
        consequences = self.relationship_manager._get_mock_consequences('CWE-89')  # SQL Injection
        
        assert isinstance(consequences, list)
        assert len(consequences) > 0
        
        # Check consequence structure
        for consequence in consequences:
            assert 'scope' in consequence
            assert 'impact' in consequence
            assert consequence['scope'] in ['Confidentiality', 'Integrity', 'Availability', 'Access Control']
    
    def test_get_mock_consequences_unknown_cwe(self):
        """Test mock consequence generation for unknown CWE."""
        consequences = self.relationship_manager._get_mock_consequences('CWE-999999')
        
        assert isinstance(consequences, list)
        assert len(consequences) >= 2  # Should have at least generic consequences
        
        # Should include generic security impacts
        scopes = [c['scope'] for c in consequences]
        assert 'Confidentiality' in scopes or 'Integrity' in scopes
    
    def test_generate_extended_description(self):
        """Test extended description generation."""
        base_result = CWEResult(
            cwe_id='CWE-79',
            name='Cross-site Scripting',
            description='Basic XSS description',
            confidence_score=1.0
        )
        
        extended_desc = self.relationship_manager._generate_extended_description(base_result)
        
        assert isinstance(extended_desc, str)
        assert len(extended_desc) > len(base_result.description)
        assert base_result.name in extended_desc
        assert 'vulnerability' in extended_desc.lower()
    
    def test_determine_abstraction_level(self):
        """Test abstraction level determination."""
        # Test different CWE ID patterns
        assert self.relationship_manager._determine_abstraction_level('CWE-79') in ['Base', 'Variant', 'Class', 'Pillar']
        assert self.relationship_manager._determine_abstraction_level('CWE-20') == 'Class'  # Input validation
        assert self.relationship_manager._determine_abstraction_level('CWE-999999') in ['Base', 'Variant']
    
    def test_determine_status(self):
        """Test status determination."""
        status = self.relationship_manager._determine_status('CWE-79')
        assert status in ['Stable', 'Draft', 'Deprecated']
        
        # Most CWEs should be stable
        stable_count = 0
        for i in range(10):
            status = self.relationship_manager._determine_status(f'CWE-{i}')
            if status == 'Stable':
                stable_count += 1
        
        assert stable_count > 5  # Most should be stable
    
    def test_cache_management(self):
        """Test cache management functionality."""
        base_result = CWEResult(
            cwe_id='CWE-79',
            name='XSS',
            description='XSS description',
            confidence_score=1.0
        )
        self.mock_hybrid_rag.search_direct.return_value = [base_result]
        
        # Fill cache
        self.relationship_manager.get_comprehensive_cwe('CWE-79')
        assert 'CWE-79' in self.relationship_manager._relationship_cache
        
        # Test cache hit
        cached_result = self.relationship_manager.get_comprehensive_cwe('CWE-79')
        assert cached_result.cwe_id == 'CWE-79'
        
        # Should still only have called hybrid RAG once
        assert self.mock_hybrid_rag.search_direct.call_count == 1
    
    def test_error_handling_hybrid_rag_failure(self):
        """Test error handling when hybrid RAG fails."""
        self.mock_hybrid_rag.search_direct.side_effect = Exception("Database error")
        
        result = self.relationship_manager.get_comprehensive_cwe('CWE-79')
        
        # Should handle error gracefully and return None
        assert result is None
    
    def test_error_handling_invalid_cwe_id(self):
        """Test error handling with invalid CWE ID."""
        # Test with None
        result = self.relationship_manager.get_comprehensive_cwe(None)
        assert result is None
        
        # Test with empty string
        result = self.relationship_manager.get_comprehensive_cwe('')
        assert result is None
        
        # Test with invalid format
        result = self.relationship_manager.get_comprehensive_cwe('invalid-cwe')
        assert result is None
    
    def test_relationship_data_consistency(self):
        """Test consistency of relationship data generation."""
        # Generate relationships multiple times for the same CWE
        rel1 = self.relationship_manager._get_mock_relationships('CWE-79')
        rel2 = self.relationship_manager._get_mock_relationships('CWE-79')
        
        # Should be consistent (same CWE should generate same relationships)
        assert rel1 == rel2
    
    def test_consequence_data_consistency(self):
        """Test consistency of consequence data generation."""
        # Generate consequences multiple times for the same CWE
        cons1 = self.relationship_manager._get_mock_consequences('CWE-79')
        cons2 = self.relationship_manager._get_mock_consequences('CWE-79')
        
        # Should be consistent
        assert cons1 == cons2
    
    def test_mock_data_quality(self):
        """Test quality and realism of mock data generation."""
        result = self.relationship_manager.get_comprehensive_cwe('CWE-89')  # SQL Injection
        
        if result:
            # Verify relationships make sense for SQL injection
            if result.relationships:
                child_relationships = result.relationships.get('ChildOf', [])
                # Should include input validation as parent
                assert any('20' in rel for rel in child_relationships)
            
            # Verify consequences make sense for SQL injection
            if result.consequences:
                scopes = [c['scope'] for c in result.consequences]
                impacts = [c['impact'] for c in result.consequences]
                
                # SQL injection typically affects confidentiality and integrity
                assert 'Confidentiality' in scopes or 'Integrity' in scopes
                assert any('database' in impact.lower() or 'data' in impact.lower() for impact in impacts)


@pytest.mark.integration
class TestCWERelationshipManagerIntegration:
    """Integration tests for CWE relationship manager."""
    
    def setup_method(self):
        """Set up integration test fixtures."""
        self.mock_hybrid_rag = Mock()
        self.relationship_manager = CWERelationshipManager(self.mock_hybrid_rag)
    
    def test_comprehensive_data_retrieval_workflow(self):
        """Test complete comprehensive data retrieval workflow."""
        # Setup mock responses
        base_results = [
            CWEResult(cwe_id='CWE-79', name='XSS', description='XSS desc', confidence_score=1.0),
            CWEResult(cwe_id='CWE-89', name='SQL Injection', description='SQL desc', confidence_score=1.0),
            CWEResult(cwe_id='CWE-120', name='Buffer Overflow', description='Buffer desc', confidence_score=1.0)
        ]
        
        self.mock_hybrid_rag.search_direct.side_effect = lambda cwe_id: [
            next((result for result in base_results if result.cwe_id == cwe_id), None)
        ]
        
        # Test retrieval of multiple CWEs
        test_cwes = ['CWE-79', 'CWE-89', 'CWE-120']
        comprehensive_results = []
        
        for cwe_id in test_cwes:
            result = self.relationship_manager.get_comprehensive_cwe(cwe_id)
            assert result is not None
            assert result.cwe_id == cwe_id
            assert result.extended_description is not None
            assert result.relationships is not None
            assert result.consequences is not None
            comprehensive_results.append(result)
        
        # Verify each result is properly enhanced
        for result in comprehensive_results:
            assert len(result.extended_description) > len(result.description)
            assert len(result.relationships) > 0
            assert len(result.consequences) > 0
            assert result.abstraction in ['Base', 'Variant', 'Class', 'Pillar']
            assert result.status in ['Stable', 'Draft', 'Deprecated']
    
    def test_caching_performance(self):
        """Test caching improves performance."""
        base_result = CWEResult(
            cwe_id='CWE-79',
            name='XSS',
            description='XSS description',
            confidence_score=1.0
        )
        self.mock_hybrid_rag.search_direct.return_value = [base_result]
        
        # First retrieval - should call hybrid RAG
        start_calls = self.mock_hybrid_rag.search_direct.call_count
        result1 = self.relationship_manager.get_comprehensive_cwe('CWE-79')
        assert self.mock_hybrid_rag.search_direct.call_count == start_calls + 1
        
        # Second retrieval - should use cache
        result2 = self.relationship_manager.get_comprehensive_cwe('CWE-79')
        assert self.mock_hybrid_rag.search_direct.call_count == start_calls + 1  # No additional call
        
        # Results should be equivalent
        assert result1.cwe_id == result2.cwe_id
        assert result1.extended_description == result2.extended_description
    
    def test_error_recovery(self):
        """Test error recovery and graceful degradation."""
        # Test various error conditions
        error_conditions = [
            Exception("Network error"),
            ValueError("Invalid data"),
            KeyError("Missing field"),
            None  # No exception, but empty result
        ]
        
        for i, error in enumerate(error_conditions[:-1]):
            self.mock_hybrid_rag.search_direct.side_effect = error
            result = self.relationship_manager.get_comprehensive_cwe(f'CWE-{i}')
            assert result is None  # Should handle errors gracefully
        
        # Test empty result
        self.mock_hybrid_rag.search_direct.side_effect = None
        self.mock_hybrid_rag.search_direct.return_value = []
        result = self.relationship_manager.get_comprehensive_cwe('CWE-999')
        assert result is None
    
    def test_realistic_relationship_patterns(self):
        """Test that generated relationships follow realistic patterns."""
        # Test common vulnerability patterns
        common_cwes = ['CWE-79', 'CWE-89', 'CWE-120', 'CWE-20', 'CWE-200']
        
        for cwe_id in common_cwes:
            base_result = CWEResult(
                cwe_id=cwe_id,
                name=f'Test {cwe_id}',
                description=f'Description for {cwe_id}',
                confidence_score=1.0
            )
            self.mock_hybrid_rag.search_direct.return_value = [base_result]
            
            result = self.relationship_manager.get_comprehensive_cwe(cwe_id)
            
            if result and result.relationships:
                # Verify relationship structure
                for rel_type, related_cwes in result.relationships.items():
                    assert rel_type in ['ChildOf', 'ParentOf', 'CanPrecede', 'CanFollow', 'PeerOf']
                    assert isinstance(related_cwes, list)
                    
                    # All related CWEs should be valid format
                    for related_cwe in related_cwes:
                        assert related_cwe.startswith('CWE-')
                        assert related_cwe != cwe_id  # Should not reference itself