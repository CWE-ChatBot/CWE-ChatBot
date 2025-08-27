"""
CWE Relationship Manager for Story 2.2 - Enhanced Database Retrieval with Relationships

This module handles comprehensive CWE data retrieval including relationships between CWEs,
consequences, and extended metadata for contextual responses.
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
import psycopg2
from psycopg2.extras import RealDictCursor
from pgvector.psycopg2 import register_vector

from .base_retriever import CWEResult

logger = logging.getLogger(__name__)


class CWERelationshipManager:
    """
    Manages enhanced CWE data retrieval with relationships and comprehensive metadata.
    
    This class extends basic CWE retrieval to include:
    - CWE relationships (ChildOf, ParentOf, etc.)
    - Extended descriptions and consequences
    - Related CWE discovery
    - Comprehensive metadata for contextual responses
    """
    
    def __init__(self, pg_config: Dict[str, Any]):
        """
        Initialize relationship manager with PostgreSQL configuration.
        
        Args:
            pg_config: PostgreSQL connection configuration
        """
        self.pg_config = pg_config
        self.connection = None
        self._connect_database()
    
    def _connect_database(self) -> None:
        """Establish connection to PostgreSQL database with pgvector support."""
        try:
            self.connection = psycopg2.connect(**self.pg_config)
            register_vector(self.connection)
            logger.info("✅ CWE Relationship Manager connected to database")
        except Exception as e:
            logger.error(f"❌ Failed to connect to database: {e}")
            raise
    
    def get_comprehensive_cwe_data(self, cwe_id: str) -> Optional[CWEResult]:
        """
        Retrieve comprehensive CWE data including all relationships and metadata.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-79")
            
        Returns:
            CWEResult with comprehensive data or None if not found
        """
        if not self.connection:
            logger.error("No database connection available")
            return None
        
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Query for comprehensive CWE data
                cursor.execute("""
                    SELECT 
                        cwe_id,
                        name,
                        description,
                        extended_description,
                        abstraction,
                        status,
                        full_text
                    FROM cwe_embeddings
                    WHERE cwe_id = %s;
                """, (cwe_id,))
                
                row = cursor.fetchone()
                if not row:
                    logger.warning(f"CWE {cwe_id} not found in database")
                    return None
                
                # For now, create mock relationship data since it's not in current schema
                # TODO: Update when real CWE relationship data is available
                mock_relationships = self._get_mock_relationships(cwe_id)
                mock_consequences = self._get_mock_consequences(cwe_id)
                
                return CWEResult(
                    cwe_id=row['cwe_id'],
                    name=row['name'],
                    description=row['description'],
                    confidence_score=1.0,  # Direct lookup = 100% confidence
                    source_method='direct_comprehensive',
                    metadata={'retrieval_type': 'comprehensive'},
                    extended_description=row['extended_description'],
                    abstraction=row['abstraction'],
                    status=row['status'],
                    relationships=mock_relationships,
                    consequences=mock_consequences
                )
                
        except Exception as e:
            logger.error(f"Error retrieving comprehensive CWE data for {cwe_id}: {e}")
            return None
    
    def get_related_cwes(self, cwe_id: str, relationship_type: str = "ChildOf") -> List[CWEResult]:
        """
        Get CWEs related by specific relationship types.
        
        Args:
            cwe_id: Source CWE identifier
            relationship_type: Type of relationship to follow ("ChildOf", "ParentOf", "PeerOf")
            
        Returns:
            List of related CWEResult objects
        """
        if not self.connection:
            logger.error("No database connection available")
            return []
        
        # For now, return mock related CWEs based on patterns
        # TODO: Implement actual relationship queries when data is available
        mock_related = self._get_mock_related_cwes(cwe_id, relationship_type)
        
        related_cwes = []
        for related_cwe_id in mock_related:
            cwe_result = self.get_comprehensive_cwe_data(related_cwe_id)
            if cwe_result:
                related_cwes.append(cwe_result)
        
        logger.info(f"Found {len(related_cwes)} related CWEs for {cwe_id} ({relationship_type})")
        return related_cwes
    
    def find_similar_cwes_by_vector(self, cwe_id: str, k: int = 5) -> List[CWEResult]:
        """
        Find similar CWEs using vector similarity search.
        
        Args:
            cwe_id: Source CWE identifier
            k: Number of similar CWEs to return
            
        Returns:
            List of similar CWEResult objects
        """
        if not self.connection:
            logger.error("No database connection available")
            return []
        
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # First get the embedding of the source CWE
                cursor.execute("""
                    SELECT embedding FROM cwe_embeddings WHERE cwe_id = %s;
                """, (cwe_id,))
                
                source_row = cursor.fetchone()
                if not source_row or not source_row['embedding']:
                    logger.warning(f"No embedding found for {cwe_id}")
                    return []
                
                # Find similar CWEs using cosine similarity
                cursor.execute("""
                    SELECT 
                        cwe_id,
                        name,
                        description,
                        extended_description,
                        abstraction,
                        status,
                        (embedding <=> %s) as distance
                    FROM cwe_embeddings
                    WHERE cwe_id != %s
                    ORDER BY embedding <=> %s
                    LIMIT %s;
                """, (source_row['embedding'], cwe_id, source_row['embedding'], k))
                
                rows = cursor.fetchall()
                
                similar_cwes = []
                for row in rows:
                    # Convert distance to confidence score (lower distance = higher confidence)
                    confidence_score = max(0.0, 1.0 - row['distance'])
                    
                    similar_cwes.append(CWEResult(
                        cwe_id=row['cwe_id'],
                        name=row['name'],
                        description=row['description'],
                        confidence_score=confidence_score,
                        source_method='vector_similarity',
                        metadata={
                            'similarity_distance': row['distance'],
                            'source_cwe': cwe_id
                        },
                        extended_description=row['extended_description'],
                        abstraction=row['abstraction'],
                        status=row['status'],
                        relationships=self._get_mock_relationships(row['cwe_id']),
                        consequences=self._get_mock_consequences(row['cwe_id'])
                    ))
                
                logger.info(f"Found {len(similar_cwes)} similar CWEs for {cwe_id}")
                return similar_cwes
                
        except Exception as e:
            logger.error(f"Error finding similar CWEs for {cwe_id}: {e}")
            return []
    
    def _get_mock_relationships(self, cwe_id: str) -> Dict[str, List[str]]:
        """
        Generate mock relationship data based on CWE patterns.
        TODO: Replace with actual relationship data from CWE corpus.
        """
        relationships = {}
        
        # Common patterns for mock relationships
        if cwe_id == "CWE-79":  # XSS
            relationships = {
                "ChildOf": ["CWE-20"],  # Improper Input Validation
                "ParentOf": ["CWE-80", "CWE-81"],  # More specific XSS types
                "CanPrecede": ["CWE-352"]  # CSRF
            }
        elif cwe_id == "CWE-89":  # SQL Injection
            relationships = {
                "ChildOf": ["CWE-20"],  # Improper Input Validation
                "ParentOf": ["CWE-564"],  # SQL Injection: Hibernate
                "PeerOf": ["CWE-78"]  # OS Command Injection
            }
        elif cwe_id == "CWE-20":  # Improper Input Validation
            relationships = {
                "ParentOf": ["CWE-79", "CWE-89", "CWE-78"],
                "MemberOf": ["CWE-1003"]  # Weaknesses for Simplified Mapping
            }
        elif cwe_id == "CWE-120":  # Buffer Overflow
            relationships = {
                "ChildOf": ["CWE-119"],  # Improper Restriction of Operations
                "ParentOf": ["CWE-121", "CWE-122"],  # Stack/Heap buffer overflow
            }
        
        return relationships
    
    def _get_mock_consequences(self, cwe_id: str) -> List[Dict[str, str]]:
        """
        Generate mock consequence data based on CWE patterns.
        TODO: Replace with actual consequence data from CWE corpus.
        """
        consequences = []
        
        if cwe_id == "CWE-79":  # XSS
            consequences = [
                {"scope": "Confidentiality", "impact": "Read Application Data"},
                {"scope": "Integrity", "impact": "Execute Unauthorized Code or Commands"},
                {"scope": "Access Control", "impact": "Bypass Protection Mechanism"}
            ]
        elif cwe_id == "CWE-89":  # SQL Injection
            consequences = [
                {"scope": "Confidentiality", "impact": "Read Application Data"},
                {"scope": "Integrity", "impact": "Modify Application Data"},
                {"scope": "Authorization", "impact": "Bypass Protection Mechanism"}
            ]
        elif cwe_id == "CWE-120":  # Buffer Overflow
            consequences = [
                {"scope": "Integrity", "impact": "Modify Memory"},
                {"scope": "Availability", "impact": "DoS: Crash, Exit, or Restart"},
                {"scope": "Confidentiality", "impact": "Execute Unauthorized Code"}
            ]
        
        return consequences
    
    def _get_mock_related_cwes(self, cwe_id: str, relationship_type: str) -> List[str]:
        """
        Generate mock related CWE IDs based on relationship type.
        TODO: Replace with actual relationship queries.
        """
        relationships = self._get_mock_relationships(cwe_id)
        return relationships.get(relationship_type, [])
    
    def close(self) -> None:
        """Close database connection."""
        if self.connection:
            self.connection.close()
            logger.info("CWE Relationship Manager connection closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()