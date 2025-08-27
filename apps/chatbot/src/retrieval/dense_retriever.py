"""
Dense vector retriever using PostgreSQL with pgvector extension.
Implements semantic search using OpenAI text-embedding-3-small embeddings.
"""

import logging
import os
from typing import List, Dict, Any, Optional
import psycopg2
from pgvector.psycopg2 import register_vector
from psycopg2 import sql

from .base_retriever import ChatBotBaseRetriever, CWEResult
from ..processing.embedding_service import EmbeddingService
from .secure_query_builder import SecureQueryBuilder


logger = logging.getLogger(__name__)


class ChatBotDenseRetriever(ChatBotBaseRetriever):
    """
    Dense vector retriever using PostgreSQL with pgvector.
    
    Performs semantic search using vector similarity with pgvector extension.
    """
    
    def __init__(
        self, 
        pg_config: Dict[str, str],
        embedding_service: Optional[EmbeddingService] = None
    ):
        """
        Initialize the dense retriever.
        
        Args:
            pg_config: PostgreSQL connection configuration
            embedding_service: Service for generating embeddings
        """
        self.pg_config = pg_config
        self.connection = None
        self.table_name = "cwe_embeddings"
        self.embedding_model = "text-embedding-3-small"
        self.embedding_dimensions = 1536
        
        # Initialize secure query builder
        self.query_builder = SecureQueryBuilder()
        
        # Initialize embedding service
        if embedding_service is None:
            self.embedding_service = EmbeddingService()
        else:
            self.embedding_service = embedding_service
        
        # Initialize database connection
        self._connect()
        logger.info("Initialized ChatBotDenseRetriever with pgvector")
    
    def _connect(self) -> None:
        """Establish connection to PostgreSQL database."""
        try:
            self.connection = psycopg2.connect(**self.pg_config)
            register_vector(self.connection)
            logger.info("Connected to PostgreSQL database with pgvector extension")
        except psycopg2.Error as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            raise ConnectionError(f"Database connection failed: {e}")
    
    def _ensure_connection(self) -> None:
        """Ensure database connection is active."""
        if self.connection is None or self.connection.closed:
            logger.warning("Database connection lost, reconnecting...")
            self._connect()
    
    def search(self, query: str, k: int = 5, **kwargs) -> List[CWEResult]:
        """
        Perform semantic search using vector similarity.
        
        Args:
            query: Search query string
            k: Number of results to return
            **kwargs: Additional search parameters (threshold, etc.)
            
        Returns:
            List of CWEResult objects ranked by similarity
        """
        if not query or not query.strip():
            return []
        
        try:
            # Generate query embedding
            query_embedding = self.embedding_service.embed_query(query.strip())
            
            # Perform vector similarity search
            return self._vector_search(query_embedding, k, **kwargs)
            
        except Exception as e:
            logger.error(f"Dense retrieval failed: {e}")
            return []
    
    def _vector_search(
        self, 
        query_embedding: List[float], 
        k: int = 5,
        threshold: float = 0.1
    ) -> List[CWEResult]:
        """
        Perform vector similarity search in PostgreSQL.
        
        Args:
            query_embedding: Query embedding vector
            k: Number of results to return
            threshold: Minimum similarity threshold
            
        Returns:
            List of CWEResult objects
        """
        self._ensure_connection()
        
        try:
            with self.connection.cursor() as cursor:
                # Build secure SQL query with proper table name validation
                secure_query = self.query_builder.build_vector_similarity_query(self.table_name)
                
                cursor.execute(secure_query, (
                    query_embedding,  # For similarity calculation
                    query_embedding,  # For threshold filter
                    threshold,        # Similarity threshold
                    query_embedding,  # For ordering
                    k                 # Limit
                ))
                
                results = cursor.fetchall()
                
                # Convert to CWEResult objects
                cwe_results = []
                for row in results:
                    cwe_id, name, description, similarity_score, metadata = row
                    
                    cwe_result = CWEResult(
                        cwe_id=cwe_id,
                        name=name or "",
                        description=description or "",
                        confidence_score=float(similarity_score),
                        source_method="dense",
                        metadata=metadata or {}
                    )
                    cwe_results.append(cwe_result)
                
                logger.debug(f"Dense search returned {len(cwe_results)} results")
                return cwe_results
                
        except psycopg2.Error as e:
            logger.error(f"Vector search query failed: {e}")
            return []
    
    def get_by_id(self, cwe_id: str) -> Optional[CWEResult]:
        """
        Get specific CWE by ID using direct database lookup.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-79")
            
        Returns:
            CWEResult if found, None otherwise
        """
        if not cwe_id:
            return None
        
        self._ensure_connection()
        
        try:
            with self.connection.cursor() as cursor:
                # Build secure direct lookup query with proper table name validation
                secure_query = self.query_builder.build_direct_cwe_lookup_query(self.table_name)
                
                cursor.execute(secure_query, (cwe_id,))
                row = cursor.fetchone()
                
                if row:
                    cwe_id, name, description, confidence_score, metadata = row
                    return CWEResult(
                        cwe_id=cwe_id,
                        name=name or "",
                        description=description or "",
                        confidence_score=confidence_score,  # From query (1.0 for direct lookup)
                        source_method="direct",
                        metadata=metadata or {}
                    )
                
                return None
                
        except psycopg2.Error as e:
            logger.error(f"Direct lookup query failed: {e}")
            return None
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get retriever metadata for evaluation."""
        self._ensure_connection()
        
        try:
            with self.connection.cursor() as cursor:
                # Get table statistics
                cursor.execute(f"SELECT COUNT(*) FROM {self.table_name};")
                total_entries = cursor.fetchone()[0]
                
                return {
                    "retriever_type": "dense",
                    "method": "pgvector_similarity",
                    "embedding_model": self.embedding_model,
                    "embedding_dimensions": self.embedding_dimensions,
                    "total_entries": total_entries,
                    "table_name": self.table_name
                }
        except psycopg2.Error as e:
            logger.error(f"Failed to get metadata: {e}")
            return {
                "retriever_type": "dense",
                "method": "pgvector_similarity",
                "embedding_model": self.embedding_model,
                "embedding_dimensions": self.embedding_dimensions,
                "error": str(e)
            }
    
    def __del__(self):
        """Clean up database connection."""
        if hasattr(self, 'connection') and self.connection:
            try:
                self.connection.close()
            except:
                pass  # Ignore errors during cleanup