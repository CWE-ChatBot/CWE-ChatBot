"""
OpenAI embedding service for generating query embeddings.
Follows ADR specification for text-embedding-3-small (1536 dimensions).
"""

import logging
import os
from typing import List, Optional
import openai
from openai import OpenAI


logger = logging.getLogger(__name__)


class EmbeddingService:
    """
    Service for generating embeddings using OpenAI text-embedding-3-small.
    
    Following the Embedding Model ADR decision for consistent production deployment.
    """
    
    # Model configuration from ADR
    DEFAULT_MODEL = "text-embedding-3-small"
    DEFAULT_DIMENSIONS = 1536
    
    def __init__(
        self, 
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        dimensions: int = DEFAULT_DIMENSIONS
    ):
        """
        Initialize the embedding service.
        
        Args:
            api_key: OpenAI API key (if None, uses OPENAI_API_KEY env var)
            model: OpenAI embedding model name
            dimensions: Number of dimensions for embeddings
        """
        self.model = model
        self.dimensions = dimensions
        
        # Initialize OpenAI client
        api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API key must be provided via parameter or OPENAI_API_KEY environment variable")
        
        self.client = OpenAI(api_key=api_key)
        logger.info(f"Initialized embedding service with model: {model}, dimensions: {dimensions}")
    
    def embed_query(self, query: str) -> List[float]:
        """
        Generate embedding vector for user query.
        
        Args:
            query: User query text to embed
            
        Returns:
            List of float values representing the embedding vector
            
        Raises:
            ValueError: If query is empty or invalid
            openai.APIError: If OpenAI API call fails
        """
        if not query or not isinstance(query, str):
            raise ValueError("Query must be a non-empty string")
        
        query = query.strip()
        if not query:
            raise ValueError("Query cannot be empty after stripping whitespace")
        
        try:
            logger.debug(f"Generating embedding for query of length {len(query)}")
            
            # Make API call to OpenAI
            response = self.client.embeddings.create(
                model=self.model,
                input=query,
                dimensions=self.dimensions
            )
            
            # Extract embedding from response
            embedding = response.data[0].embedding
            
            # Validate embedding dimensions
            if len(embedding) != self.dimensions:
                raise ValueError(f"Expected {self.dimensions} dimensions, got {len(embedding)}")
            
            logger.debug(f"Successfully generated embedding with {len(embedding)} dimensions")
            return embedding
            
        except openai.APIError as e:
            logger.error(f"OpenAI API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error generating embedding: {e}")
            raise
    
    def embed_batch(self, queries: List[str], batch_size: int = 100) -> List[List[float]]:
        """
        Generate embeddings for multiple queries efficiently.
        
        Args:
            queries: List of query strings to embed
            batch_size: Maximum number of queries per API call
            
        Returns:
            List of embedding vectors in same order as input queries
        """
        if not queries:
            return []
        
        embeddings = []
        
        # Process in batches to handle API limits
        for i in range(0, len(queries), batch_size):
            batch = queries[i:i + batch_size]
            
            # Filter out empty queries
            valid_batch = [q.strip() for q in batch if q and q.strip()]
            if not valid_batch:
                # Add empty embeddings for invalid queries
                embeddings.extend([[0.0] * self.dimensions] * len(batch))
                continue
            
            try:
                logger.debug(f"Processing batch of {len(valid_batch)} queries")
                
                response = self.client.embeddings.create(
                    model=self.model,
                    input=valid_batch,
                    dimensions=self.dimensions
                )
                
                # Extract embeddings from response
                batch_embeddings = [item.embedding for item in response.data]
                embeddings.extend(batch_embeddings)
                
            except Exception as e:
                logger.error(f"Batch embedding failed: {e}")
                # Add zero embeddings for failed batch
                embeddings.extend([[0.0] * self.dimensions] * len(batch))
        
        logger.info(f"Generated embeddings for {len(embeddings)} queries")
        return embeddings
    
    def get_model_info(self) -> dict:
        """Get information about the current embedding model configuration."""
        return {
            "model": self.model,
            "dimensions": self.dimensions,
            "provider": "OpenAI"
        }