# apps/cwe_ingestion/embedder.py
"""
Local embedding model for CWE text using sentence transformers.
Handles optional dependency gracefully.
"""
import logging
import numpy as np
from typing import List, Union, Optional

logger = logging.getLogger(__name__)


class CWEEmbedder:
    """Local sentence transformer for generating CWE embeddings."""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.is_local_model = True
        self.api_key = None  # No API key needed for local model
        self.model = None
        self.embedding_dimension = 384  # Default for MiniLM
        
        try:
            logger.info(f"Attempting to load embedding model: {model_name}")
            self._load_model()
            logger.info(f"Model loaded successfully. Dimension: {self.embedding_dimension}")
        except ImportError as e:
            logger.warning(f"sentence-transformers not available: {e}")
            logger.info("Using mock embedder for testing/development")
            self._use_mock_embedder()
        except Exception as e:
            logger.error(f"Failed to load embedding model: {e}")
            logger.info("Falling back to mock embedder")
            self._use_mock_embedder()
    
    def _load_model(self):
        """Load the sentence transformer model."""
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(self.model_name)
        self.embedding_dimension = self.model.get_sentence_embedding_dimension()
    
    def _use_mock_embedder(self):
        """Use mock embedder for testing when sentence-transformers is not available."""
        self.model = None
        self.embedding_dimension = 384  # Mock dimension
        logger.info("Using mock embedder - embeddings will be random vectors")
    
    def embed_text(self, text: str) -> np.ndarray:
        """
        Generate embedding for a single text.
        
        Args:
            text: Input text to embed
            
        Returns:
            numpy array containing the embedding vector
        """
        if text is None:
            raise ValueError("Text cannot be None")
        
        try:
            if not text or not text.strip():
                logger.warning("Empty text provided for embedding")
                return np.zeros(self.embedding_dimension, dtype=np.float32)
            
            if self.model is not None:
                # Use real sentence transformer
                embedding = self.model.encode(text.strip(), convert_to_numpy=True)
                return embedding
            else:
                # Use mock embedder for testing
                return self._generate_mock_embedding(text)
                
        except Exception as e:
            logger.error(f"Failed to generate embedding: {e}")
            raise
    
    def embed_batch(self, texts: List[str]) -> List[np.ndarray]:
        """
        Generate embeddings for multiple texts efficiently.
        
        Args:
            texts: List of texts to embed
            
        Returns:
            List of numpy arrays containing embedding vectors
        """
        try:
            if not texts:
                return []
            
            # Filter valid texts
            valid_texts = [text.strip() for text in texts if text and text.strip()]
            
            if not valid_texts:
                logger.warning("No valid texts provided for batch embedding")
                return [np.zeros(self.embedding_dimension, dtype=np.float32) for _ in texts]
            
            if self.model is not None:
                # Use real sentence transformer
                logger.info(f"Generating embeddings for {len(valid_texts)} texts")
                embeddings = self.model.encode(valid_texts, convert_to_numpy=True, show_progress_bar=True)
                return [emb for emb in embeddings]
            else:
                # Use mock embedder
                return [self._generate_mock_embedding(text) for text in valid_texts]
            
        except Exception as e:
            logger.error(f"Failed to generate batch embeddings: {e}")
            raise
    
    def _generate_mock_embedding(self, text: str) -> np.ndarray:
        """Generate deterministic mock embedding for testing."""
        # Use hash of text to generate consistent embeddings
        text_hash = hash(text) % (2**32)
        np.random.seed(text_hash)
        embedding = np.random.rand(self.embedding_dimension).astype(np.float32)
        # Normalize to unit vector
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm
        return embedding
    
    def get_embedding_dimension(self) -> int:
        """Get the dimension of the embedding vectors."""
        return self.embedding_dimension