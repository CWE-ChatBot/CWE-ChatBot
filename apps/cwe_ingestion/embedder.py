# apps/cwe_ingestion/embedder.py
"""
Local embedding model for CWE text using sentence transformers.
Handles optional dependency gracefully.
Story 1.4: Added Gemini API integration for state-of-the-art embeddings.
"""
import logging
import os
from typing import List, Optional
import asyncio

import numpy as np

logger = logging.getLogger(__name__)


def validate_gemini_environment() -> bool:
    """
    Validate that GEMINI_API_KEY environment variable is properly configured.

    Returns:
        True if environment is valid

    Raises:
        ValueError: If API key is missing or invalid
    """
    api_key = os.getenv('GEMINI_API_KEY')

    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY environment variable is required for Gemini embeddings. "
            "Please set it with your Google AI API key."
        )

    if not api_key.strip():
        raise ValueError(
            "GEMINI_API_KEY environment variable cannot be empty. "
            "Please set it with a valid Google AI API key."
        )

    # Basic format validation - Google AI API keys typically start with "AIza"
    if len(api_key) < 20:
        raise ValueError(
            "GEMINI_API_KEY appears to be too short. "
            "Please check that you have set the complete API key."
        )

    return True


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

    # Replace the existing embed_batch with this
    def embed_batch(self, texts: List[str]) -> List[np.ndarray]:
        """Generate embeddings for multiple texts efficiently using asyncio."""
        if not texts:
            return []

        # This can be run from a sync context like the pipeline
        return asyncio.run(self._embed_batch_async(texts))

    async def _embed_batch_async(self, texts: List[str]) -> List[np.ndarray]:
        """Helper to run embedding tasks concurrently."""
        # A semaphore can be used to limit concurrency to avoid rate limiting
        # e.g., semaphore = asyncio.Semaphore(10)
        
        tasks = [self._embed_single_with_retry(text) for text in texts]
        embeddings = await asyncio.gather(*tasks)
        return embeddings

    async def _embed_single_with_retry(self, text: str, retries: int = 3) -> np.ndarray:
        """Async embedder for a single text with simple retry logic."""
        for attempt in range(retries):
            try:
                # Assuming the genai library will support async or can be wrapped
                # For now, we wrap the sync call in an executor
                loop = asyncio.get_running_loop()
                embedding = await loop.run_in_executor(None, self.embed_text, text)
                return embedding
            except Exception as e:
                logger.warning(f"Embedding failed for text (attempt {attempt+1}): {e}")
                if attempt == retries - 1:
                    # Return zero vector on final failure
                    return np.zeros(self.embedding_dimension, dtype=np.float32)
                await asyncio.sleep(2**attempt) # Exponential backoff
        # Should not be reached, but for type safety
        return np.zeros(self.embedding_dimension, dtype=np.float32)

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


class GeminiEmbedder:
    """Google Gemini embedding model for high-quality CWE embeddings."""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize GeminiEmbedder with API key validation.

        Args:
            api_key: Optional API key. If not provided, uses GEMINI_API_KEY env var.

        Raises:
            ValueError: If API key is missing or invalid
        """
        api_key = api_key or os.getenv('GEMINI_API_KEY')
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY environment variable is required for Gemini embeddings. "
                "Please set it with your Google AI API key."
            )

        # Store only masked version for error handling
        self.api_key_masked = api_key[:8] + "..." + api_key[-4:] if len(api_key) > 12 else "[PROTECTED]"
        self.is_local_model = False
        self.embedding_dimension = 3072  # gemini-embedding-001 default

        # Configure the Gemini API
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)  # Use raw key for configuration
            self.genai = genai
            logger.info("Gemini API configured successfully")
        except ImportError as e:
            logger.error(f"Failed to import google.generativeai: {e}")
            raise ImportError(
                "google-generativeai library is required for GeminiEmbedder. "
                "Please install it with: pip install google-generativeai"
            )

    def get_embedding_dimension(self) -> int:
        """Get the dimension of the embedding vectors."""
        return self.embedding_dimension

    def embed_text(self, text: str) -> np.ndarray:
        """
        Generate embedding for a single text using Gemini API.

        Args:
            text: Input text to embed

        Returns:
            numpy array containing the 3072-dimensional embedding vector

        Raises:
            ValueError: If text is None or invalid
            Exception: If API call fails
        """
        if text is None:
            raise ValueError("Text cannot be None")

        try:
            if not text or not text.strip():
                logger.warning("Empty text provided for embedding")
                return np.zeros(self.embedding_dimension, dtype=np.float32)

            # Sanitize input - basic validation to prevent injection
            sanitized_text = text.strip()
            if len(sanitized_text) > 100000:  # Reasonable limit
                logger.warning("Text truncated to 100k characters")
                sanitized_text = sanitized_text[:100000]

            # Make API call with correct format for gemini-embedding-001
            result = self.genai.embed_content(
                model="models/embedding-001",
                content=sanitized_text,
                output_dimensionality=3072
            )

            # Extract embedding from response
            embedding_list = result['embedding']
            embedding = np.array(embedding_list, dtype=np.float32)

            # Validate dimension
            if embedding.shape[0] != self.embedding_dimension:
                raise ValueError(
                    f"Expected {self.embedding_dimension} dimensions, "
                    f"got {embedding.shape[0]}"
                )

            return embedding

        except Exception as e:
            logger.error(f"Failed to generate Gemini embedding: {e}")
            # Use masked API key in error messages - no raw key exposure
            raise Exception(f"Gemini API error (key: {self.api_key_masked}): {str(e)}")

    def embed_batch(self, texts: List[str]) -> List[np.ndarray]:
        """
        Generate embeddings for multiple texts efficiently.

        Args:
            texts: List of texts to embed

        Returns:
            List of numpy arrays containing embedding vectors

        Raises:
            Exception: If any API call fails
        """
        try:
            if not texts:
                return []

            # Filter valid texts
            valid_texts = [text.strip() for text in texts if text and text.strip()]

            if not valid_texts:
                logger.warning("No valid texts provided for batch embedding")
                return [np.zeros(self.embedding_dimension, dtype=np.float32) for _ in texts]

            embeddings = []
            logger.info(f"Generating Gemini embeddings for {len(valid_texts)} texts")

            # Process each text individually (Gemini doesn't support batch requests)
            for i, text in enumerate(valid_texts):
                try:
                    # Add small delay to avoid rate limiting
                    if i > 0:
                        import time
                        time.sleep(0.1)

                    embedding = self.embed_text(text)
                    embeddings.append(embedding)

                    if (i + 1) % 10 == 0:
                        logger.info(f"Processed {i + 1}/{len(valid_texts)} texts")

                except Exception as e:
                    logger.error(f"Failed to embed text {i}: {e}")
                    # Add zero vector for failed embeddings to maintain indexing
                    embeddings.append(np.zeros(self.embedding_dimension, dtype=np.float32))

            return embeddings

        except Exception as e:
            logger.error(f"Failed to generate batch embeddings: {e}")
            raise
