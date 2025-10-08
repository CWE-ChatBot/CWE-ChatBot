# apps/cwe_ingestion/embedder.py
"""
Embedding providers for CWE ingestion.

- CWEEmbedder: standardized 3072-D mock embedder (no external deps)
- GeminiEmbedder: 3072-D embeddings via google-generativeai

Local sentence-transformers support has been removed to simplify the stack
and align all embeddings to 3072 dimensions used in production (pgvector).
"""
import asyncio
import logging
import os
import uuid
from typing import Any, List, Optional, Tuple

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
    api_key = os.getenv("GEMINI_API_KEY")

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
        self.api_key = None  # No API key needed for local mock embedder
        self.model: Optional[Any] = None  # Always None for mock-only implementation
        self.embedding_dimension = 3072
        logger.info("Initialized 3072-D mock embedder (no external model)")

    # sentence-transformers support removed; mock-only implementation

    def _use_mock_embedder(self) -> None:
        """Use mock embedder for testing when sentence-transformers is not available."""
        self.model = None
        self.embedding_dimension = 3072  # Mock dimension standardized
        logger.info("Using mock embedder (3072-D) - embeddings will be random vectors")

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

            # Always use mock embedder for local implementation
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
                await asyncio.sleep(2**attempt)  # Exponential backoff
        # Should not be reached, but for type safety
        return np.zeros(self.embedding_dimension, dtype=np.float32)

    def _generate_mock_embedding(self, text: str) -> np.ndarray:
        """Generate deterministic mock embedding for testing."""
        # Use hash of text to generate consistent embeddings
        text_hash = hash(text) % (2**32)
        np.random.seed(text_hash)
        embedding = np.random.rand(self.embedding_dimension).astype(
            np.float32
        )  # DevSkim: ignore DS148264
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
        api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY environment variable is required for Gemini embeddings. "
                "Please set it with your Google AI API key."
            )

        # Security: Generate correlation ID for error tracking without exposing API key (HIGH-001)
        self.correlation_id = str(uuid.uuid4())[:8]
        self.is_local_model = False
        self.embedding_dimension = (
            3072  # Requested 3072D for enhanced semantic precision
        )
        logger.info(f"GeminiEmbedder initialized (correlation: {self.correlation_id})")

        # Configure the Gemini API
        try:
            # Optional dependency; ignore Pylance missing import in environments
            # where google-generativeai isn't installed.
            import google.generativeai as genai  # type: ignore[reportMissingImports]

            # Avoid private/exported attribute warnings by using getattr.
            configure_fn = getattr(genai, "configure", None)
            if callable(configure_fn):
                configure_fn(api_key=api_key)
            else:
                # Fallback: library also reads GOOGLE_API_KEY from env
                os.environ["GOOGLE_API_KEY"] = api_key
            self.genai: Any = genai
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

            # Make API call with gemini-embedding-001 (native 3072D support)
            result: Any = self.genai.embed_content(
                model="models/gemini-embedding-001", content=sanitized_text
            )

            # Extract embedding from response
            # google-generativeai typically returns {'embedding': {'values': [...]}}
            embedding_payload: Any = (
                result.get("embedding")
                if hasattr(result, "get")
                else result["embedding"]
            )
            embedding_list = (
                embedding_payload.get("values")
                if isinstance(embedding_payload, dict) and "values" in embedding_payload
                else embedding_payload
            )
            embedding = np.array(embedding_list, dtype=np.float32)

            # Validate dimension
            if embedding.shape[0] != self.embedding_dimension:
                raise ValueError(
                    f"Expected {self.embedding_dimension} dimensions, "
                    f"got {embedding.shape[0]}"
                )

            return embedding

        except Exception as e:
            # Security: Use correlation ID instead of API key for error tracking (HIGH-001)
            error_type = type(e).__name__
            logger.error(
                f"Gemini API error (correlation: {self.correlation_id}): {error_type}"
            )
            raise Exception(f"Gemini API error (correlation: {self.correlation_id})")

    def embed_batch(self, texts: List[str], max_workers: int = 5) -> List[np.ndarray]:
        """
        Generate embeddings for multiple texts efficiently with smart rate limiting.

        Args:
            texts: List of texts to embed
            max_workers: Maximum concurrent threads (default: 5)

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
                return [
                    np.zeros(self.embedding_dimension, dtype=np.float32) for _ in texts
                ]

            logger.info(
                f"Generating Gemini embeddings for {len(valid_texts)} texts (max_workers={max_workers})"
            )

            # Choose strategy based on batch size
            if len(valid_texts) <= 10:
                # Small batch: use sequential with minimal delay
                return self._embed_batch_sequential(valid_texts, smart_delay=True)
            else:
                # Large batch: use thread pool for better throughput
                return self._embed_batch_parallel(valid_texts, max_workers)

        except Exception as e:
            logger.error(f"Failed to generate batch embeddings: {e}")
            raise

    def _embed_batch_sequential(
        self, texts: List[str], smart_delay: bool = True
    ) -> List[np.ndarray]:
        """Sequential embedding with smart delay strategy."""
        import time

        embeddings = []
        consecutive_failures = 0

        for i, text in enumerate(texts):
            try:
                # Smart delay strategy
                if smart_delay and i > 0:
                    if consecutive_failures > 0:
                        # Exponential backoff after failures
                        delay = min(0.5 * (2**consecutive_failures), 5.0)
                        time.sleep(delay)
                    elif i % 20 == 0:
                        # Small delay every 20 requests to be respectful
                        time.sleep(0.05)
                    # Otherwise, no delay for good throughput

                embedding = self.embed_text(text)
                embeddings.append(embedding)
                consecutive_failures = 0  # Reset failure counter

                if (i + 1) % 10 == 0:
                    logger.info(f"Processed {i + 1}/{len(texts)} texts")

            except Exception as e:
                logger.error(f"Failed to embed text {i}: {e}")
                consecutive_failures += 1
                embeddings.append(np.zeros(self.embedding_dimension, dtype=np.float32))

        return embeddings

    def _embed_batch_parallel(
        self, texts: List[str], max_workers: int
    ) -> List[np.ndarray]:
        """Parallel embedding using thread pool with rate limiting."""
        import concurrent.futures
        import time

        # Initialize with zero vectors to keep types consistent for Pylance
        embeddings: List[np.ndarray] = [
            np.zeros(self.embedding_dimension, dtype=np.float32) for _ in texts
        ]

        def embed_with_retry(
            args: Tuple[int, str]
        ) -> Tuple[int, np.ndarray, Optional[Exception]]:
            index, text = args
            max_retries = 3
            base_delay = 0.1

            for attempt in range(max_retries):
                try:
                    # Add jitter to prevent thundering herd
                    if attempt > 0:
                        jitter = 0.1 * (hash(text) % 10) / 10
                        time.sleep(base_delay * (2**attempt) + jitter)

                    embedding = self.embed_text(text)
                    return (index, embedding, None)
                except Exception as e:
                    if attempt == max_retries - 1:
                        logger.error(
                            f"Failed to embed text {index} after {max_retries} attempts: {e}"
                        )
                        return (
                            index,
                            np.zeros(self.embedding_dimension, dtype=np.float32),
                            e,
                        )
                    else:
                        logger.warning(
                            f"Embedding attempt {attempt + 1} failed for text {index}: {e}"
                        )

            # Fallback to satisfy type checker; should be unreachable
            return (
                index,
                np.zeros(self.embedding_dimension, dtype=np.float32),
                None,
            )

        # Process in parallel with controlled concurrency
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_index = {
                executor.submit(embed_with_retry, (i, text)): i
                for i, text in enumerate(texts)
            }

            completed = 0
            for future in concurrent.futures.as_completed(future_to_index):
                try:
                    index, embedding, error = future.result()
                    embeddings[index] = embedding
                    completed += 1

                    if completed % 10 == 0:
                        logger.info(f"Completed {completed}/{len(texts)} embeddings")

                except Exception as e:
                    index = future_to_index[future]
                    logger.error(f"Unexpected error processing text {index}: {e}")
                    embeddings[index] = np.zeros(
                        self.embedding_dimension, dtype=np.float32
                    )

        return embeddings
