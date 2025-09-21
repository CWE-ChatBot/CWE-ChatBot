"""
Gemini embedding service for generating query embeddings (3072‑D).
Wraps the ingestion GeminiEmbedder to standardize chatbot embeddings.
"""

import logging
import os
from typing import List, Optional

import numpy as np

try:
    # Reuse ingestion embedder for consistency
    from apps.cwe_ingestion.embedder import GeminiEmbedder
except ImportError:
    # Fallback import when running src directly
    from ...cwe_ingestion.embedder import GeminiEmbedder


logger = logging.getLogger(__name__)


class EmbeddingService:
    """Service for generating embeddings using Gemini embedding-001 (3072‑D)."""

    DEFAULT_MODEL = "models/embedding-001"
    DEFAULT_DIMENSIONS = 3072

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        dimensions: int = DEFAULT_DIMENSIONS,
    ):
        self.model = model
        self.dimensions = dimensions

        api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY must be provided via parameter or environment variable")

        # Wrap ingestion embedder
        self._embedder = GeminiEmbedder(api_key=api_key)
        logger.info(f"Initialized Gemini embedding service: {model} ({dimensions}D)")

    def embed_query(self, query: str) -> List[float]:
        if not isinstance(query, str) or not query.strip():
            raise ValueError("Query must be a non-empty string")
        vec: np.ndarray = self._embedder.embed_text(query.strip())
        if vec.shape[0] != self.dimensions:
            raise ValueError(f"Expected {self.dimensions}D, got {vec.shape[0]}")
        return list(vec.astype(np.float32))

    def embed_batch(self, queries: List[str], batch_size: int = 64) -> List[List[float]]:
        if not queries:
            return []
        out: List[List[float]] = []
        for i in range(0, len(queries), batch_size):
            batch = [q.strip() for q in queries[i : i + batch_size] if isinstance(q, str) and q.strip()]
            if not batch:
                out.extend([[0.0] * self.dimensions] * (i + batch_size))
                continue
            # Use single calls; GeminiEmbedder has only single-text API here
            for q in batch:
                try:
                    vec: np.ndarray = self._embedder.embed_text(q)
                    out.append(vec.astype(np.float32).tolist())
                except Exception:
                    out.append([0.0] * self.dimensions)
        return out

    def get_model_info(self) -> dict:
        return {"model": self.model, "dimensions": self.dimensions, "provider": "Gemini"}
