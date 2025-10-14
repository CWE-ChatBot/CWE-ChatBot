#!/usr/bin/env python3
"""
Persistent embedding cache for CWE corpus ingestion.
Prevents re-generation of expensive embeddings on failures.
"""

import hashlib
import json
import logging
import pickle
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)


class EmbeddingCache:
    """Persistent cache for CWE embeddings with failure recovery."""

    def __init__(self, cache_dir: str = "cwe_embeddings_cache"):
        """Initialize embedding cache with persistent storage."""
        self.cache_dir = Path(cache_dir).absolute()
        self.cache_dir.mkdir(exist_ok=True)

        # Metadata file tracks cache state
        self.metadata_file = self.cache_dir / "cache_metadata.json"
        self.metadata = self._load_metadata()

        logger.info(f"Embedding cache initialized: {self.cache_dir}")

    def _load_metadata(self) -> Dict[str, Any]:
        """Load cache metadata or create new."""
        if self.metadata_file.exists():
            with open(self.metadata_file, "r") as f:
                data = json.load(f)
                return dict(data)
        else:
            return {
                "created": datetime.now().isoformat(),
                "cache_version": "1.0",
                "embeddings": {},  # cwe_id -> file_info
                "last_updated": None,
                "total_cached": 0,
            }

    def _save_metadata(self) -> None:
        """Save cache metadata to disk."""
        self.metadata["last_updated"] = datetime.now().isoformat()
        with open(self.metadata_file, "w") as f:
            json.dump(self.metadata, f, indent=2)

    def _get_cache_key(
        self,
        cwe_id: str,
        embedder_type: str,
        model_name: str,
        section: str = "",
        section_rank: int = 0,
    ) -> str:
        """Generate unique cache key for CWE embedding, optionally section-specific for chunked mode."""
        if section:
            # For chunked embeddings: include section and rank in key
            key_data = f"{cwe_id}_{section}_{section_rank}_{embedder_type}_{model_name}"
        else:
            # For single embeddings: original format
            key_data = f"{cwe_id}_{embedder_type}_{model_name}"
        return hashlib.md5(key_data.encode()).hexdigest()  # nosec B324 - MD5 used for cache key generation, not cryptographic security

    def _get_cache_filename(self, cache_key: str, cwe_id: Optional[str] = None) -> Path:
        """
        Get cache file path for embedding with optional CWE ID.

        Security: Sanitizes CWE ID to prevent path traversal attacks.

        Args:
            cache_key: MD5 hash of embedding metadata
            cwe_id: Optional CWE identifier (e.g., "CWE-79")

        Returns:
            Path: Safe cache file path

        Raises:
            ValueError: If CWE ID format is invalid or contains path traversal
        """
        if cwe_id:
            # Security: Sanitize CWE ID to prevent path traversal (CRIT-001)
            # Remove all characters except alphanumeric, dash, and underscore
            safe_id = re.sub(r"[^a-zA-Z0-9\-_]", "", cwe_id)

            # Validate format: must start with "CWE-" and have numeric ID
            if not safe_id or not re.match(r"^CWE-\d+$", safe_id):
                logger.error(f"Invalid CWE ID format rejected: {cwe_id}")
                raise ValueError(f"Invalid CWE ID format: {cwe_id}")

            # Include CWE ID in filename for easier identification
            return self.cache_dir / f"embedding_{safe_id}_{cache_key}.pkl"
        else:
            # Fallback to original format
            return self.cache_dir / f"embedding_{cache_key}.pkl"

    def has_embedding(
        self,
        cwe_id: str,
        embedder_type: str,
        model_name: str,
        section: str = "",
        section_rank: int = 0,
    ) -> bool:
        """Check if embedding exists in cache."""
        cache_key = self._get_cache_key(
            cwe_id, embedder_type, model_name, section, section_rank
        )
        cache_file = self._get_cache_filename(cache_key, cwe_id)

        # Check both metadata and file existence
        return cache_key in self.metadata.get("embeddings", {}) and cache_file.exists()

    def save_embedding(
        self, cwe_data: Dict[str, Any], embedder_type: str, model_name: str
    ) -> str:
        """Save CWE embedding to persistent cache."""
        cwe_id = cwe_data.get("cwe_id", "unknown")
        section = cwe_data.get("section", "")
        section_rank = cwe_data.get("section_rank", 0)
        cache_key = self._get_cache_key(
            cwe_id, embedder_type, model_name, section, section_rank
        )
        cache_file = self._get_cache_filename(cache_key, cwe_id)

        # Prepare data for serialization
        cache_data = {
            "cwe_id": cwe_id,
            "embedder_type": embedder_type,
            "model_name": model_name,
            "timestamp": datetime.now().isoformat(),
            "cwe_data": cwe_data.copy(),
        }

        # Convert numpy array to list for serialization
        if "embedding" in cache_data["cwe_data"]:
            embedding = cache_data["cwe_data"]["embedding"]
            if isinstance(embedding, np.ndarray):
                cache_data["cwe_data"]["embedding"] = embedding.tolist()
                cache_data["embedding_shape"] = embedding.shape
                cache_data["embedding_dtype"] = str(embedding.dtype)

        # Save to disk
        with open(cache_file, "wb") as f:
            pickle.dump(cache_data, f)

        # Update metadata
        self.metadata["embeddings"][cache_key] = {
            "cwe_id": cwe_id,
            "file": str(cache_file.name),
            "timestamp": cache_data["timestamp"],
            "embedder_type": embedder_type,
            "model_name": model_name,
        }
        self.metadata["total_cached"] = len(self.metadata["embeddings"])
        self._save_metadata()

        logger.debug(f"Cached embedding for {cwe_id} ({embedder_type}/{model_name})")
        return cache_key

    def load_embedding(
        self,
        cwe_id: str,
        embedder_type: str,
        model_name: str,
        section: str = "",
        section_rank: int = 0,
    ) -> Optional[Dict[str, Any]]:
        """Load CWE embedding from persistent cache."""
        cache_key = self._get_cache_key(
            cwe_id, embedder_type, model_name, section, section_rank
        )
        cache_file = self._get_cache_filename(cache_key, cwe_id)

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, "rb") as f:
                cache_data = pickle.load(f)  # nosec B301 - Loading trusted local cache files only, not untrusted data

            # Restore numpy array from list
            if "embedding" in cache_data["cwe_data"]:
                embedding_list = cache_data["cwe_data"]["embedding"]
                if isinstance(embedding_list, list):
                    shape = cache_data.get("embedding_shape", (len(embedding_list),))
                    dtype = cache_data.get("embedding_dtype", "float32")
                    cache_data["cwe_data"]["embedding"] = np.array(
                        embedding_list, dtype=dtype
                    ).reshape(shape)

            logger.debug(f"Loaded cached embedding for {cwe_id}")
            result: Dict[str, Any] = cache_data["cwe_data"]
            return result

        except Exception as e:
            logger.error(f"Failed to load cached embedding for {cwe_id}: {e}")
            return None

    def save_batch(
        self, cwe_batch: List[Dict[str, Any]], embedder_type: str, model_name: str
    ) -> int:
        """Save batch of CWE embeddings to cache."""
        saved_count = 0
        for cwe_data in cwe_batch:
            try:
                self.save_embedding(cwe_data, embedder_type, model_name)
                saved_count += 1
            except Exception as e:
                cwe_id = cwe_data.get("cwe_id", "unknown")
                logger.error(f"Failed to cache embedding for {cwe_id}: {e}")

        logger.info(f"Cached {saved_count}/{len(cwe_batch)} embeddings")
        return saved_count

    def load_batch(
        self, cwe_ids: List[str], embedder_type: str, model_name: str
    ) -> List[Dict[str, Any]]:
        """Load batch of CWE embeddings from cache."""
        loaded_embeddings = []
        for cwe_id in cwe_ids:
            embedding_data = self.load_embedding(cwe_id, embedder_type, model_name)
            if embedding_data:
                loaded_embeddings.append(embedding_data)

        logger.info(
            f"Loaded {len(loaded_embeddings)}/{len(cwe_ids)} embeddings from cache"
        )
        return loaded_embeddings

    def get_cached_cwe_ids(self, embedder_type: str, model_name: str) -> List[str]:
        """Get list of CWE IDs that have cached embeddings."""
        cached_ids = []
        for cache_key, info in self.metadata.get("embeddings", {}).items():
            if (
                info.get("embedder_type") == embedder_type
                and info.get("model_name") == model_name
            ):
                cached_ids.append(info["cwe_id"])

        return sorted(cached_ids)

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        embeddings = self.metadata.get("embeddings", {})

        # Group by embedder type and model
        stats_by_type = {}
        for info in embeddings.values():
            key = f"{info['embedder_type']}/{info['model_name']}"
            if key not in stats_by_type:
                stats_by_type[key] = 0
            stats_by_type[key] += 1

        return {
            "cache_dir": str(self.cache_dir),
            "total_cached": len(embeddings),
            "by_embedder": stats_by_type,
            "created": self.metadata.get("created"),
            "last_updated": self.metadata.get("last_updated"),
            "disk_usage_mb": sum(f.stat().st_size for f in self.cache_dir.glob("*.pkl"))
            / (1024 * 1024),
        }


def create_sample_cwe_list(total_cwes: int = 30) -> List[str]:
    """Create a representative sample of CWEs for testing."""
    # Representative CWEs covering different categories
    priority_cwes = [
        "CWE-79",  # XSS (Web)
        "CWE-89",  # SQL Injection (Web)
        "CWE-22",  # Path Traversal (Web)
        "CWE-78",  # OS Command Injection (Web)
        "CWE-352",  # CSRF (Web)
        "CWE-434",  # File Upload (Web)
        "CWE-287",  # Authentication (Auth)
        "CWE-862",  # Authorization (Auth)
        "CWE-276",  # Permissions (Auth)
        "CWE-120",  # Buffer Overflow (Memory)
        "CWE-125",  # Buffer Over-read (Memory)
        "CWE-416",  # Use After Free (Memory)
        "CWE-476",  # NULL Pointer (Memory)
        "CWE-190",  # Integer Overflow (Numeric)
        "CWE-191",  # Integer Underflow (Numeric)
        "CWE-369",  # Division by Zero (Numeric)
        "CWE-311",  # Encryption (Crypto)
        "CWE-327",  # Weak Crypto (Crypto)
        "CWE-330",  # Weak Random (Crypto)
        "CWE-20",  # Input Validation (Input)
        "CWE-1021",  # Deserialization (Input)
        "CWE-129",  # Array Index (Input)
        "CWE-200",  # Information Disclosure (Info)
        "CWE-209",  # Error Information (Info)
        "CWE-532",  # Log Information (Info)
        "CWE-362",  # Race Condition (Concurrency)
        "CWE-367",  # TOCTOU (Concurrency)
        "CWE-404",  # Resource Management (Resource)
        "CWE-401",  # Memory Leak (Resource)
        "CWE-665",  # Improper Initialization (Resource)
    ]

    return priority_cwes[:total_cwes]


if __name__ == "__main__":
    # Demo usage
    cache = EmbeddingCache()
    print("📦 Embedding Cache Ready")
    print(f"Cache directory: {cache.cache_dir}")

    stats = cache.get_cache_stats()
    print(f"Current cache: {stats['total_cached']} embeddings")

    # Show sample CWE list
    sample_cwes = create_sample_cwe_list(30)
    print(f"\n🎯 Sample CWEs for testing (30): {', '.join(sample_cwes[:10])}...")
