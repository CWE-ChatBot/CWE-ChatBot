#!/usr/bin/env python3
"""
Extract embeddings from database and populate the EmbeddingCache.
This script reads embeddings from a populated database and creates cache files
for future reuse, avoiding expensive re-generation of Gemini embeddings.
"""
import logging
import os
import sys
from pathlib import Path
from typing import List, Dict, Any
import numpy as np

try:
    from .pg_chunk_store import PostgresChunkStore
    from .embedding_cache import EmbeddingCache
except ImportError:
    from pg_chunk_store import PostgresChunkStore
    from embedding_cache import EmbeddingCache

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def extract_embeddings_to_cache(
    database_url: str,
    cache_dir: str = "cwe_embeddings_cache_shared",
    embedder_type: str = "gemini",
    model_name: str = "text-embedding-004"
) -> bool:
    """
    Extract embeddings from database and populate the EmbeddingCache.

    Args:
        database_url: PostgreSQL connection string
        cache_dir: Directory to store cached embeddings
        embedder_type: Type of embedder used (e.g., 'gemini')
        model_name: Model name used for embeddings

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Initialize cache and database
        logger.info(f"Initializing embedding cache: {cache_dir}")
        cache = EmbeddingCache(cache_dir)

        logger.info(f"Connecting to database: {database_url[:50]}...")
        chunk_store = PostgresChunkStore(dims=3072, database_url=database_url)

        # Get database statistics
        stats = chunk_store.get_collection_stats()
        logger.info(f"Database contains {stats['count']:,} chunks")

        if stats['count'] == 0:
            logger.warning("No chunks found in database")
            return False

        # Extract all embeddings from database
        logger.info("Extracting embeddings from database...")
        chunks = extract_all_chunks(chunk_store)

        if not chunks:
            logger.error("Failed to extract chunks from database")
            return False

        logger.info(f"Extracted {len(chunks):,} chunks")

        # Group chunks by CWE ID and section for caching
        grouped_chunks = group_chunks_for_cache(chunks)
        logger.info(f"Grouped into {len(grouped_chunks):,} cache entries")

        # Save to cache
        saved_count = save_chunks_to_cache(cache, grouped_chunks, embedder_type, model_name)

        # Verify cache
        cache_stats = cache.get_cache_stats()
        logger.info(f"Cache now contains {cache_stats['total_cached']} embeddings")
        logger.info(f"Cache disk usage: {cache_stats['disk_usage_mb']:.1f} MB")

        logger.info(f"✅ Successfully cached {saved_count} embeddings")
        return True

    except Exception as e:
        logger.error(f"Failed to extract embeddings to cache: {e}", exc_info=True)
        return False


def extract_all_chunks(chunk_store: PostgresChunkStore) -> List[Dict[str, Any]]:
    """Extract all chunks from the database."""
    try:
        with chunk_store.conn.cursor() as cur:
            # Query all chunks with their embeddings
            cur.execute("""
                SELECT
                    cwe_id,
                    section,
                    section_rank,
                    name,
                    alternate_terms_text,
                    full_text,
                    embedding
                FROM cwe_chunks
                ORDER BY cwe_id, section_rank
            """)

            chunks = []
            for row in cur.fetchall():
                cwe_id, section, section_rank, name, alt_terms, full_text, embedding_vector = row

                # Convert embedding vector to numpy array
                # PostgreSQL returns vectors as string format: '[1.0,2.0,3.0]'
                if isinstance(embedding_vector, str):
                    # Remove brackets and split by comma
                    vector_str = embedding_vector.strip('[]')
                    embedding = np.array([float(x) for x in vector_str.split(',')], dtype=np.float32)
                else:
                    # Already parsed (shouldn't happen with psycopg but handle gracefully)
                    embedding = np.array(embedding_vector, dtype=np.float32)

                chunks.append({
                    "cwe_id": cwe_id,
                    "section": section,
                    "section_rank": section_rank,
                    "name": name,
                    "alternate_terms_text": alt_terms or "",
                    "full_text": full_text,
                    "embedding": embedding
                })

            return chunks

    except Exception as e:
        logger.error(f"Failed to extract chunks: {e}")
        return []


def group_chunks_for_cache(chunks: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Group chunks by CWE ID and section for efficient caching.
    Cache format matches the EmbeddingCache expectations.
    """
    grouped = {}

    for chunk in chunks:
        cwe_id = chunk["cwe_id"]
        section = chunk["section"]
        section_rank = chunk["section_rank"]

        # Create cache key that matches EmbeddingCache format
        cache_key = f"{cwe_id}_{section}_{section_rank}"

        grouped[cache_key] = {
            "cwe_id": cwe_id,
            "section": section,
            "section_rank": section_rank,
            "name": chunk["name"],
            "alternate_terms_text": chunk["alternate_terms_text"],
            "full_text": chunk["full_text"],
            "embedding": chunk["embedding"]
        }

    return grouped


def save_chunks_to_cache(
    cache: EmbeddingCache,
    grouped_chunks: Dict[str, Dict[str, Any]],
    embedder_type: str,
    model_name: str
) -> int:
    """Save grouped chunks to the embedding cache."""
    saved_count = 0

    logger.info(f"Saving {len(grouped_chunks)} embeddings to cache...")

    for i, (cache_key, chunk_data) in enumerate(grouped_chunks.items(), 1):
        try:
            # Save using the EmbeddingCache interface
            cache.save_embedding(chunk_data, embedder_type, model_name)
            saved_count += 1

            # Progress indicator
            if i % 100 == 0:
                logger.info(f"Cached {i:,}/{len(grouped_chunks):,} embeddings...")

        except Exception as e:
            logger.error(f"Failed to cache {cache_key}: {e}")
            continue

    logger.info(f"Successfully cached {saved_count}/{len(grouped_chunks)} embeddings")
    return saved_count


def main():
    """Main script entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Extract embeddings from database to cache")
    parser.add_argument(
        "--database-url",
        required=True,
        help="PostgreSQL database URL"
    )
    parser.add_argument(
        "--cache-dir",
        default="cwe_embeddings_cache_shared",
        help="Cache directory (default: cwe_embeddings_cache_shared)"
    )
    parser.add_argument(
        "--embedder-type",
        default="gemini",
        help="Embedder type (default: gemini)"
    )
    parser.add_argument(
        "--model-name",
        default="gemini-embedding-001",
        help="Model name (default: gemini-embedding-001)"
    )

    args = parser.parse_args()

    logger.info("🔄 Starting embedding extraction to cache...")
    logger.info(f"Database: {args.database_url[:50]}...")
    logger.info(f"Cache dir: {args.cache_dir}")
    logger.info(f"Embedder: {args.embedder_type}/{args.model_name}")

    success = extract_embeddings_to_cache(
        database_url=args.database_url,
        cache_dir=args.cache_dir,
        embedder_type=args.embedder_type,
        model_name=args.model_name
    )

    if success:
        logger.info("✅ Embedding extraction completed successfully")
        sys.exit(0)
    else:
        logger.error("❌ Embedding extraction failed")
        sys.exit(1)


if __name__ == "__main__":
    main()