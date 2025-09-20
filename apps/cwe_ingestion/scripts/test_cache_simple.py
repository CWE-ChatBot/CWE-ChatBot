#!/usr/bin/env python3
"""Simple test of cache lookup logic."""

import os
from embedding_cache import EmbeddingCache

def test_cache_lookup():
    """Test cache lookup with section parameters."""
    print("🔧 Testing Cache Lookup Logic")
    print("=" * 40)

    # Initialize cache
    cache = EmbeddingCache('cwe_embeddings_cache_shared')

    # Parameters used in multi_db_pipeline
    cwe_id = "CWE-78"
    embedder_type = "gemini"
    model_name = "gemini-embedding-001"

    print(f"Testing cache lookup for: {cwe_id}")
    print(f"Embedder: {embedder_type}")
    print(f"Model: {model_name}")

    # Check cache stats
    stats = cache.get_cache_stats()
    print(f"\nCache contains {stats['total_cached']} embeddings")

    # Show what sections exist for CWE-78
    cwe78_sections = []
    for cache_key, info in cache.metadata.get("embeddings", {}).items():
        if info.get("cwe_id") == cwe_id:
            # Try to load this embedding to see its structure
            try:
                cache_file = cache._get_cache_filename(cache_key, cwe_id)
                if cache_file.exists():
                    import pickle
                    with open(cache_file, 'rb') as f:
                        data = pickle.load(f)
                        cwe_data = data.get('cwe_data', {})
                        section = cwe_data.get('section', 'Unknown')
                        section_rank = cwe_data.get('section_rank', 0)
                        cwe78_sections.append((section, section_rank))
            except Exception as e:
                print(f"Error reading {cache_key}: {e}")

    print(f"\nFound {len(cwe78_sections)} sections for CWE-78:")
    for section, rank in sorted(cwe78_sections):
        print(f"  {section} (rank {rank})")

    # Test cache lookup for each section
    print(f"\nTesting cache lookups:")
    cache_hits = 0
    cache_misses = 0

    for section, section_rank in cwe78_sections[:5]:  # Test first 5
        has_cache = cache.has_embedding(cwe_id, embedder_type, model_name, section, section_rank)
        if has_cache:
            cache_hits += 1
            print(f"  ✓ CACHE HIT: {section} (rank {section_rank})")
            # Try to load it
            cached_data = cache.load_embedding(cwe_id, embedder_type, model_name, section, section_rank)
            if cached_data and 'embedding' in cached_data:
                embedding_shape = getattr(cached_data['embedding'], 'shape', 'N/A')
                print(f"    Loaded embedding shape: {embedding_shape}")
            else:
                print(f"    ❌ Failed to load embedding data")
        else:
            cache_misses += 1
            print(f"  ❌ CACHE MISS: {section} (rank {section_rank})")

    print(f"\n🎯 Cache Performance:")
    print(f"  Hits: {cache_hits}")
    print(f"  Misses: {cache_misses}")
    print(f"  Hit Rate: {cache_hits/(cache_hits+cache_misses)*100:.1f}%")

    if cache_hits > 0:
        print("\n✅ Cache lookup is WORKING!")
    else:
        print("\n❌ Cache lookup is BROKEN!")

if __name__ == "__main__":
    test_cache_lookup()