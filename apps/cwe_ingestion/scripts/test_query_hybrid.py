#!/usr/bin/env python3
"""
Test script to verify query_hybrid works with production database.
Run this to test if SQL injection queries return results.
"""

import os
import sys

# Add cwe_ingestion to path
sys.path.insert(0, "/home/chris/work/CyberSecAI/cwe_chatbot_bmad/apps/cwe_ingestion")

from cwe_ingestion.embedder import GeminiEmbedder
from cwe_ingestion.pg_chunk_store import PostgresChunkStore


def test_query_hybrid():
    """Test query_hybrid with SQL injection query."""

    # Get API key from environment
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("❌ GEMINI_API_KEY not set")
        return False

    # Initialize components
    print("🔧 Initializing PostgresChunkStore and GeminiEmbedder...")
    db_url = "postgresql://postgres:postgres@localhost:5432/cwe"

    try:
        store = PostgresChunkStore(
            dims=3072, database_url=db_url, skip_schema_init=True
        )
        embedder = GeminiEmbedder(api_key=api_key)
    except Exception as e:
        print(f"❌ Failed to initialize: {e}")
        return False

    # Test query
    query = "Show me SQL injection prevention techniques"
    print(f"\n📝 Testing query: '{query}'")

    # Generate embedding
    print("🧮 Generating embedding...")
    try:
        query_embedding = embedder.embed_text(query)
        print(f"✅ Generated {len(query_embedding)}D embedding")
    except Exception as e:
        print(f"❌ Embedding failed: {e}")
        return False

    # Execute query_hybrid
    print("\n🔍 Executing query_hybrid...")
    try:
        results = store.query_hybrid(
            query_text=query,
            query_embedding=query_embedding,
            limit_chunks=5,
            w_vec=0.65,
            w_fts=0.25,
            w_alias=0.10,
        )

        print(f"\n✅ Retrieved {len(results)} chunks:")

        if len(results) == 0:
            print("❌ NO RESULTS - query_hybrid returned empty list!")
            return False

        for i, r in enumerate(results[:5], 1):
            cwe_id = r["metadata"]["cwe_id"]
            section = r["metadata"]["section"]
            hybrid_score = r["scores"]["hybrid"]
            vec_score = r["scores"]["vec"]
            fts_score = r["scores"]["fts"]
            alias_score = r["scores"]["alias"]

            print(f"\n  {i}. {cwe_id}: {section}")
            print(
                f"     Hybrid: {hybrid_score:.4f} (vec: {vec_score:.4f}, fts: {fts_score:.4f}, alias: {alias_score:.4f})"
            )
            print(f"     Text: {r['document'][:100]}...")

        # Check if CWE-89 is in results
        cwe_ids = [r["metadata"]["cwe_id"] for r in results]
        if "CWE-89" in cwe_ids:
            print(
                f"\n✅ SUCCESS: CWE-89 found in results at position {cwe_ids.index('CWE-89') + 1}"
            )
            return True
        else:
            print(f"\n⚠️  WARNING: CWE-89 not in top {len(results)} results")
            print(f"   Found CWEs: {cwe_ids}")
            return False

    except Exception as e:
        print(f"❌ query_hybrid failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_query_hybrid()
    sys.exit(0 if success else 1)
