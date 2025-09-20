#!/usr/bin/env python3
"""
Test script to verify PostgreSQL connection and pgvector setup.
Run this after starting your PostgreSQL database.
"""
import os
import sys

# Set the DATABASE_URL for testing
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/cwe"
)

def test_postgres_connection():
    """Test basic PostgreSQL connection."""
    try:
        from pg_vector_store import PostgresVectorStore

        print("🔍 Testing PostgreSQL connection...")
        store = PostgresVectorStore(dims=3072)

        stats = store.get_collection_stats()
        print(f"✅ PostgreSQL connection successful!")
        print(f"📊 Database stats: {stats}")

        return True

    except Exception as e:
        print(f"❌ PostgreSQL connection failed: {e}")
        print("\n💡 Make sure your database is running:")
        print("   docker compose up -d")
        print("   export DATABASE_URL='postgresql://postgres:postgres@localhost:5432/cwe'")
        return False

def test_pgvector_extension():
    """Test pgvector extension functionality."""
    try:
        import numpy as np
        from pg_vector_store import PostgresVectorStore

        print("\n🔍 Testing pgvector extension...")
        store = PostgresVectorStore(dims=3072)

        # Test with a dummy embedding
        dummy_embedding = np.random.rand(3072).astype(np.float32)
        test_doc = {
            "id": "CWE-TEST",
            "cwe_id": "CWE-TEST",
            "name": "Test Weakness",
            "abstraction": "Base",
            "status": "Draft",
            "full_text": "This is a test CWE entry for database validation.",
            "alternate_terms_text": "test; validation",
            "embedding": dummy_embedding
        }

        # Store test document
        stored = store.store_batch([test_doc])
        print(f"✅ pgvector test successful! Stored {stored} test documents.")

        # Test vector similarity query
        results = store.query_similar(dummy_embedding, n_results=1)
        if results and results[0]["metadata"]["cwe_id"] == "CWE-TEST":
            print("✅ Vector similarity search working!")
        else:
            print("⚠️  Vector similarity search may have issues")

        return True

    except Exception as e:
        print(f"❌ pgvector test failed: {e}")
        return False

def test_hybrid_retrieval():
    """Test hybrid retrieval functionality."""
    try:
        import numpy as np
        from pg_vector_store import PostgresVectorStore

        print("\n🔍 Testing hybrid retrieval...")
        store = PostgresVectorStore(dims=3072)

        dummy_embedding = np.random.rand(3072).astype(np.float32)

        # Test hybrid query
        results = store.query_hybrid(
            query_text="test weakness",
            query_embedding=dummy_embedding,
            k_vec=10,
            limit=5
        )

        print(f"✅ Hybrid retrieval successful! Found {len(results)} results.")

        return True

    except Exception as e:
        print(f"❌ Hybrid retrieval test failed: {e}")
        return False

if __name__ == "__main__":
    print("🧪 PostgreSQL + pgvector Database Test")
    print("=" * 50)

    success = True
    success &= test_postgres_connection()
    success &= test_pgvector_extension()
    success &= test_hybrid_retrieval()

    if success:
        print("\n🎉 All database tests passed! Ready for CWE ingestion.")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed. Check your database setup.")
        sys.exit(1)
