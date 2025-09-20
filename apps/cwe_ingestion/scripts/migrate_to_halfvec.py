#!/usr/bin/env python3
"""
Migration script to add halfvec(3072) column and HNSW index for optimal performance.
Implements the recommended optimization for 200ms p95 target.
"""

import os
import time
import logging
from typing import Optional
import psycopg

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_database_to_halfvec(database_url: str, db_name: str):
    """Add halfvec column and HNSW index to achieve <200ms p95 performance."""
    print(f"\n🚀 MIGRATING {db_name.upper()} DATABASE TO HALFVEC")
    print("=" * 60)

    try:
        # Connect with autocommit for index operations
        conn = psycopg.connect(database_url)
        conn.autocommit = True

        with conn.cursor() as cur:
            # Check current state
            print("📊 Checking current database state...")
            cur.execute("SELECT COUNT(*) FROM cwe_chunks;")
            row_count = cur.fetchone()[0]
            print(f"  Total rows: {row_count:,}")

            # Check if halfvec column exists
            cur.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'cwe_chunks' AND column_name = 'embedding_h'
            """)
            has_halfvec = cur.fetchone() is not None
            print(f"  Halfvec column exists: {has_halfvec}")

            # Check HNSW index
            cur.execute("""
                SELECT indexname FROM pg_indexes
                WHERE tablename = 'cwe_chunks' AND indexname = 'cwe_chunks_embedding_h_hnsw'
            """)
            has_hnsw = cur.fetchone() is not None
            print(f"  HNSW index exists: {has_hnsw}")

            if not has_halfvec:
                print("\n🔧 Step 1: Adding halfvec(3072) column...")
                start_time = time.time()

                # Add normalized halfvec column
                cur.execute("""
                    ALTER TABLE cwe_chunks
                    ADD COLUMN embedding_h halfvec(3072)
                    GENERATED ALWAYS AS (l2_normalize(embedding::halfvec)) STORED;
                """)

                elapsed = time.time() - start_time
                print(f"  ✅ Halfvec column added in {elapsed:.1f}s")

                # Verify column was created and populated
                cur.execute("""
                    SELECT COUNT(*) FROM cwe_chunks
                    WHERE embedding_h IS NOT NULL
                """)
                populated_count = cur.fetchone()[0]
                print(f"  ✅ {populated_count:,} rows populated with halfvec embeddings")
            else:
                print("  ✅ Halfvec column already exists")

            if not has_hnsw:
                print("\n🔧 Step 2: Creating HNSW index...")
                print("  This may take several minutes for large datasets...")
                start_time = time.time()

                # Create HNSW index (optimized parameters for 8k rows)
                cur.execute("""
                    CREATE INDEX cwe_chunks_embedding_h_hnsw
                    ON cwe_chunks USING hnsw (embedding_h halfvec_cosine_ops)
                    WITH (m = 16, ef_construction = 64);
                """)

                elapsed = time.time() - start_time
                print(f"  ✅ HNSW index created in {elapsed:.1f}s")
            else:
                print("  ✅ HNSW index already exists")

            # Test query performance
            print("\n🚀 Step 3: Testing halfvec query performance...")

            # Create a test vector (normalized)
            import numpy as np
            test_vector = np.random.random(3072).astype(np.float32)
            test_vector = test_vector / np.linalg.norm(test_vector)  # L2 normalize
            test_vector_list = test_vector.tolist()

            # Configure HNSW settings for optimal performance
            cur.execute("SET LOCAL hnsw.ef_search = 80;")
            cur.execute("SET LOCAL jit = off;")
            cur.execute("SET LOCAL work_mem = '64MB';")

            # Test halfvec query
            start_time = time.time()
            cur.execute("""
                SELECT cwe_id, section, embedding_h <=> %s::halfvec AS distance
                FROM cwe_chunks
                ORDER BY distance
                LIMIT 10;
            """, (test_vector_list,))
            results = cur.fetchall()
            query_time = time.time() - start_time

            print(f"  ✅ Halfvec query: {query_time*1000:.1f}ms for {len(results)} results")
            print(f"  🎯 Target: <20ms (current: {'✅ EXCELLENT' if query_time < 0.02 else '✅ GOOD' if query_time < 0.1 else '⚠️ SLOW'})")

            if results:
                top_result = results[0]
                print(f"  Top result: {top_result[0]} - {top_result[1]} (distance: {top_result[2]:.3f})")

            # Compare with original vector query
            print("\n📊 Comparing with original vector(3072) query...")
            start_time = time.time()
            cur.execute("""
                SELECT cwe_id, section, embedding <=> %s::vector AS distance
                FROM cwe_chunks
                ORDER BY distance
                LIMIT 10;
            """, (test_vector_list,))
            vector_results = cur.fetchall()
            vector_query_time = time.time() - start_time

            speedup = vector_query_time / query_time if query_time > 0 else 0
            print(f"  Original vector query: {vector_query_time*1000:.1f}ms")
            print(f"  Speedup with halfvec: {speedup:.1f}x faster")

            # Final status
            print(f"\n🎉 {db_name.upper()} DATABASE MIGRATION COMPLETE!")
            print(f"  ✅ Halfvec column: Ready")
            print(f"  ✅ HNSW index: Ready")
            print(f"  ✅ Query performance: {query_time*1000:.1f}ms")
            print(f"  🚀 Ready for <200ms p95 target")

        conn.close()
        return True

    except Exception as e:
        print(f"❌ Migration failed for {db_name}: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run halfvec migration on both databases."""
    print("🚀 HALFVEC OPTIMIZATION MIGRATION")
    print("=" * 50)
    print("Target: <200ms p95 end-to-end performance")
    print("Strategy: halfvec(3072) + HNSW indexing")

    # Database URLs
    local_url = os.getenv('LOCAL_DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/cwe')
    prod_url = os.getenv('PROD_DATABASE_URL', 'postgresql://cwe-postgres-sa%40cwechatbot.iam@127.0.0.1:5433/postgres?sslmode=disable')

    results = {}

    # Migrate local database
    print("\n" + "="*80)
    results['local'] = migrate_database_to_halfvec(local_url, "local")

    # Migrate production database
    print("\n" + "="*80)
    results['production'] = migrate_database_to_halfvec(prod_url, "production")

    # Final summary
    print("\n" + "="*80)
    print("🏆 MIGRATION SUMMARY")
    print("=" * 30)

    for db_name, success in results.items():
        status = "✅ SUCCESS" if success else "❌ FAILED"
        print(f"{db_name.capitalize():12s}: {status}")

    if all(results.values()):
        print(f"\n🎉 ALL DATABASES READY FOR HIGH-PERFORMANCE QUERIES!")
        print(f"   - halfvec(3072) columns: ✅ Ready")
        print(f"   - HNSW indexes: ✅ Ready")
        print(f"   - Target performance: <200ms p95")
        print(f"   - Next: Update application to use halfvec queries")
    else:
        print(f"\n⚠️ Some migrations failed - check logs above")

if __name__ == "__main__":
    main()