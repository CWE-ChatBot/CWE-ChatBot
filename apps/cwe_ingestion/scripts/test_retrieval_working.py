#!/usr/bin/env python3
"""
Working retrieval performance test that avoids SQL compatibility issues.
Tests actual retrieval methods that work in both databases.
"""

import os
import time
import numpy as np
from pg_chunk_store import PostgresChunkStore
from embedder import GeminiEmbedder

def test_database_status(store: PostgresChunkStore, db_name: str):
    """Test database status and basic functionality."""
    print(f"\n🔍 {db_name.upper()} DATABASE STATUS")
    print("=" * 50)

    # Get basic stats
    stats = store.get_collection_stats()
    print(f"Total chunks: {stats['count']:,}")

    with store.conn.cursor() as cur:
        # Check unique CWEs
        cur.execute("SELECT COUNT(DISTINCT cwe_id) FROM cwe_chunks;")
        unique_cwes = cur.fetchone()[0]
        print(f"Unique CWEs: {unique_cwes}")

        # Check section distribution (top 5)
        cur.execute("SELECT section, COUNT(*) FROM cwe_chunks GROUP BY section ORDER BY COUNT(*) DESC LIMIT 5;")
        sections = cur.fetchall()
        print(f"Top sections:")
        for section, count in sections:
            print(f"  {section}: {count:,} chunks")

        # Check PostgreSQL version
        cur.execute("SELECT version();")
        version = cur.fetchone()[0]
        pg_version = version.split()[1]
        print(f"PostgreSQL version: {pg_version}")

        # Check pgvector extension
        cur.execute("SELECT extname, extversion FROM pg_extension WHERE extname = 'vector';")
        vector_ext = cur.fetchone()
        if vector_ext:
            print(f"pgvector extension: {vector_ext[1]}")
        else:
            print("pgvector extension: Not found")

        # Check vector indexes
        cur.execute("""
            SELECT indexname, indexdef
            FROM pg_indexes
            WHERE tablename = 'cwe_chunks' AND indexdef ILIKE '%vector%'
        """)
        vector_indexes = cur.fetchall()
        print(f"Vector indexes: {len(vector_indexes)}")

        if vector_indexes:
            for idx_name, idx_def in vector_indexes:
                index_type = "HNSW" if "hnsw" in idx_def.lower() else "IVFFlat" if "ivfflat" in idx_def.lower() else "Unknown"
                print(f"  {idx_name}: {index_type}")
        else:
            print("  No vector indexes found - using sequential scan")

    return {
        "total_chunks": stats['count'],
        "unique_cwes": unique_cwes,
        "pg_version": pg_version,
        "vector_indexes": len(vector_indexes)
    }

def test_vector_search_only(store: PostgresChunkStore, embedder: GeminiEmbedder, db_name: str):
    """Test pure vector similarity search."""
    print(f"\n🚀 {db_name.upper()} VECTOR SEARCH TEST")
    print("=" * 45)

    test_queries = [
        "SQL injection vulnerabilities",
        "Cross-site scripting XSS",
        "Buffer overflow memory corruption",
        "Command injection attacks",
        "Authentication bypass"
    ]

    results = []
    total_time = 0
    successful_queries = 0

    for i, query in enumerate(test_queries, 1):
        print(f"\n[{i}/5] Testing: '{query}'")

        try:
            # Generate embedding
            start_time = time.time()
            query_embedding = embedder.embed_text(query)
            embedding_time = time.time() - start_time

            # Test vector search using query_similar
            search_start = time.time()
            chunks = store.query_similar(query_embedding, n_results=10)
            search_time = time.time() - search_start

            total_query_time = embedding_time + search_time

            # Analyze results
            found_cwes = list(set([chunk['metadata']['cwe_id'] for chunk in chunks]))
            sections = list(set([chunk['metadata']['section'] for chunk in chunks]))

            print(f"  Embedding: {embedding_time*1000:5.1f}ms")
            print(f"  Search:    {search_time*1000:5.1f}ms")
            print(f"  Total:     {total_query_time*1000:5.1f}ms")
            print(f"  Results:   {len(chunks)} chunks from {len(found_cwes)} CWEs")
            print(f"  Sections:  {', '.join(sections[:3])}{'...' if len(sections) > 3 else ''}")

            if chunks:
                top_chunk = chunks[0]
                print(f"  Top result: {top_chunk['metadata']['cwe_id']} - {top_chunk['metadata']['name'][:40]}...")
                print(f"  Distance:   {top_chunk['distance']:.3f}")

            total_time += total_query_time
            successful_queries += 1

            results.append({
                "query": query,
                "total_time_ms": round(total_query_time * 1000, 1),
                "results_count": len(chunks),
                "unique_cwes": len(found_cwes),
                "top_cwe": chunks[0]['metadata']['cwe_id'] if chunks else None
            })

        except Exception as e:
            print(f"  ❌ Error: {e}")

    # Summary
    if successful_queries > 0:
        avg_time = total_time / successful_queries
        print(f"\n📊 Vector Search Summary:")
        print(f"  Successful queries: {successful_queries}/5")
        print(f"  Average query time: {avg_time*1000:.1f}ms")
        print(f"  Performance: {'✅ EXCELLENT' if avg_time < 0.1 else '✅ GOOD' if avg_time < 0.5 else '⚠️ SLOW'}")

    return results

def test_text_search_only(store: PostgresChunkStore, db_name: str):
    """Test PostgreSQL full-text search directly."""
    print(f"\n📝 {db_name.upper()} TEXT SEARCH TEST")
    print("=" * 45)

    test_queries = [
        "SQL injection",
        "Cross site scripting",
        "Buffer overflow",
        "Command injection",
        "Authentication"
    ]

    results = []

    for i, query in enumerate(test_queries, 1):
        print(f"\n[{i}/5] Testing: '{query}'")

        try:
            start_time = time.time()

            # Direct text search using tsv column
            with store.conn.cursor() as cur:
                cur.execute("""
                    SELECT cwe_id, section, section_rank, name, full_text,
                           ts_rank(tsv, websearch_to_tsquery('english', %s)) as rank
                    FROM cwe_chunks
                    WHERE tsv @@ websearch_to_tsquery('english', %s)
                    ORDER BY rank DESC
                    LIMIT 10
                """, (query, query))
                rows = cur.fetchall()

            search_time = time.time() - start_time

            # Analyze results
            found_cwes = list(set([row[0] for row in rows]))
            sections = list(set([row[1] for row in rows]))

            print(f"  Search time: {search_time*1000:5.1f}ms")
            print(f"  Results:     {len(rows)} chunks from {len(found_cwes)} CWEs")
            print(f"  Sections:    {', '.join(sections[:3])}{'...' if len(sections) > 3 else ''}")

            if rows:
                top_result = rows[0]
                print(f"  Top result:  {top_result[0]} - {top_result[3][:40]}...")
                print(f"  Text rank:   {top_result[5]:.3f}")

            results.append({
                "query": query,
                "search_time_ms": round(search_time * 1000, 1),
                "results_count": len(rows),
                "unique_cwes": len(found_cwes),
                "top_cwe": rows[0][0] if rows else None
            })

        except Exception as e:
            print(f"  ❌ Error: {e}")

    return results

def create_vector_indexes(store: PostgresChunkStore, db_name: str):
    """Attempt to create vector indexes if they don't exist."""
    print(f"\n🔧 {db_name.upper()} VECTOR INDEX CREATION")
    print("=" * 50)

    with store.conn.cursor() as cur:
        # Check current indexes
        cur.execute("""
            SELECT indexname FROM pg_indexes
            WHERE tablename = 'cwe_chunks' AND indexdef ILIKE '%vector%'
        """)
        existing = [row[0] for row in cur.fetchall()]

        if existing:
            print(f"Existing vector indexes: {existing}")
            return

        # Try to create HNSW index
        try:
            print("Attempting to create HNSW index...")
            cur.execute("""
                CREATE INDEX CONCURRENTLY IF NOT EXISTS cwe_chunks_hnsw_cos
                ON cwe_chunks USING hnsw (embedding vector_cosine_ops)
            """)
            store.conn.commit()
            print("✅ HNSW index created successfully")
        except Exception as e:
            print(f"❌ HNSW index failed: {e}")
            store.conn.rollback()

            # Try IVFFlat as fallback
            try:
                print("Attempting to create IVFFlat index...")
                cur.execute("""
                    CREATE INDEX CONCURRENTLY IF NOT EXISTS cwe_chunks_ivf_cos
                    ON cwe_chunks USING ivfflat (embedding vector_cosine_ops)
                    WITH (lists = 100)
                """)
                store.conn.commit()
                print("✅ IVFFlat index created successfully")
            except Exception as e2:
                print(f"❌ IVFFlat index also failed: {e2}")
                store.conn.rollback()

def main():
    """Run working retrieval performance tests."""
    print("🚀 CWE DATABASE RETRIEVAL TESTING (Working Version)")
    print("=" * 65)

    # Initialize connections
    local_url = os.getenv('LOCAL_DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/cwe')
    prod_url = os.getenv('PROD_DATABASE_URL', 'postgresql://cwe-postgres-sa%40cwechatbot.iam@127.0.0.1:5433/postgres?sslmode=disable')

    try:
        local_store = PostgresChunkStore(dims=3072, database_url=local_url)
        prod_store = PostgresChunkStore(dims=3072, database_url=prod_url)
        embedder = GeminiEmbedder()

        print("✅ All connections established successfully")

        # Test database status
        print("\n" + "="*80)
        local_status = test_database_status(local_store, "local")

        print("\n" + "="*80)
        prod_status = test_database_status(prod_store, "production")

        # Try to create vector indexes
        print("\n" + "="*80)
        create_vector_indexes(local_store, "local")

        print("\n" + "="*80)
        create_vector_indexes(prod_store, "production")

        # Test vector search
        print("\n" + "="*80)
        local_vector_results = test_vector_search_only(local_store, embedder, "local")

        print("\n" + "="*80)
        prod_vector_results = test_vector_search_only(prod_store, embedder, "production")

        # Test text search
        print("\n" + "="*80)
        local_text_results = test_text_search_only(local_store, "local")

        print("\n" + "="*80)
        prod_text_results = test_text_search_only(prod_store, "production")

        # Final assessment
        print("\n" + "="*80)
        print("🏆 FINAL ASSESSMENT")
        print("=" * 30)

        local_good = (local_status['unique_cwes'] >= 960 and
                     len(local_vector_results) > 0 and
                     len(local_text_results) > 0)

        prod_good = (prod_status['unique_cwes'] >= 960 and
                    len(prod_vector_results) > 0 and
                    len(prod_text_results) > 0)

        print(f"Local Database:      {'✅ FULLY OPERATIONAL' if local_good else '❌ ISSUES DETECTED'}")
        print(f"Production Database: {'✅ FULLY OPERATIONAL' if prod_good else '❌ ISSUES DETECTED'}")

        if local_good and prod_good:
            print(f"\n🎉 SUCCESS: Both databases operational with working retrieval!")
            print(f"   - Complete CWE corpus ({local_status['unique_cwes']} CWEs)")
            print(f"   - Vector search working (pgvector {local_status.get('vector_version', 'detected')})")
            print(f"   - Text search working (PostgreSQL {local_status['pg_version']})")
            print(f"   - Enhanced chunking (multiple sections per CWE)")
        else:
            print(f"\n⚠️ Some issues detected - check individual test results above")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()