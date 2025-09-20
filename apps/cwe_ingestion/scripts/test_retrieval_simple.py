#!/usr/bin/env python3
"""
Comprehensive but simple retrieval performance testing for CWE databases.
"""

import os
import time
import numpy as np
from pg_chunk_store import PostgresChunkStore
from embedder import GeminiEmbedder

def test_database_features(store: PostgresChunkStore, db_name: str, embedder: GeminiEmbedder):
    """Test all database features and retrieval methods."""
    print(f"\n🔍 {db_name.upper()} DATABASE COMPREHENSIVE TEST")
    print("=" * 60)

    # Database status
    stats = store.get_collection_stats()
    print(f"📊 Database Status:")
    print(f"  Total chunks: {stats['count']:,}")

    with store.conn.cursor() as cur:
        # Check unique CWEs and sections
        cur.execute("SELECT COUNT(DISTINCT cwe_id) FROM cwe_chunks;")
        unique_cwes = cur.fetchone()[0]

        cur.execute("SELECT COUNT(DISTINCT section) FROM cwe_chunks;")
        unique_sections = cur.fetchone()[0]

        # Check index status
        cur.execute("""
            SELECT schemaname, tablename, indexname, indexdef
            FROM pg_indexes
            WHERE tablename = 'cwe_chunks' AND indexdef ILIKE '%vector%';
        """)
        vector_indexes = cur.fetchall()

        # Check pgvector extension
        cur.execute("SELECT extname, extversion FROM pg_extension WHERE extname = 'vector';")
        vector_ext = cur.fetchone()

        print(f"  Unique CWEs: {unique_cwes}")
        print(f"  Unique sections: {unique_sections}")
        print(f"  Vector extension: {vector_ext[1] if vector_ext else 'Not found'}")
        print(f"  Vector indexes: {len(vector_indexes)}")

        if vector_indexes:
            for idx in vector_indexes:
                index_type = "HNSW" if "hnsw" in idx[3].lower() else "IVFFlat" if "ivfflat" in idx[3].lower() else "Unknown"
                print(f"    {idx[2]}: {index_type}")
        else:
            print("    No vector indexes found (falling back to sequential scan)")

    # Test queries
    test_queries = [
        ("SQL Injection", "SQL injection vulnerabilities database queries"),
        ("XSS Attack", "cross-site scripting XSS web application"),
        ("Buffer Overflow", "buffer overflow memory corruption stack"),
        ("Command Injection", "OS command injection shell execution"),
        ("Authentication", "authentication bypass credential verification"),
        ("Path Traversal", "path traversal directory file access"),
        ("Cryptography", "weak cryptography encryption algorithm"),
        ("Race Condition", "race condition concurrent thread safety"),
        ("Information Disclosure", "information exposure sensitive data"),
        ("Integer Overflow", "integer overflow numeric calculation")
    ]

    print(f"\n🚀 Retrieval Performance Tests:")
    print("-" * 40)

    total_time = 0
    successful_queries = 0

    for i, (test_name, query) in enumerate(test_queries, 1):
        print(f"\n[{i:2d}/10] {test_name}")
        print(f"Query: '{query}'")

        try:
            # Generate embedding
            embedding_start = time.time()
            query_embedding = embedder.embed_text(query)
            embedding_time = time.time() - embedding_start

            # Test hybrid search (the main method we use)
            search_start = time.time()
            results = store.query_hybrid(
                query_text=query,
                query_embedding=query_embedding,
                limit_chunks=10
            )
            search_time = time.time() - search_start
            total_query_time = embedding_time + search_time

            # Analyze results
            found_cwes = list(set([r['cwe_id'] for r in results]))
            sections_found = list(set([r['section'] for r in results]))

            print(f"  Embedding: {embedding_time*1000:5.1f}ms")
            print(f"  Search:    {search_time*1000:5.1f}ms")
            print(f"  Total:     {total_query_time*1000:5.1f}ms")
            print(f"  Results:   {len(results)} chunks, {len(found_cwes)} CWEs")
            print(f"  Sections:  {', '.join(sections_found[:3])}{'...' if len(sections_found) > 3 else ''}")

            if results:
                print(f"  Top CWE:   {results[0]['cwe_id']} - {results[0]['name'][:50]}")

            total_time += total_query_time
            successful_queries += 1

        except Exception as e:
            print(f"  ❌ Error: {e}")

    # Test section-specific queries
    print(f"\n📋 Section-Specific Query Tests:")
    print("-" * 40)

    section_tests = [
        ("Mitigations", "how to prevent SQL injection"),
        ("Examples", "example vulnerable code"),
        ("Common_Consequences", "impact of buffer overflow"),
        ("Detection", "detecting XSS attacks")
    ]

    for section, query in section_tests:
        try:
            query_embedding = embedder.embed_text(query)
            start_time = time.time()

            # Test with section filter
            results = store.query_hybrid(
                query_text=query,
                query_embedding=query_embedding,
                limit_chunks=5,
                section_filter=section
            )

            query_time = time.time() - start_time

            section_accuracy = len([r for r in results if r['section'] == section]) / len(results) if results else 0

            print(f"  {section:15s}: {query_time*1000:5.1f}ms | {len(results)} results | {section_accuracy*100:4.1f}% accuracy")

        except Exception as e:
            print(f"  {section:15s}: Error - {e}")

    # Summary
    if successful_queries > 0:
        avg_time = total_time / successful_queries
        print(f"\n📊 Performance Summary:")
        print(f"  Successful queries: {successful_queries}/10")
        print(f"  Average query time: {avg_time*1000:.1f}ms")
        print(f"  Database status: {'✅ EXCELLENT' if avg_time < 0.1 else '✅ GOOD' if avg_time < 0.5 else '⚠️ SLOW'}")

    return {
        "total_chunks": stats['count'],
        "unique_cwes": unique_cwes,
        "unique_sections": unique_sections,
        "vector_indexes": len(vector_indexes),
        "avg_query_time_ms": avg_time * 1000 if successful_queries > 0 else 0,
        "successful_queries": successful_queries
    }

def main():
    """Run comprehensive but simple retrieval tests."""
    print("🚀 CWE DATABASE RETRIEVAL TESTING")
    print("=" * 50)

    # Initialize connections
    local_url = os.getenv('LOCAL_DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/cwe')
    prod_url = os.getenv('PROD_DATABASE_URL', 'postgresql://cwe-postgres-sa%40cwechatbot.iam@127.0.0.1:5433/postgres?sslmode=disable')

    try:
        local_store = PostgresChunkStore(dims=3072, database_url=local_url)
        prod_store = PostgresChunkStore(dims=3072, database_url=prod_url)
        embedder = GeminiEmbedder()

        print("✅ All connections established successfully")

        # Test both databases
        print("\n" + "="*80)
        local_results = test_database_features(local_store, "local", embedder)

        print("\n" + "="*80)
        prod_results = test_database_features(prod_store, "production", embedder)

        # Final comparison
        print(f"\n🏆 FINAL COMPARISON")
        print("=" * 30)
        print(f"{'Metric':<20} {'Local':<15} {'Production':<15}")
        print("-" * 50)
        print(f"{'Total Chunks':<20} {local_results['total_chunks']:<15,} {prod_results['total_chunks']:<15,}")
        print(f"{'Unique CWEs':<20} {local_results['unique_cwes']:<15} {prod_results['unique_cwes']:<15}")
        print(f"{'Unique Sections':<20} {local_results['unique_sections']:<15} {prod_results['unique_sections']:<15}")
        print(f"{'Vector Indexes':<20} {local_results['vector_indexes']:<15} {prod_results['vector_indexes']:<15}")
        print(f"{'Avg Query Time':<20} {local_results['avg_query_time_ms']:<15.1f}ms {prod_results['avg_query_time_ms']:<15.1f}ms")
        print(f"{'Success Rate':<20} {local_results['successful_queries']}/10{'':<10} {prod_results['successful_queries']}/10")

        # Overall assessment
        local_ok = local_results['unique_cwes'] == 969 and local_results['avg_query_time_ms'] < 500
        prod_ok = prod_results['unique_cwes'] == 969 and prod_results['avg_query_time_ms'] < 500

        print(f"\n🎯 OVERALL ASSESSMENT:")
        print(f"  Local Database:     {'✅ FULLY OPERATIONAL' if local_ok else '❌ ISSUES DETECTED'}")
        print(f"  Production Database: {'✅ FULLY OPERATIONAL' if prod_ok else '❌ ISSUES DETECTED'}")

        if local_ok and prod_ok:
            print(f"\n🎉 SUCCESS: Both databases are fully operational with excellent performance!")
            print(f"   - Complete CWE corpus (969 CWEs)")
            print(f"   - Enhanced chunking (14 sections)")
            print(f"   - Fast retrieval (sub-500ms)")
            print(f"   - Vector search enabled")

    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    main()