#!/usr/bin/env python3
"""
Test halfvec performance optimizations for <200ms p95 target.
Validates the new query_similar_fast and query_hybrid_fast methods.
"""

import os
import time
import numpy as np
from statistics import mean, median
from pg_chunk_store import PostgresChunkStore
from embedder import GeminiEmbedder

def benchmark_query_method(store: PostgresChunkStore, embedder: GeminiEmbedder,
                          method_name: str, query_func, iterations: int = 10):
    """Benchmark a query method with multiple iterations for p95 analysis."""
    print(f"\n🚀 Benchmarking {method_name}")
    print("-" * 50)

    test_queries = [
        "SQL injection vulnerabilities",
        "Cross-site scripting attacks",
        "Buffer overflow memory corruption",
        "Command injection exploits",
        "Authentication bypass methods"
    ]

    all_times = []
    results_summary = []

    for i, query in enumerate(test_queries, 1):
        print(f"\n[{i}/5] Query: '{query}'")

        # Generate embedding once
        embedding_start = time.time()
        query_embedding = embedder.embed_text(query)
        embedding_time = time.time() - embedding_start

        query_times = []

        # Run multiple iterations for statistical analysis
        for iteration in range(iterations):
            start_time = time.time()
            try:
                if method_name.endswith("_fast"):
                    results = query_func(query_embedding, n_results=10)
                elif "hybrid" in method_name:
                    results = query_func(query, query_embedding, limit_chunks=10)
                else:
                    results = query_func(query_embedding, n_results=10)

                query_time = time.time() - start_time
                query_times.append(query_time)

                if iteration == 0:  # Show first result
                    print(f"  Results: {len(results)} chunks")
                    if results:
                        if isinstance(results[0], dict) and 'metadata' in results[0]:
                            print(f"  Top: {results[0]['metadata']['cwe_id']}")
                        elif isinstance(results[0], dict) and 'cwe_id' in results[0]:
                            print(f"  Top: {results[0]['cwe_id']}")

            except Exception as e:
                print(f"  ❌ Error in iteration {iteration+1}: {e}")
                continue

        if query_times:
            avg_time = mean(query_times)
            median_time = median(query_times)
            p95_time = sorted(query_times)[int(0.95 * len(query_times))]

            total_time = embedding_time + avg_time

            print(f"  Embedding: {embedding_time*1000:5.1f}ms")
            print(f"  Query avg: {avg_time*1000:5.1f}ms")
            print(f"  Query p95: {p95_time*1000:5.1f}ms")
            print(f"  Total avg: {total_time*1000:5.1f}ms")

            status = "✅ EXCELLENT" if p95_time < 0.02 else "✅ GOOD" if p95_time < 0.1 else "⚠️ SLOW"
            print(f"  Status: {status}")

            all_times.extend(query_times)
            results_summary.append({
                "query": query,
                "embedding_ms": embedding_time * 1000,
                "avg_query_ms": avg_time * 1000,
                "p95_query_ms": p95_time * 1000,
                "total_avg_ms": total_time * 1000
            })

    if all_times:
        overall_avg = mean(all_times) * 1000
        overall_p95 = sorted(all_times)[int(0.95 * len(all_times))] * 1000
        overall_median = median(all_times) * 1000

        print(f"\n📊 {method_name.upper()} SUMMARY:")
        print(f"  Iterations per query: {iterations}")
        print(f"  Total samples: {len(all_times)}")
        print(f"  Average query time: {overall_avg:.1f}ms")
        print(f"  Median query time: {overall_median:.1f}ms")
        print(f"  P95 query time: {overall_p95:.1f}ms")

        target_status = "✅ TARGET MET" if overall_p95 < 20 else "⚠️ ABOVE TARGET"
        print(f"  P95 vs 20ms target: {target_status}")

        return {
            "method": method_name,
            "avg_ms": overall_avg,
            "median_ms": overall_median,
            "p95_ms": overall_p95,
            "samples": len(all_times),
            "results": results_summary
        }

    return None

def test_database_performance(store: PostgresChunkStore, embedder: GeminiEmbedder, db_name: str):
    """Test all query methods on a database."""
    print(f"\n🔍 {db_name.upper()} DATABASE PERFORMANCE TESTING")
    print("=" * 60)

    # Check halfvec availability
    with store.conn.cursor() as cur:
        cur.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'cwe_chunks' AND column_name = 'embedding_h'
        """)
        has_halfvec = cur.fetchone() is not None

        if not has_halfvec:
            print("❌ Halfvec column not found! Run migrate_to_halfvec.py first.")
            return None

    results = {}

    # Test original vector query
    print("\n" + "="*70)
    results['original'] = benchmark_query_method(
        store, embedder, "Original vector(3072)",
        store.query_similar, iterations=5
    )

    # Test optimized halfvec query
    print("\n" + "="*70)
    results['halfvec'] = benchmark_query_method(
        store, embedder, "Optimized halfvec_fast",
        store.query_similar_fast, iterations=10
    )

    # Test hybrid fast query
    print("\n" + "="*70)
    results['hybrid'] = benchmark_query_method(
        store, embedder, "Hybrid halfvec_fast",
        store.query_hybrid_fast, iterations=10
    )

    return results

def main():
    """Run halfvec performance validation tests."""
    print("🚀 HALFVEC PERFORMANCE VALIDATION")
    print("=" * 50)
    print("Target: <20ms p95 query time for 200ms p95 end-to-end")

    # Database URLs
    local_url = os.getenv('LOCAL_DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/cwe')
    prod_url = os.getenv('PROD_DATABASE_URL', 'postgresql://cwe-postgres-sa%40cwechatbot.iam@127.0.0.1:5433/postgres?sslmode=disable')

    try:
        local_store = PostgresChunkStore(dims=3072, database_url=local_url)
        prod_store = PostgresChunkStore(dims=3072, database_url=prod_url)
        embedder = GeminiEmbedder()

        print("✅ All connections established successfully")

        # Test local database
        print("\n" + "="*80)
        local_results = test_database_performance(local_store, embedder, "local")

        # Test production database
        print("\n" + "="*80)
        prod_results = test_database_performance(prod_store, embedder, "production")

        # Comparison summary
        print("\n" + "="*80)
        print("🏆 PERFORMANCE COMPARISON")
        print("=" * 40)

        if local_results and prod_results:
            print(f"{'Method':<20} {'Local P95':<12} {'Prod P95':<12} {'Speedup'}")
            print("-" * 55)

            for method in ['original', 'halfvec', 'hybrid']:
                if method in local_results and method in prod_results:
                    local_p95 = local_results[method]['p95_ms']
                    prod_p95 = prod_results[method]['p95_ms']

                    # Calculate speedup vs original
                    if method != 'original' and 'original' in local_results:
                        original_p95 = local_results['original']['p95_ms']
                        speedup = f"{original_p95/local_p95:.1f}x" if local_p95 > 0 else "N/A"
                    else:
                        speedup = "baseline"

                    print(f"{method:<20} {local_p95:<12.1f} {prod_p95:<12.1f} {speedup}")

        # Final assessment
        print("\n🎯 TARGET ASSESSMENT:")
        if local_results and 'halfvec' in local_results:
            local_p95 = local_results['halfvec']['p95_ms']
            target_met = local_p95 < 20
            print(f"  Local halfvec p95: {local_p95:.1f}ms ({'✅ TARGET MET' if target_met else '⚠️ ABOVE TARGET'})")

        if prod_results and 'halfvec' in prod_results:
            prod_p95 = prod_results['halfvec']['p95_ms']
            # Production target is higher due to network overhead
            prod_target_met = prod_p95 < 100
            print(f"  Prod halfvec p95: {prod_p95:.1f}ms ({'✅ ACCEPTABLE' if prod_target_met else '⚠️ SLOW'})")

        print(f"\n📊 Next steps:")
        print(f"  - Use query_similar_fast() for pure vector search")
        print(f"  - Use query_hybrid_fast() for keyword+semantic search")
        print(f"  - Deploy app in us-central1 for production optimization")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()