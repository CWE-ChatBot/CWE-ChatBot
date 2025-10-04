#!/usr/bin/env python3
"""
Load testing script for CWE database query performance.

Tests realistic query patterns under concurrent load to validate
performance targets (<500ms p95) before production deployment.
"""

import asyncio
import os
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import List

import psycopg2
from psycopg2.pool import ThreadedConnectionPool


@dataclass
class QueryResult:
    """Query execution result with timing."""
    query_type: str
    duration_ms: float
    success: bool
    error: str = ""


class DatabaseLoadTester:
    """Load testing for CWE database queries."""

    def __init__(self, connection_string: str, pool_size: int = 10):
        """Initialize load tester with connection pool."""
        self.connection_string = connection_string
        self.pool_size = pool_size

        # Parse connection string to extract components
        parts = {}
        for part in connection_string.split():
            if '=' in part:
                key, value = part.split('=', 1)
                parts[key] = value.strip("'")

        self.pool = ThreadedConnectionPool(
            minconn=1,
            maxconn=pool_size,
            host=parts.get('host'),
            port=int(parts.get('port', 5432)),
            dbname=parts.get('dbname'),
            user=parts.get('user'),
            password=parts.get('password'),
            sslmode=parts.get('sslmode', 'require')
        )

        # Sample queries representing realistic workload
        self.test_queries = [
            # Vector similarity search (most common query)
            ("vector_search", """
                SET LOCAL hnsw.ef_search = 32;
                SET LOCAL enable_seqscan = off;
                SELECT cwe_id, section_type, content,
                       embedding_halfvec <=> %s::halfvec AS distance
                FROM cwe_chunks
                ORDER BY embedding_halfvec <=> %s::halfvec
                LIMIT 10;
            """),

            # Full-text search
            ("fts_search", """
                SELECT cwe_id, section_type, content
                FROM cwe_chunks
                WHERE to_tsvector('english', content) @@ plainto_tsquery('english', %s)
                LIMIT 10;
            """),

            # Specific CWE lookup
            ("cwe_lookup", """
                SELECT cwe_id, section_type, content
                FROM cwe_chunks
                WHERE cwe_id = %s
                ORDER BY section_type;
            """),

            # Hybrid search (vector + FTS)
            ("hybrid_search", """
                WITH vector_results AS (
                    SELECT cwe_id, section_type, content,
                           (embedding_halfvec <=> %s::halfvec) * 0.65 AS vector_score
                    FROM cwe_chunks
                    ORDER BY embedding_halfvec <=> %s::halfvec
                    LIMIT 50
                ),
                fts_results AS (
                    SELECT cwe_id, section_type, content,
                           ts_rank(to_tsvector('english', content),
                                   plainto_tsquery('english', %s)) * 0.35 AS fts_score
                    FROM cwe_chunks
                    WHERE to_tsvector('english', content) @@ plainto_tsquery('english', %s)
                    LIMIT 50
                )
                SELECT COALESCE(v.cwe_id, f.cwe_id) as cwe_id,
                       COALESCE(v.content, f.content) as content,
                       COALESCE(v.vector_score, 0) + COALESCE(f.fts_score, 0) as total_score
                FROM vector_results v
                FULL OUTER JOIN fts_results f ON v.cwe_id = f.cwe_id AND v.section_type = f.section_type
                ORDER BY total_score DESC
                LIMIT 10;
            """),
        ]

        # Sample test data
        self.sample_embedding = self._generate_sample_embedding()
        self.sample_queries = [
            "buffer overflow vulnerability",
            "SQL injection attack",
            "cross-site scripting",
            "authentication bypass",
            "path traversal"
        ]
        self.sample_cwe_ids = ["CWE-79", "CWE-89", "CWE-120", "CWE-787", "CWE-20"]

    def _generate_sample_embedding(self) -> str:
        """Generate a sample embedding vector for testing."""
        # Use a realistic embedding (3072 dimensions of small floats)
        # Using a simple pattern to avoid embedding API call
        vector = [0.001 * (i % 100) for i in range(3072)]
        return '[' + ','.join(str(v) for v in vector) + ']'

    def execute_query(self, query_type: str, query: str, params: tuple) -> QueryResult:
        """Execute a single query and measure performance."""
        conn = None
        try:
            start_time = time.time()
            conn = self.pool.getconn()

            with conn.cursor() as cursor:
                cursor.execute(query, params)
                results = cursor.fetchall()

            duration_ms = (time.time() - start_time) * 1000

            return QueryResult(
                query_type=query_type,
                duration_ms=duration_ms,
                success=True
            )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return QueryResult(
                query_type=query_type,
                duration_ms=duration_ms,
                success=False,
                error=str(e)
            )

        finally:
            if conn:
                self.pool.putconn(conn)

    def run_single_query_test(self, iterations: int = 100) -> List[QueryResult]:
        """Run single-threaded query test."""
        print(f"\n=== Single-Threaded Test ({iterations} iterations) ===")
        results = []

        for i in range(iterations):
            # Rotate through different query types
            query_idx = i % len(self.test_queries)
            query_type, query = self.test_queries[query_idx]

            # Prepare parameters based on query type
            if query_type == "vector_search":
                params = (self.sample_embedding, self.sample_embedding)
            elif query_type == "fts_search":
                params = (self.sample_queries[i % len(self.sample_queries)],)
            elif query_type == "cwe_lookup":
                params = (self.sample_cwe_ids[i % len(self.sample_cwe_ids)],)
            elif query_type == "hybrid_search":
                q = self.sample_queries[i % len(self.sample_queries)]
                params = (self.sample_embedding, self.sample_embedding, q, q)

            result = self.execute_query(query_type, query, params)
            results.append(result)

            if (i + 1) % 20 == 0:
                print(f"  Progress: {i + 1}/{iterations} queries...")

        return results

    def run_concurrent_query_test(self, total_queries: int = 100, workers: int = 4) -> List[QueryResult]:
        """Run concurrent query test with multiple workers."""
        print(f"\n=== Concurrent Test ({total_queries} queries, {workers} workers) ===")
        results = []

        def execute_batch(batch_size):
            batch_results = []
            for i in range(batch_size):
                query_idx = i % len(self.test_queries)
                query_type, query = self.test_queries[query_idx]

                if query_type == "vector_search":
                    params = (self.sample_embedding, self.sample_embedding)
                elif query_type == "fts_search":
                    params = (self.sample_queries[i % len(self.sample_queries)],)
                elif query_type == "cwe_lookup":
                    params = (self.sample_cwe_ids[i % len(self.sample_cwe_ids)],)
                elif query_type == "hybrid_search":
                    q = self.sample_queries[i % len(self.sample_queries)]
                    params = (self.sample_embedding, self.sample_embedding, q, q)

                result = self.execute_query(query_type, query, params)
                batch_results.append(result)
            return batch_results

        # Distribute work across workers
        queries_per_worker = total_queries // workers

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(execute_batch, queries_per_worker) for _ in range(workers)]
            for future in futures:
                results.extend(future.result())

        return results

    def analyze_results(self, results: List[QueryResult], test_name: str):
        """Analyze and print query performance statistics."""
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]

        if not successful:
            print(f"\n❌ {test_name}: All queries failed!")
            return

        durations = [r.duration_ms for r in successful]

        # Calculate percentiles
        p50 = statistics.median(durations)
        p95 = statistics.quantiles(durations, n=20)[18] if len(durations) > 1 else durations[0]
        p99 = statistics.quantiles(durations, n=100)[98] if len(durations) > 1 else durations[0]

        print(f"\n📊 {test_name} Results:")
        print(f"  Total queries:    {len(results)}")
        print(f"  Successful:       {len(successful)} ({len(successful)/len(results)*100:.1f}%)")
        print(f"  Failed:           {len(failed)} ({len(failed)/len(results)*100:.1f}%)")
        print(f"\n  Performance:")
        print(f"    Mean:           {statistics.mean(durations):.2f} ms")
        print(f"    Median (p50):   {p50:.2f} ms")
        print(f"    p95:            {p95:.2f} ms {'✅' if p95 < 500 else '⚠️'}")
        print(f"    p99:            {p99:.2f} ms")
        print(f"    Min:            {min(durations):.2f} ms")
        print(f"    Max:            {max(durations):.2f} ms")

        # Performance breakdown by query type
        print(f"\n  By Query Type:")
        query_types = set(r.query_type for r in successful)
        for qt in sorted(query_types):
            qt_results = [r.duration_ms for r in successful if r.query_type == qt]
            qt_mean = statistics.mean(qt_results)
            qt_p95 = statistics.quantiles(qt_results, n=20)[18] if len(qt_results) > 1 else qt_results[0]
            print(f"    {qt:20s}: mean={qt_mean:6.2f}ms, p95={qt_p95:6.2f}ms")

        # Show errors if any
        if failed:
            print(f"\n  ❌ Errors:")
            error_counts = {}
            for r in failed:
                error_counts[r.error] = error_counts.get(r.error, 0) + 1
            for error, count in sorted(error_counts.items(), key=lambda x: -x[1])[:5]:
                print(f"    [{count}x] {error[:100]}")

        # Target validation
        print(f"\n  Target Validation:")
        if p95 < 500:
            print(f"    ✅ p95 < 500ms target: PASS ({p95:.2f}ms)")
        else:
            print(f"    ⚠️  p95 < 500ms target: FAIL ({p95:.2f}ms, {p95-500:.2f}ms over)")

        if statistics.mean(durations) < 200:
            print(f"    ✅ Mean < 200ms target: PASS ({statistics.mean(durations):.2f}ms)")
        else:
            print(f"    ℹ️  Mean < 200ms target: {statistics.mean(durations):.2f}ms (local target)")

    def run_all_tests(self):
        """Run complete load test suite."""
        print("=" * 70)
        print("CWE Database Load Testing")
        print("=" * 70)
        print(f"Connection pool size: {self.pool_size}")
        print(f"Test queries: {len(self.test_queries)}")

        # Test 1: Single-threaded baseline
        results_single = self.run_single_query_test(iterations=50)
        self.analyze_results(results_single, "Single-Threaded Baseline")

        # Test 2: Moderate concurrent load (4 workers)
        results_concurrent_4 = self.run_concurrent_query_test(total_queries=100, workers=4)
        self.analyze_results(results_concurrent_4, "Concurrent Load (4 workers)")

        # Test 3: Higher concurrent load (8 workers)
        results_concurrent_8 = self.run_concurrent_query_test(total_queries=100, workers=8)
        self.analyze_results(results_concurrent_8, "Concurrent Load (8 workers)")

        # Test 4: Stress test (max pool size)
        results_stress = self.run_concurrent_query_test(total_queries=100, workers=self.pool_size)
        self.analyze_results(results_stress, f"Stress Test ({self.pool_size} workers)")

        print("\n" + "=" * 70)
        print("Load Testing Complete")
        print("=" * 70)

    def close(self):
        """Close connection pool."""
        self.pool.closeall()


def main():
    """Main entry point."""
    # Read connection details from environment
    db_host = os.getenv('DB_HOST', '10.43.0.3')
    db_port = os.getenv('DB_PORT', '5432')
    db_name = os.getenv('DB_NAME', 'postgres')
    db_user = os.getenv('DB_USER', 'app_user')
    db_password = os.getenv('DB_PASSWORD')

    if not db_password:
        print("❌ Error: DB_PASSWORD environment variable not set")
        print("\nUsage:")
        print("  export DB_PASSWORD='your-password'")
        print("  python load_test_database.py")
        return 1

    connection_string = (
        f"host={db_host} "
        f"port={db_port} "
        f"dbname={db_name} "
        f"user={db_user} "
        f"password='{db_password}' "
        f"sslmode=require"
    )

    tester = DatabaseLoadTester(connection_string, pool_size=10)

    try:
        tester.run_all_tests()
    finally:
        tester.close()

    return 0


if __name__ == '__main__':
    exit(main())
