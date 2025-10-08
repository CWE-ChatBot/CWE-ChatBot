#!/usr/bin/env python3
"""
Test runner for persona-based CWE retrieval queries.

This script executes the queries from test_queries_personas.py against the
production database to validate retrieval performance and accuracy.

Usage:
    poetry run python run_persona_query_tests.py
    poetry run python run_persona_query_tests.py --persona psirt
    poetry run python run_persona_query_tests.py --query-type semantic
    poetry run python run_persona_query_tests.py --max-queries 5
"""

import argparse
import os
import sys
import time
from typing import Any, Dict, List, Optional

from .test_queries_personas import (
    ALL_PERSONA_QUERIES,
    ALL_QUERIES,
    TestQuery,
    get_queries_by_persona,
)

# Import the required components
try:
    from embedder import GeminiEmbedder
    from pg_chunk_store import PostgresChunkStore
except ImportError as e:
    print(f"❌ Import error: {e}")
    print(
        "Make sure you're running from the correct directory with: poetry run python run_persona_query_tests.py"
    )
    sys.exit(1)


def format_results_summary(results: List[Dict[str, Any]]) -> str:
    """Format query results into a readable summary."""
    if not results:
        return "No results found"

    # Group by CWE ID
    cwe_groups: Dict[str, List[Dict[str, Any]]] = {}
    for result in results:
        cwe_id = result["metadata"]["cwe_id"]
        if cwe_id not in cwe_groups:
            cwe_groups[cwe_id] = []
        cwe_groups[cwe_id].append(result)

    summary_lines = []
    for i, (cwe_id, cwe_results) in enumerate(cwe_groups.items()):
        if i >= 3:  # Limit to top 3 CWEs
            break

        best_result = max(
            cwe_results, key=lambda x: x.get("scores", {}).get("hybrid", 0.0)
        )
        sections = [r["metadata"]["section"] for r in cwe_results]

        summary_lines.append(
            f"  {cwe_id}: {best_result['metadata']['name'][:50]}..."
            f" (score={best_result.get('scores', {}).get('hybrid', 0.0):.2f}, sections={','.join(sections[:2])})"
        )

    if len(cwe_groups) > 3:
        summary_lines.append(f"  ... and {len(cwe_groups) - 3} more CWEs")

    return "\n" + "\n".join(summary_lines)


def evaluate_query_accuracy(
    query: TestQuery, results: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Evaluate how well the query results match expectations."""
    if not results:
        return {
            "accuracy_score": 0.0,
            "expected_found": 0,
            "expected_total": len(query.expected_cwes),
            "top_match": False,
            "notes": "No results returned",
        }

    # Get CWEs found in results
    found_cwes = set(r["metadata"]["cwe_id"] for r in results)
    expected_cwes = set(query.expected_cwes)

    # Calculate accuracy metrics
    expected_found = len(expected_cwes.intersection(found_cwes))
    top_match = results[0]["metadata"]["cwe_id"] in expected_cwes if results else False

    accuracy_score = expected_found / len(expected_cwes) if expected_cwes else 0.0

    return {
        "accuracy_score": accuracy_score,
        "expected_found": expected_found,
        "expected_total": len(expected_cwes),
        "top_match": top_match,
        "found_cwes": list(found_cwes),
        "expected_cwes": list(expected_cwes),
        "notes": f"Found {expected_found}/{len(expected_cwes)} expected CWEs",
    }


def run_single_query_test(
    query: TestQuery,
    store: PostgresChunkStore,
    embedder: GeminiEmbedder,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Run a single query test and return detailed results."""

    print(f"\n{'='*60}")
    print(f"🔍 Testing: {query.persona} Query")
    print(f"Query: '{query.query_text}'")
    print(f"Use Case: {query.use_case}")
    print(f"Type: {query.query_type} | Expected: {', '.join(query.expected_cwes[:3])}")

    try:
        # Generate embedding
        embedding_start = time.time()
        query_embedding = embedder.embed_text(query.query_text)
        embedding_time = time.time() - embedding_start

        # Prepare query parameters
        query_params = {
            "query_text": query.query_text,
            "query_embedding": query_embedding,
            "limit_chunks": 15,
            "w_vec": query.optimal_weights.get("w_vec", 0.65),
            "w_fts": query.optimal_weights.get("w_fts", 0.25),
            "w_alias": query.optimal_weights.get("w_alias", 0.10),
        }

        if query.section_boost:
            query_params["section_intent_boost"] = query.section_boost
            query_params["section_boost_value"] = 0.15

        # Execute hybrid search
        search_start = time.time()
        results = store.query_hybrid(**query_params)
        search_time = time.time() - search_start

        total_time = embedding_time + search_time

        # Evaluate accuracy
        accuracy = evaluate_query_accuracy(query, results)

        # Print results
        print(
            f"⏱️  Timing: {total_time*1000:.1f}ms (embed: {embedding_time*1000:.1f}ms, search: {search_time*1000:.1f}ms)"
        )
        print(
            f"📊 Results: {len(results)} chunks, accuracy: {accuracy['accuracy_score']*100:.1f}%"
        )
        print(
            f"🎯 Expected: {accuracy['expected_found']}/{accuracy['expected_total']} CWEs found"
        )
        print(f"🏆 Top match: {'✅ YES' if accuracy['top_match'] else '❌ NO'}")

        if verbose:
            print(format_results_summary(results))

        # Determine success
        success = (
            accuracy["accuracy_score"] >= 0.5 and total_time < 2.0
        )  # 50% accuracy, under 2s
        status_icon = "✅" if success else "⚠️"
        print(f"{status_icon} Status: {'PASS' if success else 'NEEDS_REVIEW'}")

        return {
            "query": query,
            "success": success,
            "total_time": total_time,
            "embedding_time": embedding_time,
            "search_time": search_time,
            "results_count": len(results),
            "accuracy": accuracy,
            "results": results[:5]
            if verbose
            else [],  # Store top 5 for detailed analysis
        }

    except Exception as e:
        print(f"❌ Error: {e}")
        return {
            "query": query,
            "success": False,
            "error": str(e),
            "total_time": 0,
            "embedding_time": 0,
            "search_time": 0,
            "results_count": 0,
            "accuracy": {"accuracy_score": 0.0, "notes": f"Error: {e}"},
        }


def run_persona_query_tests(
    personas: Optional[List[str]] = None,
    query_types: Optional[List[str]] = None,
    max_queries: Optional[int] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Run persona-based query tests with filtering options."""

    print("🚀 CWE PERSONA QUERY TESTING")
    print("=" * 50)

    # Initialize connections
    database_url = os.getenv("DATABASE_URL") or os.getenv("LOCAL_DATABASE_URL")
    if not database_url:
        print("❌ No DATABASE_URL or LOCAL_DATABASE_URL environment variable set")
        print(
            "Set with: export DATABASE_URL='postgresql://postgres:postgres@localhost:5432/cwe'"
        )
        return {"success": False, "error": "No database URL"}

    try:
        store = PostgresChunkStore(dims=3072, database_url=database_url)
        embedder = GeminiEmbedder()
        print("✅ Connected to database and embedder")

        # Check database status
        stats = store.get_collection_stats()
        print(f"📊 Database contains {stats['count']:,} chunks")

        if stats["count"] == 0:
            print("⚠️  Database appears empty. Run ingestion first with:")
            print("   poetry run python cli.py ingest --chunked")
            return {"success": False, "error": "Empty database"}

    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return {"success": False, "error": str(e)}

    # Filter queries
    test_queries = ALL_QUERIES.copy()

    if personas:
        filtered_queries = []
        for persona in personas:
            filtered_queries.extend(get_queries_by_persona(persona))
        test_queries = filtered_queries

    if query_types:
        filtered_queries = []
        for query_type in query_types:
            filtered_queries.extend(
                [q for q in test_queries if q.query_type == query_type]
            )
        test_queries = filtered_queries

    if max_queries:
        test_queries = test_queries[:max_queries]

    print(f"🎯 Running {len(test_queries)} test queries...")

    # Run tests
    test_results = []
    start_time = time.time()

    for i, query in enumerate(test_queries, 1):
        print(f"\n[{i:2d}/{len(test_queries)}] ", end="")
        result = run_single_query_test(query, store, embedder, verbose)
        test_results.append(result)

    total_test_time = time.time() - start_time

    # Analyze results
    successful_tests = [r for r in test_results if r["success"]]
    failed_tests = [r for r in test_results if not r["success"]]

    if test_results:
        avg_query_time = sum(r["total_time"] for r in test_results) / len(test_results)
        avg_accuracy = sum(r["accuracy"]["accuracy_score"] for r in test_results) / len(
            test_results
        )
    else:
        avg_query_time = 0
        avg_accuracy = 0

    # Print summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    print(f"✅ Successful: {len(successful_tests)}/{len(test_results)}")
    print(f"❌ Failed: {len(failed_tests)}")
    print(f"⏱️  Average query time: {avg_query_time*1000:.1f}ms")
    print(f"🎯 Average accuracy: {avg_accuracy*100:.1f}%")
    print(f"🕐 Total test time: {total_test_time:.1f}s")

    # Per-persona breakdown
    if len(test_results) > 1:
        print("\n📈 Results by Persona:")
        persona_stats = {}
        for result in test_results:
            persona = result["query"].persona
            if persona not in persona_stats:
                persona_stats[persona] = {
                    "total": 0,
                    "successful": 0,
                    "avg_accuracy": 0,
                }

            persona_stats[persona]["total"] += 1
            if result["success"]:
                persona_stats[persona]["successful"] += 1
            persona_stats[persona]["avg_accuracy"] += result["accuracy"][
                "accuracy_score"
            ]

        for persona, stats in persona_stats.items():
            success_rate = stats["successful"] / stats["total"] * 100
            avg_acc = stats["avg_accuracy"] / stats["total"] * 100
            print(
                f"  {persona:20s}: {stats['successful']}/{stats['total']} ({success_rate:4.1f}%) | Avg accuracy: {avg_acc:4.1f}%"
            )

    # Issues to investigate
    if failed_tests:
        print("\n🔍 Issues to Investigate:")
        for result in failed_tests[:3]:  # Show top 3 failures
            query = result["query"]
            error = result.get("error", "Low accuracy or slow performance")
            print(f"  • {query.persona}: '{query.query_text[:50]}...' - {error}")

    overall_success = (
        len(successful_tests) / len(test_results) >= 0.8 if test_results else False
    )

    print(
        f"\n🎉 Overall Assessment: {'✅ EXCELLENT' if overall_success else '⚠️ NEEDS IMPROVEMENT'}"
    )

    return {
        "success": overall_success,
        "total_tests": len(test_results),
        "successful_tests": len(successful_tests),
        "failed_tests": len(failed_tests),
        "avg_query_time_ms": avg_query_time * 1000,
        "avg_accuracy_percent": avg_accuracy * 100,
        "total_test_time": total_test_time,
        "detailed_results": test_results,
    }


def main():
    """Main entry point with command line argument parsing."""
    parser = argparse.ArgumentParser(description="Run persona-based CWE query tests")
    parser.add_argument(
        "--persona",
        choices=list(ALL_PERSONA_QUERIES.keys()),
        help="Test only specific persona queries",
    )
    parser.add_argument(
        "--query-type",
        choices=["semantic", "keyword", "hybrid", "direct"],
        help="Test only specific query types",
    )
    parser.add_argument(
        "--max-queries", type=int, help="Limit number of queries to test"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed results for each query",
    )

    args = parser.parse_args()

    # Convert single values to lists for filtering
    personas = [args.persona] if args.persona else None
    query_types = [args.query_type] if args.query_type else None

    # Run tests
    results = run_persona_query_tests(
        personas=personas,
        query_types=query_types,
        max_queries=args.max_queries,
        verbose=args.verbose,
    )

    # Exit with appropriate code
    exit_code = 0 if results.get("success", False) else 1
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
