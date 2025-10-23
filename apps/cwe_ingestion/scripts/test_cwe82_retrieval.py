#!/usr/bin/env python3
"""
Test CWE-82 retrieval from production database.
"""
import os
import sys

# Add apps/cwe_ingestion to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "apps", "cwe_ingestion"))

from cwe_ingestion.embedder import GeminiEmbedder
from cwe_ingestion.pg_chunk_store import PostgresChunkStore


def main():
    """Test CWE-82 specific retrieval."""
    print("🔍 Testing CWE-82 Retrieval")
    print("=" * 60)

    # Connect to production database
    prod_url = os.getenv(
        "PROD_DATABASE_URL",
        "postgresql://cwe-postgres-sa%40cwechatbot.iam@127.0.0.1:5433/postgres?sslmode=disable",
    )

    try:
        store = PostgresChunkStore(dims=3072, database_url=prod_url)
        embedder = GeminiEmbedder()
        print("✅ Connected to production database")

        # Check if CWE-82 exists in database
        print("\n1️⃣ Checking if CWE-82 exists in database...")
        with store.conn.cursor() as cur:
            cur.execute(
                "SELECT cwe_id, name, section, LEFT(text, 100) FROM cwe_chunks WHERE cwe_id = 'CWE-82' LIMIT 5;"
            )
            rows = cur.fetchall()

            if rows:
                print(f"✅ Found {len(rows)} chunks for CWE-82:")
                for row in rows:
                    print(f"   - {row[0]} | {row[1][:40]} | {row[2]}")
                    print(f"     Text: {row[3][:80]}...")
            else:
                print("❌ CWE-82 NOT FOUND in database")
                print("\nChecking if any CWE-8X exists:")
                cur.execute(
                    "SELECT DISTINCT cwe_id FROM cwe_chunks WHERE cwe_id LIKE 'CWE-8%' ORDER BY cwe_id LIMIT 20;"
                )
                similar_cwes = cur.fetchall()
                print(f"Found {len(similar_cwes)} CWE-8X entries:")
                for cwe in similar_cwes:
                    print(f"   - {cwe[0]}")
                return

        # Test hybrid search for CWE-82
        print("\n2️⃣ Testing hybrid search for CWE-82...")
        test_queries = [
            "What is CWE-82?",
            "CWE-82",
            "Improper Neutralization of Script in Attributes of IMG Tags",
            "IMG tag XSS",
        ]

        for query in test_queries:
            print(f"\n   Query: '{query}'")
            query_embedding = embedder.embed_text(query)
            results = store.query_hybrid(
                query_text=query, query_embedding=query_embedding, limit_chunks=10
            )

            if results:
                cwe_82_found = any(r["cwe_id"] == "CWE-82" for r in results)
                print(f"   Results: {len(results)} chunks")
                print(f"   CWE-82 in results: {'✅ YES' if cwe_82_found else '❌ NO'}")
                print(f"   Top 3 CWEs: {', '.join([r['cwe_id'] for r in results[:3]])}")

                if cwe_82_found:
                    cwe_82_results = [r for r in results if r["cwe_id"] == "CWE-82"]
                    print(
                        f"   CWE-82 sections: {', '.join([r['section'] for r in cwe_82_results])}"
                    )
            else:
                print("   ❌ No results returned")

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
