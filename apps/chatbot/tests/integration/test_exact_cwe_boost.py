"""
Integration test for exact CWE ID boost in QueryHandler.
Verifies queries with CWE variants prioritize the exact CWE in top results.
"""

import os
import sys
from pathlib import Path
import pytest
import asyncio


@pytest.mark.integration
@pytest.mark.requires_secrets
@pytest.mark.skipif(
    not all(os.getenv(k) for k in [
        "POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DATABASE",
        "POSTGRES_USER", "POSTGRES_PASSWORD", "GEMINI_API_KEY"
    ]),
    reason="Database and GEMINI_API_KEY required"
)
def test_exact_cwe_id_boost_direct():
    # Ensure cwe_ingestion is importable for QueryHandler fallback path
    here = Path(__file__).resolve()
    cwe_path = here.parents[3] / "cwe_ingestion"
    os.environ.setdefault("CWE_INGESTION_PATH", str(cwe_path))

    from src.query_handler import CWEQueryHandler

    db_url = os.getenv("DATABASE_URL") or (
        f"postgresql://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}@"
        f"{os.getenv('POSTGRES_HOST')}:{os.getenv('POSTGRES_PORT')}/{os.getenv('POSTGRES_DATABASE')}"
    )
    gh = CWEQueryHandler(database_url=db_url, gemini_api_key=os.getenv("GEMINI_API_KEY"))

    cases = [
        ("Explain CWE-79 in simple terms", "CWE-79"),
        ("Explain cwe_123 in simple terms", "CWE-123"),
        ("Explain CWE 80 in simple terms", "CWE-80"),
        ("Explain cwe 33 in simple terms", "CWE-33"),
    ]

    async def run_case(q, expected):
        results = await gh.process_query(q, {"persona": "Developer"})
        assert results, f"No results for query: {q}"
        top_cwe = (results[0].get("metadata") or {}).get("cwe_id")
        assert str(top_cwe).upper() == expected, f"Top CWE mismatch for '{q}': {top_cwe} != {expected}"

    loop = asyncio.get_event_loop()
    for q, exp in cases:
        loop.run_until_complete(run_case(q, exp))
