#!/usr/bin/env python3
"""
Random CWE sampling test for systematic coverage.

This test randomly samples 30 CWEs from the entire corpus and validates
responses using LLM-as-judge. This helps detect systematic issues that
affect multiple CWEs, not just known problem cases.

Usage:
    # Run with specific seed for reproducibility
    RANDOM_SEED=42 poetry run pytest tests/integration/test_random_cwe_sampling.py

    # Run weekly as part of regression testing
    poetry run pytest tests/integration/test_random_cwe_sampling.py --weekly
"""
import asyncio
import os
import random
from typing import List

import pytest

# Import from the LLM judge test
from test_cwe_response_accuracy_llm_judge import (
    LLMJudge,
    MITREGroundTruth,
)


def get_all_cwe_ids(min_id: int = 1, max_id: int = 1425) -> List[str]:
    """
    Get all CWE IDs from MITRE CWE range.

    Args:
        min_id: Minimum CWE ID number (default: 1)
        max_id: Maximum CWE ID number (default: 1425 for CWE v4.18)

    Returns:
        List of CWE IDs like ['CWE-1', 'CWE-2', ...]
    """
    return [f"CWE-{i}" for i in range(min_id, max_id + 1)]


def sample_cwes(
    all_cwes: List[str], sample_size: int = 30, seed: int = None
) -> List[str]:
    """
    Sample random CWEs with optional seed for reproducibility.

    Args:
        all_cwes: List of all CWE IDs
        sample_size: Number of CWEs to sample
        seed: Random seed for reproducibility

    Returns:
        List of sampled CWE IDs
    """
    if seed is not None:
        random.seed(seed)

    return random.sample(all_cwes, min(sample_size, len(all_cwes)))


@pytest.mark.asyncio
@pytest.mark.skip(
    reason="Integration test - requires chatbot API running (CHATBOT_URL) and GEMINI_API_KEY"
)
async def test_random_cwe_sample_systematic_coverage():
    """
    Test 30 random CWEs to detect systematic issues across corpus.

    This test helps identify:
    - Ingestion failures (missing CWEs in database)
    - Retrieval issues (force-injection not working)
    - Response generation problems (LLM hallucinations)
    - Systematic patterns (e.g., all CWEs with certain characteristics fail)
    """
    # Configuration
    sample_size = 30
    max_failure_rate = 0.10  # Allow 10% failures (3/30) for edge cases
    seed = int(os.getenv("RANDOM_SEED", None) or random.randint(1, 10000))

    print(f"\n🎲 Random CWE Sampling Test (seed={seed})")
    print("=" * 60)

    # Initialize
    mitre = MITREGroundTruth()
    judge = LLMJudge()

    # Get sample
    all_cwes = get_all_cwe_ids()
    sample = sample_cwes(all_cwes, sample_size, seed)

    print(f"📋 Sampling {sample_size} CWEs from {len(all_cwes)} total")
    print(
        f"Sample: {', '.join(sample[:10])}..."
        if len(sample) > 10
        else f"Sample: {', '.join(sample)}"
    )
    print()

    # Track results
    results = {
        "PASS": [],
        "PARTIAL": [],
        "FAIL": [],
        "SKIP": [],
        "ERROR": [],
    }

    # Test each CWE
    for i, cwe_id in enumerate(sample, 1):
        print(f"[{i}/{sample_size}] Testing {cwe_id}...", end=" ")

        # Get ground truth
        ground_truth = mitre.fetch_cwe_description(cwe_id)
        if "error" in ground_truth:
            print(f"⏭️  Skipped: {ground_truth['error']}")
            results["SKIP"].append((cwe_id, ground_truth["error"]))
            continue

        # Query chatbot (placeholder - replace with actual API call)
        chatbot_response = await query_chatbot_placeholder(cwe_id)

        # Judge response
        verdict = await judge.evaluate(cwe_id, ground_truth, chatbot_response)
        verdict_type = verdict["verdict"]

        # Print result
        emoji_map = {
            "PASS": "✅",
            "PARTIAL": "⚠️",
            "FAIL": "❌",
            "ERROR": "🔥",
        }
        emoji = emoji_map.get(verdict_type, "❓")
        print(f"{emoji} {verdict_type}: {verdict['reasoning'][:60]}...")

        # Store result
        results[verdict_type].append((cwe_id, verdict["reasoning"]))

    # Print summary
    print("\n" + "=" * 60)
    print("📊 SUMMARY")
    print("=" * 60)

    total_tested = sum(len(results[k]) for k in ["PASS", "PARTIAL", "FAIL", "ERROR"])
    total_failures = len(results["FAIL"])
    failure_rate = total_failures / total_tested if total_tested > 0 else 0

    print(f"✅ PASS:    {len(results['PASS']):2d}/{sample_size}")
    print(f"⚠️  PARTIAL: {len(results['PARTIAL']):2d}/{sample_size}")
    print(f"❌ FAIL:    {len(results['FAIL']):2d}/{sample_size}")
    print(f"⏭️  SKIP:    {len(results['SKIP']):2d}/{sample_size}")
    print(f"🔥 ERROR:   {len(results['ERROR']):2d}/{sample_size}")
    print(f"\nFailure Rate: {failure_rate * 100:.1f}%")

    # Print failures detail
    if results["FAIL"]:
        print("\n❌ FAILED CWEs:")
        for cwe_id, reasoning in results["FAIL"]:
            print(f"  {cwe_id}: {reasoning}")

    # Assert failure rate acceptable
    assert (
        failure_rate <= max_failure_rate
    ), f"Failure rate {failure_rate * 100:.1f}% exceeds threshold {max_failure_rate * 100:.1f}%"

    # Return summary for reporting
    return {
        "seed": seed,
        "sample_size": sample_size,
        "results": results,
        "failure_rate": failure_rate,
    }


async def query_chatbot_placeholder(cwe_id: str) -> str:
    """
    Query chatbot for CWE via REST API.

    Args:
        cwe_id: CWE ID to query

    Returns:
        Chatbot response text
    """
    import httpx

    chatbot_url = os.getenv("CHATBOT_URL", "http://localhost:8081")
    api_endpoint = f"{chatbot_url}/api/v1/query"
    api_key = os.getenv("TEST_API_KEY")

    if not api_key:
        raise ValueError(
            "TEST_API_KEY environment variable required for API authentication"
        )

    headers = {"X-API-Key": api_key}

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            api_endpoint,
            headers=headers,
            json={"query": f"What is {cwe_id}?", "persona": "Developer"},
        )
        response.raise_for_status()
        data = response.json()
        return data["response"]


# Standalone runner for debugging
async def run_random_sampling_standalone():
    """Run random sampling test standalone for debugging."""
    summary = await test_random_cwe_sample_systematic_coverage()

    print("\n" + "=" * 60)
    print("🎯 Test Complete")
    print("=" * 60)
    print(f"Seed: {summary['seed']} (use RANDOM_SEED={summary['seed']} to reproduce)")
    print(f"Pass Rate: {(1 - summary['failure_rate']) * 100:.1f}%")


if __name__ == "__main__":
    asyncio.run(run_random_sampling_standalone())
