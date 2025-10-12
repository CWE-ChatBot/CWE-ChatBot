#!/usr/bin/env python3
"""
Integration tests for CWE response accuracy using LLM-as-judge.

This test suite validates that chatbot responses about specific CWEs match
the ground truth from MITRE CWE documentation. An LLM acts as a judge to
evaluate whether responses are accurate, complete, and not hallucinated.

Test coverage:
- 10 high-priority CWEs (common/critical weaknesses)
- 20 random CWEs from corpus
- 10 low-frequency CWEs (like CWE-82 that triggered the original bug)
"""
import asyncio
import os
import random
import re
from typing import Dict, List, Optional

import pytest
from src.llm_provider import get_llm_provider


class MITREGroundTruth:
    """Fetch ground truth CWE descriptions from MITRE CWE XML."""

    def __init__(self, xml_path: Optional[str] = None):
        """
        Initialize with path to CWE XML file.

        Args:
            xml_path: Path to cwec_latest.xml or cwec_vX.XX.xml
        """
        self.xml_path = xml_path or "/tmp/cwec_v4.18.xml"
        self._cwe_cache: Dict[str, Dict[str, str]] = {}

    def fetch_cwe_description(self, cwe_id: str) -> Dict[str, str]:
        """
        Extract CWE description from XML.

        Args:
            cwe_id: CWE ID like "CWE-82"

        Returns:
            Dict with name, description, extended_description
        """
        if cwe_id in self._cwe_cache:
            return self._cwe_cache[cwe_id]

        try:
            with open(self.xml_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Extract numeric ID from CWE-82 format
            numeric_id = cwe_id.replace("CWE-", "")

            # Find the weakness entry
            pattern = rf'<Weakness ID="{numeric_id}"[^>]*>(.*?)</Weakness>'
            match = re.search(pattern, content, re.DOTALL)

            if not match:
                return {"error": f"{cwe_id} not found in MITRE XML"}

            weakness_xml = match.group(1)

            # Extract name
            name_match = re.search(r'Name="([^"]+)"', match.group(0))
            name = name_match.group(1) if name_match else "Unknown"

            # Extract description
            desc_match = re.search(
                r"<Description>(.*?)</Description>", weakness_xml, re.DOTALL
            )
            description = (
                desc_match.group(1).strip() if desc_match else "No description"
            )

            # Extract extended description
            ext_desc_match = re.search(
                r"<Extended_Description>(.*?)</Extended_Description>",
                weakness_xml,
                re.DOTALL,
            )
            extended_description = (
                ext_desc_match.group(1).strip() if ext_desc_match else ""
            )

            # Clean XML tags from descriptions
            description = re.sub(r"<[^>]+>", "", description).strip()
            extended_description = re.sub(r"<[^>]+>", "", extended_description).strip()

            result = {
                "cwe_id": cwe_id,
                "name": name,
                "description": description,
                "extended_description": extended_description,
            }

            self._cwe_cache[cwe_id] = result
            return result

        except FileNotFoundError:
            return {
                "error": f"MITRE XML not found at {self.xml_path}. Download from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
            }
        except Exception as e:
            return {"error": f"Failed to parse {cwe_id}: {str(e)}"}


class LLMJudge:
    """LLM-based judge for evaluating chatbot response accuracy."""

    def __init__(
        self, api_key: Optional[str] = None, model_name: str = "gemini-2.0-flash-lite"
    ):
        """
        Initialize LLM judge.

        Args:
            api_key: Gemini API key (or from GEMINI_API_KEY env var)
            model_name: Model to use for judging
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "GEMINI_API_KEY required for LLM judge (set via env var or parameter)"
            )

        self.model_name = model_name
        self.provider = None

    def _get_provider(self):
        """Lazy initialize provider to avoid event loop issues."""
        if self.provider is None:
            self.provider = get_llm_provider(
                provider="google",
                api_key=self.api_key,
                model_name=self.model_name,
                generation_config={"temperature": 0.0},  # Deterministic judging
                safety_settings=None,
                offline=False,
            )
        return self.provider

    async def evaluate(
        self, cwe_id: str, ground_truth: Dict[str, str], chatbot_response: str
    ) -> Dict[str, str]:
        """
        Evaluate chatbot response against ground truth.

        Args:
            cwe_id: CWE ID being tested
            ground_truth: Dict with name, description from MITRE
            chatbot_response: Actual chatbot response text

        Returns:
            Dict with verdict (PASS/FAIL/PARTIAL) and reasoning
        """
        if "error" in ground_truth:
            return {"verdict": "SKIP", "reasoning": ground_truth["error"]}

        prompt = f"""You are evaluating a CWE chatbot's accuracy.

Ground Truth from MITRE CWE Database:
CWE ID: {ground_truth['cwe_id']}
Name: {ground_truth['name']}
Description: {ground_truth['description']}
{f"Extended: {ground_truth['extended_description']}" if ground_truth.get('extended_description') else ""}

Chatbot Response:
{chatbot_response}

Evaluation Criteria:
1. Does the response correctly identify {cwe_id}?
2. Does the response accurately describe what {cwe_id} is?
3. Is the core weakness concept correct (matches MITRE description)?
4. Are there any factual errors or hallucinations?

Verdict Guidelines:
- PASS: Response is accurate and matches ground truth (may be brief but not wrong)
- PARTIAL: Response is incomplete but not incorrect (missing details but core concept right)
- FAIL: Response is incorrect, describes wrong CWE, or contains hallucinations

Output Format (EXACTLY):
<verdict>PASS/FAIL/PARTIAL</verdict>
<reasoning>Brief explanation (1-2 sentences)</reasoning>
"""

        try:
            provider = self._get_provider()
            response = await provider.generate(prompt)

            # Extract verdict and reasoning
            verdict_match = re.search(
                r"<verdict>(PASS|FAIL|PARTIAL)</verdict>", response, re.IGNORECASE
            )
            reasoning_match = re.search(
                r"<reasoning>(.*?)</reasoning>", response, re.DOTALL | re.IGNORECASE
            )

            verdict = verdict_match.group(1).upper() if verdict_match else "FAIL"
            reasoning = (
                reasoning_match.group(1).strip() if reasoning_match else response[:200]
            )

            return {"verdict": verdict, "reasoning": reasoning}

        except Exception as e:
            return {"verdict": "ERROR", "reasoning": f"Judge evaluation failed: {e}"}


# Test data: High-priority CWEs from OWASP Top 10 and CWE Top 25
HIGH_PRIORITY_CWES = [
    "CWE-79",  # Cross-site Scripting (XSS)
    "CWE-89",  # SQL Injection
    "CWE-78",  # OS Command Injection
    "CWE-22",  # Path Traversal
    "CWE-352",  # CSRF
    "CWE-434",  # Unrestricted Upload
    "CWE-639",  # Insecure Direct Object References
    "CWE-798",  # Hardcoded Credentials
    "CWE-862",  # Missing Authorization
    "CWE-918",  # SSRF
]

# Low-frequency CWEs that might have poor hybrid search scores
LOW_FREQUENCY_CWES = [
    "CWE-15",  # External Control of System or Configuration Setting
    "CWE-36",  # Absolute Path Traversal
    "CWE-82",  # Improper Neutralization of Script in IMG Tags (the original bug!)
    "CWE-108",  # Struts File Disclosure
    "CWE-182",  # Collapse of Data into Unsafe Value
    "CWE-242",  # Use of Inherently Dangerous Function
    "CWE-324",  # Use of a Key Past its Expiration Date
    "CWE-470",  # Use of Externally-Controlled Input to Select Classes or Code
    "CWE-641",  # Improper Restriction of Names for Files
    "CWE-829",  # Inclusion of Functionality from Untrusted Control Sphere
]


@pytest.mark.asyncio
class TestCWEResponseAccuracyWithLLMJudge:
    """Integration tests for CWE response accuracy using LLM-as-judge."""

    @pytest.fixture(scope="class")
    def mitre_ground_truth(self):
        """Initialize MITRE ground truth fetcher."""
        return MITREGroundTruth()

    @pytest.fixture(scope="function")
    def llm_judge(self):
        """Initialize LLM judge (function scope to avoid event loop issues)."""
        return LLMJudge()

    async def query_chatbot(self, cwe_id: str) -> str:
        """
        Query the chatbot for a specific CWE via REST API.

        Args:
            cwe_id: CWE ID to query

        Returns:
            Chatbot response text
        """
        import asyncio

        import httpx

        chatbot_url = os.getenv("CHATBOT_URL", "http://localhost:8081")
        api_endpoint = f"{chatbot_url}/api/v1/query"
        api_key = os.getenv("TEST_API_KEY")

        if not api_key:
            raise ValueError(
                "TEST_API_KEY environment variable required for API authentication"
            )

        headers = {"X-API-Key": api_key}

        # Rate limiting: 10 req/min = 6 seconds between requests
        await asyncio.sleep(7)

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                api_endpoint,
                headers=headers,
                json={"query": f"What is {cwe_id}?", "persona": "Developer"},
            )
            response.raise_for_status()
            data = response.json()
            return data["response"]

    @pytest.mark.parametrize("cwe_id", HIGH_PRIORITY_CWES)
    async def test_high_priority_cwe_accuracy(
        self, cwe_id, mitre_ground_truth, llm_judge
    ):
        """Test accuracy for high-priority CWEs (OWASP/CWE Top 25)."""
        # Get ground truth
        ground_truth = mitre_ground_truth.fetch_cwe_description(cwe_id)
        if "error" in ground_truth:
            pytest.skip(ground_truth["error"])

        # Query chatbot
        chatbot_response = await self.query_chatbot(cwe_id)

        # Judge response
        verdict = await llm_judge.evaluate(cwe_id, ground_truth, chatbot_response)

        # Log verdict for documentation
        print(f"\n{cwe_id} Judge Verdict: {verdict['verdict']}")
        print(f"{cwe_id} Judge Reasoning: {verdict['reasoning']}")

        # Assert verdict
        assert verdict["verdict"] in [
            "PASS",
            "PARTIAL",
        ], f"{cwe_id} failed: {verdict['reasoning']}"

    @pytest.mark.parametrize("cwe_id", LOW_FREQUENCY_CWES)
    async def test_low_frequency_cwe_accuracy(
        self, cwe_id, mitre_ground_truth, llm_judge
    ):
        """Test accuracy for low-frequency CWEs (like CWE-82)."""
        # Get ground truth
        ground_truth = mitre_ground_truth.fetch_cwe_description(cwe_id)
        if "error" in ground_truth:
            pytest.skip(ground_truth["error"])

        # Query chatbot
        chatbot_response = await self.query_chatbot(cwe_id)

        # Judge response
        verdict = await llm_judge.evaluate(cwe_id, ground_truth, chatbot_response)

        # Log verdict for documentation
        print(f"\n{cwe_id} Judge Verdict: {verdict['verdict']}")
        print(f"{cwe_id} Judge Reasoning: {verdict['reasoning']}")

        # Assert verdict (allow PARTIAL for low-frequency CWEs)
        assert verdict["verdict"] in [
            "PASS",
            "PARTIAL",
        ], f"{cwe_id} failed: {verdict['reasoning']}"

    async def test_random_cwe_sample_accuracy(self, mitre_ground_truth, llm_judge):
        """Test accuracy for 20 random CWEs to detect systematic issues."""
        # Get all CWE IDs from 1 to 1425 (MITRE CWE range as of v4.18)
        all_cwes = [f"CWE-{i}" for i in range(1, 1426)]

        # Random sample of 20
        sample = random.sample(all_cwes, 20)

        failures = []
        for cwe_id in sample:
            # Get ground truth
            ground_truth = mitre_ground_truth.fetch_cwe_description(cwe_id)
            if "error" in ground_truth:
                continue  # Skip CWEs not in database

            # Query chatbot
            chatbot_response = await self.query_chatbot(cwe_id)

            # Judge response
            verdict = await llm_judge.evaluate(cwe_id, ground_truth, chatbot_response)

            if verdict["verdict"] == "FAIL":
                failures.append((cwe_id, verdict["reasoning"]))

        # Allow up to 10% failure rate (2/20) for edge cases
        assert len(failures) <= 2, f"Too many failures ({len(failures)}/20): {failures}"

    @pytest.mark.asyncio
    async def test_off_topic_query_handling(self):
        """
        Test that off-topic queries (non-security topics) are properly rejected.

        Verifies the query processor correctly identifies and handles queries
        unrelated to CWE/security topics with appropriate guidance.
        """
        # Off-topic query that should be rejected
        query = "tell me about dogs"

        # Query chatbot
        response = await self.query_chatbot(query)

        # Verify response indicates off-topic rejection
        assert (
            "cybersecurity" in response.lower()
        ), f"Expected off-topic rejection mentioning 'cybersecurity', got: {response[:200]}"
        assert (
            "cwe" in response.lower() or "weakness" in response.lower()
        ), f"Expected guidance about CWE topics, got: {response[:200]}"

        # Should NOT attempt to analyze dogs as a security topic
        assert (
            "vulnerability" not in response.lower()
            or "cybersecurity" in response.lower()
        ), "Should not treat 'dogs' as a vulnerability without cybersecurity context"


# Standalone test runner with detailed output
async def run_llm_judge_tests_standalone():
    """
    Run LLM judge tests with detailed output.

    This can be run directly without pytest for debugging.
    """
    print("🔍 CWE Response Accuracy Testing with LLM-as-Judge")
    print("=" * 60)

    mitre = MITREGroundTruth()
    judge = LLMJudge()

    # Test a few high-priority CWEs
    test_cwes = ["CWE-79", "CWE-89", "CWE-82"]

    for cwe_id in test_cwes:
        print(f"\n📋 Testing {cwe_id}...")

        # Get ground truth
        ground_truth = mitre.fetch_cwe_description(cwe_id)
        if "error" in ground_truth:
            print(f"  ⚠️  Skipped: {ground_truth['error']}")
            continue

        print(f"  Name: {ground_truth['name']}")
        print(f"  Description: {ground_truth['description'][:100]}...")

        # Simulate chatbot response (replace with real API call)
        chatbot_response = f"Placeholder response for {cwe_id}"

        # Judge
        verdict = await judge.evaluate(cwe_id, ground_truth, chatbot_response)

        # Print verdict
        emoji = (
            "✅"
            if verdict["verdict"] == "PASS"
            else "⚠️"
            if verdict["verdict"] == "PARTIAL"
            else "❌"
        )
        print(f"  {emoji} Verdict: {verdict['verdict']}")
        print(f"  Reasoning: {verdict['reasoning']}")


if __name__ == "__main__":
    # Run standalone test
    asyncio.run(run_llm_judge_tests_standalone())
