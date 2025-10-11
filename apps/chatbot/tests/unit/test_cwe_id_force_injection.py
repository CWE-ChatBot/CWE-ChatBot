#!/usr/bin/env python3
"""
Unit tests for CWE ID force-injection logic.

Tests the fix for ISSUE-CWE-82-NOT-FOUND.md to ensure that when a specific
CWE ID is mentioned in a query, it appears in the results even if hybrid
search doesn't rank it highly.
"""
from unittest.mock import MagicMock, patch

import pytest
from src.processing.pipeline import ProcessingPipeline
from src.processing.query_processor import QueryProcessor


def make_chunk(cwe_id: str, section: str, text: str, hybrid: float = 0.8):
    """Helper to create a mock chunk with proper structure."""
    return {
        "metadata": {
            "cwe_id": cwe_id,
            "section": section,
            "section_rank": 1,
            "name": f"{cwe_id} Name",
        },
        "document": text,
        "scores": {"hybrid": hybrid, "vec": hybrid, "fts": 0.0, "alias": 0.0},
    }


class TestCWEIDForceInjection:
    """Test suite for CWE ID force-injection logic."""

    @pytest.fixture
    def mock_query_handler(self):
        """Mock query handler with fetch_canonical_sections_for_cwes."""
        handler = MagicMock()

        # Mock the fetch method to return CWE-82 sections when requested
        def fetch_canonical_sections(cwe_ids):
            if "CWE-82" in cwe_ids:
                return [
                    make_chunk(
                        "CWE-82",
                        "Description",
                        "Improper Neutralization of Script in Attributes of IMG Tags",
                        hybrid=0.0,
                    ),
                    make_chunk(
                        "CWE-82",
                        "Extended_Description",
                        "Attackers can embed XSS exploits into IMG attributes",
                        hybrid=0.0,
                    ),
                ]
            return []

        handler.fetch_canonical_sections_for_cwes = MagicMock(
            side_effect=fetch_canonical_sections
        )
        return handler

    @pytest.fixture
    def pipeline(self, mock_query_handler):
        """Create pipeline with mocked dependencies."""
        pipeline = ProcessingPipeline()
        pipeline.query_handler = mock_query_handler
        pipeline.query_processor = QueryProcessor()
        return pipeline

    def test_force_injection_when_cwe_id_missing_from_results(self, pipeline):
        """
        Test that CWE-82 is force-injected when mentioned in query but not in results.

        Scenario: User queries "What is CWE-82?" but hybrid search returns
        wrong CWEs (CWE-191, CWE-572, etc.) without CWE-82.

        Expected: CWE-82 should be force-injected into results.
        """
        query = "What is CWE-82?"

        # Simulate hybrid search returning wrong CWEs (the bug scenario)
        raw_chunks = [
            make_chunk("CWE-191", "Description", "Integer Underflow", hybrid=0.24),
            make_chunk("CWE-572", "Description", "Call to Thread run()", hybrid=0.24),
            make_chunk("CWE-1264", "Description", "Hardware Logic Issue", hybrid=0.22),
        ]

        # Apply business logic (should force-inject CWE-82)
        processed_chunks = pipeline._apply_retrieval_business_logic(query, raw_chunks)

        # Verify CWE-82 was force-injected
        cwe_ids = [c["metadata"]["cwe_id"] for c in processed_chunks]
        assert (
            "CWE-82" in cwe_ids
        ), "CWE-82 should be force-injected when missing from results"

        # Verify fetch was called with CWE-82
        pipeline.query_handler.fetch_canonical_sections_for_cwes.assert_called_once_with(
            ["CWE-82"]
        )

    def test_force_injection_applies_high_score_boost(self, pipeline):
        """Test that force-injected CWE IDs get +3.0 score boost."""
        query = "What is CWE-82?"
        raw_chunks = [
            make_chunk("CWE-191", "Description", "Integer Underflow", hybrid=0.24),
        ]

        processed_chunks = pipeline._apply_retrieval_business_logic(query, raw_chunks)

        # Find CWE-82 chunk
        cwe_82_chunks = [
            c for c in processed_chunks if c["metadata"]["cwe_id"] == "CWE-82"
        ]
        assert len(cwe_82_chunks) > 0, "CWE-82 should be in results"

        # Verify boost applied (original 0.0 + 3.0 boost = 3.0)
        for chunk in cwe_82_chunks:
            assert (
                chunk["scores"]["hybrid"] >= 3.0
            ), "Force-injected chunks should have +3.0 boost"

    def test_no_force_injection_when_cwe_id_already_in_results(self, pipeline):
        """Test that force-injection doesn't happen if CWE ID already in results."""
        query = "What is CWE-82?"

        # Simulate CWE-82 already in results (hybrid search worked)
        raw_chunks = [
            make_chunk("CWE-82", "Description", "IMG tag XSS", hybrid=0.85),
            make_chunk("CWE-79", "Description", "XSS", hybrid=0.75),
        ]

        processed_chunks = pipeline._apply_retrieval_business_logic(query, raw_chunks)

        # Verify fetch was NOT called (CWE-82 already present)
        pipeline.query_handler.fetch_canonical_sections_for_cwes.assert_not_called()

        # Verify no duplicates
        cwe_82_count = sum(
            1 for c in processed_chunks if c["metadata"]["cwe_id"] == "CWE-82"
        )
        assert cwe_82_count == 1, "Should not duplicate CWE-82 if already in results"

    def test_force_injection_with_multiple_missing_cwe_ids(self, pipeline):
        """Test force-injection when multiple CWE IDs mentioned but missing."""

        # Mock fetch to return both CWE-82 and CWE-79
        def fetch_multiple(cwe_ids):
            chunks = []
            for cwe_id in cwe_ids:
                chunks.append(
                    make_chunk(
                        cwe_id, "Description", f"{cwe_id} description", hybrid=0.0
                    )
                )
            return chunks

        pipeline.query_handler.fetch_canonical_sections_for_cwes = MagicMock(
            side_effect=fetch_multiple
        )

        query = "Compare CWE-82 and CWE-79"
        raw_chunks = [
            make_chunk("CWE-20", "Description", "Input Validation", hybrid=0.3),
        ]

        processed_chunks = pipeline._apply_retrieval_business_logic(query, raw_chunks)

        # Verify both missing CWE IDs were force-injected
        cwe_ids = set(c["metadata"]["cwe_id"] for c in processed_chunks)
        assert "CWE-82" in cwe_ids, "CWE-82 should be force-injected"
        assert "CWE-79" in cwe_ids, "CWE-79 should be force-injected"
        assert "CWE-20" in cwe_ids, "Original results should be preserved"

    def test_force_injection_with_no_results(self, pipeline):
        """Test force-injection when hybrid search returns zero results."""
        query = "What is CWE-82?"
        raw_chunks = []  # No results

        processed_chunks = pipeline._apply_retrieval_business_logic(query, raw_chunks)

        # Verify CWE-82 was force-injected
        cwe_ids = [c["metadata"]["cwe_id"] for c in processed_chunks]
        assert "CWE-82" in cwe_ids, "Should force-inject even with zero initial results"

    def test_no_force_injection_when_no_cwe_ids_in_query(self, pipeline):
        """Test that force-injection doesn't happen for semantic queries without CWE IDs."""
        query = "How do I prevent SQL injection?"
        raw_chunks = [
            make_chunk("CWE-89", "Description", "SQL Injection", hybrid=0.9),
        ]

        processed_chunks = pipeline._apply_retrieval_business_logic(query, raw_chunks)

        # Verify fetch was NOT called (no CWE IDs to inject)
        pipeline.query_handler.fetch_canonical_sections_for_cwes.assert_not_called()

        # Results should be unchanged
        assert len(processed_chunks) == len(raw_chunks)

    def test_cwe_id_extraction_from_various_formats(self, pipeline):
        """Test that CWE ID extraction works for different query formats."""
        test_cases = [
            ("What is CWE-82?", ["CWE-82"]),
            ("Tell me about cwe-82", ["CWE-82"]),
            ("CWE-82 and CWE-79", ["CWE-82", "CWE-79"]),
            ("Explain CWE 82", ["CWE-82"]),  # Space instead of dash
        ]

        for query, expected_cwe_ids in test_cases:
            result = pipeline.query_processor.preprocess_query(query)
            extracted = result.get("cwe_ids", set())

            for expected_id in expected_cwe_ids:
                assert (
                    expected_id in extracted
                ), f"Failed to extract {expected_id} from '{query}'"

    def test_force_injection_preserves_original_results(self, pipeline):
        """Test that force-injection adds to results without removing existing ones."""
        query = "What is CWE-82?"
        raw_chunks = [
            make_chunk("CWE-191", "Description", "Integer Underflow", hybrid=0.24),
            make_chunk("CWE-572", "Description", "Thread Issue", hybrid=0.24),
        ]

        processed_chunks = pipeline._apply_retrieval_business_logic(query, raw_chunks)

        # Verify original chunks still present
        cwe_ids = set(c["metadata"]["cwe_id"] for c in processed_chunks)
        assert "CWE-191" in cwe_ids, "Original results should be preserved"
        assert "CWE-572" in cwe_ids, "Original results should be preserved"
        assert "CWE-82" in cwe_ids, "Force-injected CWE should be added"

        # Verify total count is original + injected
        assert len(processed_chunks) > len(
            raw_chunks
        ), "Should have more results after injection"

    def test_boost_mentioned_cwe_ids_in_existing_results(self, pipeline):
        """Test that mentioned CWE IDs in results get +2.0 boost even if already present."""
        query = "What is CWE-82?"

        # CWE-82 already in results with low score
        raw_chunks = [
            make_chunk("CWE-82", "Description", "IMG tag XSS", hybrid=0.15),
            make_chunk("CWE-191", "Description", "Integer Underflow", hybrid=0.24),
        ]

        processed_chunks = pipeline._apply_retrieval_business_logic(query, raw_chunks)

        # Find CWE-82 chunk
        cwe_82_chunk = next(
            c for c in processed_chunks if c["metadata"]["cwe_id"] == "CWE-82"
        )

        # Verify boost applied (0.15 + 2.0 boost = 2.15)
        assert (
            cwe_82_chunk["scores"]["hybrid"] >= 2.0
        ), "Mentioned CWE should get +2.0 boost"


class TestCWEIDExtractionEdgeCases:
    """Test edge cases for CWE ID extraction."""

    def test_extract_cwe_with_no_dash(self):
        """Test extraction of CWE ID with space instead of dash."""
        processor = QueryProcessor()
        result = processor.preprocess_query("What is CWE 82?")
        extracted = result.get("cwe_ids", set())
        assert (
            "CWE-82" in extracted
        ), "Should extract 'CWE 82' and normalize to 'CWE-82'"

    def test_extract_multiple_cwe_ids(self):
        """Test extraction of multiple CWE IDs from one query."""
        processor = QueryProcessor()
        result = processor.preprocess_query("Compare CWE-79, CWE-89, and CWE-78")
        extracted = result.get("cwe_ids", set())
        assert "CWE-79" in extracted
        assert "CWE-89" in extracted
        assert "CWE-78" in extracted

    def test_extract_cwe_lowercase(self):
        """Test extraction works with lowercase 'cwe'."""
        processor = QueryProcessor()
        result = processor.preprocess_query("what is cwe-82?")
        extracted = result.get("cwe_ids", set())
        assert "CWE-82" in extracted, "Should normalize lowercase cwe-82 to CWE-82"

    def test_no_extraction_from_semantic_query(self):
        """Test that semantic queries without CWE IDs return empty set."""
        processor = QueryProcessor()
        result = processor.preprocess_query("How do I prevent SQL injection?")
        extracted = result.get("cwe_ids", set())
        assert (
            len(extracted) == 0
        ), "Semantic query without CWE IDs should extract nothing"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
