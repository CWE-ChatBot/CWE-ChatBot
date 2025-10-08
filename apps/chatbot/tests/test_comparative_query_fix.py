#!/usr/bin/env python3
"""
Test script to verify the comparative query fix.
Tests that "how does cwe 81 compare to cwe 90" extracts both CWEs.
"""

import os
import sys

# Add current directory to path for local imports
sys.path.insert(0, os.getcwd())

from src.processing.cwe_extractor import CWEExtractor
from src.processing.query_processor import QueryProcessor


def test_cwe_extraction():
    """Test that CWE extraction works for comparative queries."""
    print("🔍 Testing CWE extraction for comparative queries...")

    extractor = CWEExtractor()
    test_queries = [
        "how does cwe 81 compare to cwe 90",
        "what is the difference between CWE-79 and CWE-89?",
        "compare CWE-22 with CWE-23",
        "CWE-787 vs CWE-125",
        "CWE-193 analysis",  # Single CWE for baseline
    ]

    for query in test_queries:
        extracted = extractor.extract_cwe_ids(query)
        print(f"Query: '{query}'")
        print(f"  Extracted CWEs: {extracted}")
        print(f"  Count: {len(extracted)}")
        print()

    return True


def test_query_processor():
    """Test that QueryProcessor properly integrates CWE extraction."""
    print("🔍 Testing QueryProcessor integration...")

    processor = QueryProcessor()
    comparative_query = "how does cwe 81 compare to cwe 90"

    try:
        result = processor.preprocess_query(comparative_query)
        extracted_cwes = result.get("cwe_ids", set())

        print(f"Query: '{comparative_query}'")
        print(f"Extracted CWEs: {extracted_cwes}")
        print(f"Query Type: {result.get('query_type')}")
        print(f"Has Direct CWE: {result.get('has_direct_cwe')}")
        print(f"Enhanced Query: {result.get('enhanced_query')}")

        # Validate that both CWEs are extracted
        expected_cwes = {"CWE-81", "CWE-90"}
        if extracted_cwes == expected_cwes:
            print("✅ SUCCESS: Both CWEs correctly extracted!")
            return True
        else:
            print(f"❌ FAILURE: Expected {expected_cwes}, got {extracted_cwes}")
            return False

    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False


def main():
    """Run all tests."""
    print("🚀 Testing Comparative Query Fix")
    print("=" * 50)

    success = True

    # Test 1: Basic CWE extraction
    success &= test_cwe_extraction()

    # Test 2: QueryProcessor integration
    success &= test_query_processor()

    print("=" * 50)
    if success:
        print("✅ ALL TESTS PASSED! Comparative query fix is working.")
        sys.exit(0)
    else:
        print("❌ SOME TESTS FAILED! Fix needs more work.")
        sys.exit(1)


if __name__ == "__main__":
    main()
