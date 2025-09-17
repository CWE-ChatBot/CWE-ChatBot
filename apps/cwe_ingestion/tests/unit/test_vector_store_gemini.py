# apps/cwe_ingestion/tests/unit/test_vector_store_gemini.py
"""
Tests for vector store with Gemini 3072-dimensional embeddings.
Following TDD Cycle 3.1a from Implementation Plan.
"""
import os
import shutil
import tempfile

import numpy as np


def test_vector_store_supports_3072_dimensions():
    """Test that vector store can handle 3072-dimensional Gemini embeddings."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    from vector_store import CWEVectorStore

    # Create temporary storage
    temp_dir = tempfile.mkdtemp()
    try:
        store = CWEVectorStore(storage_path=temp_dir)

        # Test storing 3072-dimensional embedding
        gemini_embedding = np.random.rand(3072).astype(np.float32)
        cwe_data = {
            'id': 'CWE-79',
            'name': 'Cross-site Scripting',
            'embedding': gemini_embedding,
            'description': 'Test CWE for Gemini embedding',
            'full_text': 'Cross-site scripting (XSS) vulnerability description...'
        }

        result = store.store_cwe(cwe_data)
        assert result is True

        # Verify retrieval works with 3072 dimensions
        retrieved = store.query_similar(gemini_embedding, n_results=1)
        assert len(retrieved) > 0
        assert retrieved[0]['metadata']['cwe_id'] == 'CWE-79'

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_vector_store_cosine_similarity_3072d():
    """Test that cosine similarity works correctly with 3072-dimensional vectors."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    from vector_store import CWEVectorStore

    temp_dir = tempfile.mkdtemp()
    try:
        store = CWEVectorStore(storage_path=temp_dir)

        # Create two similar 3072-dimensional embeddings
        base_embedding = np.random.rand(3072).astype(np.float32)
        similar_embedding = base_embedding + np.random.normal(0, 0.1, 3072).astype(np.float32)

        # Store multiple CWEs
        store.store_cwe({
            'id': 'CWE-79', 'name': 'XSS', 'embedding': base_embedding,
            'description': 'Cross-site scripting', 'full_text': 'XSS vulnerability details...'
        })

        store.store_cwe({
            'id': 'CWE-89', 'name': 'SQL Injection', 'embedding': similar_embedding,
            'description': 'SQL injection vulnerability', 'full_text': 'SQL injection details...'
        })

        # Search should find the more similar one first
        results = store.query_similar(base_embedding, n_results=2)
        assert len(results) == 2
        # First result should be CWE-79 (exact match)
        assert results[0]['metadata']['cwe_id'] == 'CWE-79'

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
