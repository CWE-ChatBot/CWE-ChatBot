# apps/cwe_ingestion/tests/unit/test_vector_store_gemini.py
"""
Tests for PostgreSQL vector store with Gemini 3072-dimensional embeddings.
"""
import os

import numpy as np
import pytest


@pytest.mark.skipif("DATABASE_URL" not in os.environ, reason="PostgreSQL required")
def test_postgres_vector_store_3072_dimensions():
    """Test that PostgresVectorStore can handle 3072-dimensional Gemini embeddings."""
    from apps.cwe_ingestion.pg_vector_store import PostgresVectorStore

    store = PostgresVectorStore(dims=3072)
    assert store.dims == 3072

    # Test storing 3072-dimensional embedding
    gemini_embedding = np.random.rand(3072).astype(np.float32)
    cwe_doc = {
        "id": "CWE-79",
        "cwe_id": "CWE-79",
        "name": "Cross-site Scripting",
        "abstraction": "Base",
        "status": "Stable",
        "full_text": "Cross-site scripting (XSS) vulnerability description...",
        "alternate_terms_text": "XSS; Cross Site Scripting",
        "embedding": gemini_embedding,
    }

    result = store.store_batch([cwe_doc])
    assert result == 1

    # Verify retrieval works with 3072 dimensions
    retrieved = store.query_similar(gemini_embedding, n_results=1)
    assert len(retrieved) > 0
    assert retrieved[0]["metadata"]["cwe_id"] == "CWE-79"
    assert retrieved[0]["metadata"]["name"] == "Cross-site Scripting"


@pytest.mark.skipif("DATABASE_URL" not in os.environ, reason="PostgreSQL required")
def test_postgres_vector_store_cosine_similarity_3072d():
    """Test that cosine similarity works correctly with 3072-dimensional vectors."""
    from apps.cwe_ingestion.pg_vector_store import PostgresVectorStore

    store = PostgresVectorStore(dims=3072)

    # Create two different 3072-dimensional embeddings
    base_embedding = np.random.rand(3072).astype(np.float32)
    different_embedding = np.random.rand(3072).astype(np.float32)

    # Store multiple CWEs
    cwe_docs = [
        {
            "id": "CWE-79",
            "cwe_id": "CWE-79",
            "name": "Cross-site Scripting",
            "abstraction": "Base",
            "status": "Stable",
            "full_text": "XSS vulnerability details...",
            "alternate_terms_text": "XSS; Cross Site Scripting",
            "embedding": base_embedding,
        },
        {
            "id": "CWE-89",
            "cwe_id": "CWE-89",
            "name": "SQL Injection",
            "abstraction": "Base",
            "status": "Stable",
            "full_text": "SQL injection vulnerability details...",
            "alternate_terms_text": "SQLi; SQL Injection Attack",
            "embedding": different_embedding,
        },
    ]

    result = store.store_batch(cwe_docs)
    assert result == 2

    # Search should find results in distance order
    results = store.query_similar(base_embedding, n_results=2)
    assert len(results) == 2
    # First result should be CWE-79 (exact match with distance ~0)
    assert results[0]["metadata"]["cwe_id"] == "CWE-79"
    assert results[0]["distance"] < results[1]["distance"]


@pytest.mark.skipif("DATABASE_URL" not in os.environ, reason="PostgreSQL required")
def test_postgres_chunk_store_3072_dimensions():
    """Test that PostgresChunkStore can handle 3072-dimensional Gemini embeddings."""
    from apps.cwe_ingestion.pg_chunk_store import PostgresChunkStore

    store = PostgresChunkStore(dims=3072)
    assert store.dims == 3072

    # Test storing chunked 3072-dimensional embedding
    gemini_embedding = np.random.rand(3072).astype(np.float32)
    chunk_doc = {
        "cwe_id": "CWE-79",
        "section": "Description",
        "section_rank": 1,
        "name": "Cross-site Scripting",
        "full_text": "XSS vulnerability description chunk...",
        "alternate_terms_text": "XSS; Cross Site Scripting",
        "embedding": gemini_embedding,
    }

    result = store.store_batch([chunk_doc])
    assert result == 1

    # Verify retrieval works with 3072 dimensions
    retrieved = store.query_similar(gemini_embedding, n_results=1)
    assert len(retrieved) > 0
    assert retrieved[0]["metadata"]["cwe_id"] == "CWE-79"
    assert retrieved[0]["metadata"]["section"] == "Description"
