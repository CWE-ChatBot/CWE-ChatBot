# apps/cwe_ingestion/tests/unit/test_vector_store.py
import os
import pytest
import numpy as np


@pytest.mark.skipif("DATABASE_URL" not in os.environ, reason="PostgreSQL required")
def test_postgres_vector_store_class_exists():
    """Test PostgresVectorStore class can be imported and instantiated."""
    from apps.cwe_ingestion.pg_vector_store import PostgresVectorStore

    store = PostgresVectorStore(dims=384)
    assert store is not None
    assert store.dims == 384


@pytest.mark.skipif("DATABASE_URL" not in os.environ, reason="PostgreSQL required")
def test_postgres_vector_store_configuration():
    """Test PostgresVectorStore initializes with correct configuration."""
    from apps.cwe_ingestion.pg_vector_store import PostgresVectorStore

    store = PostgresVectorStore(table="cwe_embeddings", dims=384)
    assert store.table == "cwe_embeddings"
    assert store.dims == 384


@pytest.mark.skipif("DATABASE_URL" not in os.environ, reason="PostgreSQL required")
def test_store_and_query_cwe_data():
    """Test that PostgresVectorStore can store and query CWE data."""
    from apps.cwe_ingestion.pg_vector_store import PostgresVectorStore

    store = PostgresVectorStore(dims=384)

    # Sample CWE data
    cwe_doc = {
        'id': 'CWE-79',
        'cwe_id': 'CWE-79',
        'name': 'Cross-site Scripting',
        'abstraction': 'Base',
        'status': 'Stable',
        'full_text': 'CWE-79: Cross-site Scripting. XSS vulnerability description...',
        'alternate_terms_text': 'XSS; Cross Site Scripting',
        'embedding': np.random.rand(384).astype(np.float32)
    }

    # Store the document
    result = store.store_batch([cwe_doc])
    assert result == 1

    # Query with similar embedding
    query_embedding = np.random.rand(384).astype(np.float32)
    results = store.query_similar(query_embedding, n_results=5)

    assert isinstance(results, list)
    if len(results) > 0:
        result = results[0]
        assert 'metadata' in result
        assert 'document' in result
        assert 'distance' in result
        # Check metadata structure
        metadata = result['metadata']
        assert 'cwe_id' in metadata
        assert 'name' in metadata


@pytest.mark.skipif("DATABASE_URL" not in os.environ, reason="PostgreSQL required")
def test_store_batch_cwe_data():
    """Test batch storage of multiple CWE entries."""
    from apps.cwe_ingestion.pg_vector_store import PostgresVectorStore

    store = PostgresVectorStore(dims=384)

    # Sample CWE batch data
    cwe_batch = [
        {
            'id': 'CWE-89',
            'cwe_id': 'CWE-89',
            'name': 'SQL Injection',
            'abstraction': 'Base',
            'status': 'Stable',
            'full_text': 'CWE-89: SQL Injection...',
            'alternate_terms_text': 'SQLi; SQL Injection Attack',
            'embedding': np.random.rand(384).astype(np.float32)
        },
        {
            'id': 'CWE-22',
            'cwe_id': 'CWE-22',
            'name': 'Path Traversal',
            'abstraction': 'Base',
            'status': 'Stable',
            'full_text': 'CWE-22: Path Traversal...',
            'alternate_terms_text': 'Directory Traversal; Dot Dot Slash',
            'embedding': np.random.rand(384).astype(np.float32)
        }
    ]

    result = store.store_batch(cwe_batch)
    assert result == 2


@pytest.mark.skipif("DATABASE_URL" not in os.environ, reason="PostgreSQL required")
def test_hybrid_query():
    """Test hybrid querying with vector and FTS."""
    from apps.cwe_ingestion.pg_vector_store import PostgresVectorStore

    store = PostgresVectorStore(dims=384)

    # Store test data
    cwe_doc = {
        'id': 'CWE-78',
        'cwe_id': 'CWE-78',
        'name': 'OS Command Injection',
        'abstraction': 'Base',
        'status': 'Stable',
        'full_text': 'The software constructs system commands using external input',
        'alternate_terms_text': 'Command Injection; Shell Injection',
        'embedding': np.random.rand(384).astype(np.float32)
    }

    store.store_batch([cwe_doc])

    # Test hybrid query
    query_embedding = np.random.rand(384).astype(np.float32)
    results = store.query_hybrid(
        query_text="command injection",
        query_embedding=query_embedding,
        k_vec=10,
        limit=5
    )

    assert isinstance(results, list)
    if len(results) > 0:
        result = results[0]
        assert 'metadata' in result
        assert 'document' in result
        assert 'scores' in result
        # Check scores structure
        scores = result['scores']
        assert 'vec' in scores
        assert 'fts' in scores
        assert 'alias' in scores
        assert 'hybrid' in scores


@pytest.mark.skipif("DATABASE_URL" not in os.environ, reason="PostgreSQL required")
def test_vector_store_collection_stats():
    """Test that PostgresVectorStore can provide collection statistics."""
    from apps.cwe_ingestion.pg_vector_store import PostgresVectorStore

    store = PostgresVectorStore(dims=384)

    # Should be able to get stats
    stats = store.get_collection_stats()
    assert isinstance(stats, dict)
    assert 'collection_name' in stats
    assert 'count' in stats
    assert stats['collection_name'] == 'cwe_embeddings'
    assert isinstance(stats['count'], int)
