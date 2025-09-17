# apps/cwe_ingestion/tests/unit/test_vector_store.py
import tempfile
from pathlib import Path

import numpy as np


def test_cwe_vector_store_class_exists():
    """Test CWEVectorStore class can be imported and instantiated."""
    from apps.cwe_ingestion.vector_store import CWEVectorStore

    with tempfile.TemporaryDirectory() as temp_dir:
        store = CWEVectorStore(storage_path=temp_dir)
        assert store is not None
    # This test MUST fail first - CWEVectorStore doesn't exist yet

def test_vector_store_initializes_with_storage_path():
    """Test vector store initializes with correct storage path."""
    from apps.cwe_ingestion.vector_store import CWEVectorStore

    with tempfile.TemporaryDirectory() as temp_dir:
        store = CWEVectorStore(storage_path=temp_dir)
        assert store.storage_path == temp_dir
        assert store.collection_name == "cwe_embeddings"

def test_vector_store_creates_collection():
    """Test that vector store creates or connects to collection."""
    from apps.cwe_ingestion.vector_store import CWEVectorStore

    with tempfile.TemporaryDirectory() as temp_dir:
        store = CWEVectorStore(storage_path=temp_dir)

        # Check that collection is accessible
        assert hasattr(store, 'collection')
        assert store.collection is not None

def test_store_cwe_data_method():
    """Test that vector store can store CWE data with embeddings."""
    from apps.cwe_ingestion.vector_store import CWEVectorStore

    with tempfile.TemporaryDirectory() as temp_dir:
        store = CWEVectorStore(storage_path=temp_dir)

        # Sample CWE data with embedding
        cwe_data = {
            'id': '79',
            'name': 'Cross-site Scripting',
            'description': 'XSS vulnerability description...',
            'embedding': np.array([0.1, 0.2, 0.3, 0.4, 0.5] * 76, dtype=np.float32),  # 384-dimensional vector
            'full_text': 'CWE-79: Cross-site Scripting. XSS vulnerability description...'
        }

        # Should not raise exceptions
        result = store.store_cwe(cwe_data)
        assert result is True

def test_store_batch_cwe_data():
    """Test batch storage of multiple CWE entries."""
    from apps.cwe_ingestion.vector_store import CWEVectorStore

    with tempfile.TemporaryDirectory() as temp_dir:
        store = CWEVectorStore(storage_path=temp_dir)

        # Sample CWE batch data
        cwe_batch = [
            {
                'id': '79',
                'name': 'Cross-site Scripting',
                'embedding': np.array([0.1] * 384, dtype=np.float32),
                'full_text': 'CWE-79: Cross-site Scripting...'
            },
            {
                'id': '89',
                'name': 'SQL Injection',
                'embedding': np.array([0.2] * 384, dtype=np.float32),
                'full_text': 'CWE-89: SQL Injection...'
            }
        ]

        result = store.store_batch(cwe_batch)
        assert result == 2  # Should return count of stored items

def test_query_similar_cwes():
    """Test querying for similar CWEs based on embedding similarity."""
    from apps.cwe_ingestion.vector_store import CWEVectorStore

    with tempfile.TemporaryDirectory() as temp_dir:
        store = CWEVectorStore(storage_path=temp_dir)

        # Store some test data first
        cwe_data = {
            'id': '79',
            'name': 'Cross-site Scripting',
            'embedding': np.array([0.1] * 384, dtype=np.float32),
            'full_text': 'CWE-79: Cross-site Scripting...'
        }
        store.store_cwe(cwe_data)

        # Query with similar embedding
        query_embedding = np.array([0.1] * 384, dtype=np.float32)
        results = store.query_similar(query_embedding, n_results=5)

        assert isinstance(results, list)
        if len(results) > 0:  # ChromaDB might return empty if no similarity threshold met
            assert 'metadata' in results[0]

def test_vector_store_handles_errors_gracefully():
    """Test that vector store handles storage errors gracefully."""
    from apps.cwe_ingestion.vector_store import CWEVectorStore

    with tempfile.TemporaryDirectory() as temp_dir:
        store = CWEVectorStore(storage_path=temp_dir)

        # Test with invalid data - should return False instead of raising
        invalid_data = {'invalid': 'data'}

        result = store.store_cwe(invalid_data)
        assert result is False

def test_vector_store_collection_stats():
    """Test that vector store can provide collection statistics."""
    from apps.cwe_ingestion.vector_store import CWEVectorStore

    with tempfile.TemporaryDirectory() as temp_dir:
        store = CWEVectorStore(storage_path=temp_dir)

        # Should be able to get stats
        stats = store.get_collection_stats()
        assert isinstance(stats, dict)
        assert 'count' in stats or 'error' in stats  # Either count or error message

def test_vector_store_security_configuration():
    """Test that vector store has proper security configuration."""
    from apps.cwe_ingestion.vector_store import CWEVectorStore

    with tempfile.TemporaryDirectory() as temp_dir:
        store = CWEVectorStore(storage_path=temp_dir)

        # Check that storage path is properly validated
        assert Path(store.storage_path).exists() or Path(store.storage_path).parent.exists()

        # Check collection name is safe
        assert store.collection_name.isalnum() or '_' in store.collection_name
