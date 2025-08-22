# apps/cwe_ingestion/tests/unit/test_embedder.py
import pytest
import numpy as np
from unittest.mock import patch, MagicMock

def test_cwe_embedder_class_exists():
    """Test CWEEmbedder class can be imported and instantiated."""
    from apps.cwe_ingestion.embedder import CWEEmbedder
    
    embedder = CWEEmbedder()
    assert embedder is not None
    # This test MUST fail first - CWEEmbedder doesn't exist yet

def test_embedder_initializes_with_local_model():
    """Test embedder initializes with local sentence transformer."""
    from apps.cwe_ingestion.embedder import CWEEmbedder
    
    embedder = CWEEmbedder()
    
    # Check local model configuration
    assert embedder.model_name == "all-MiniLM-L6-v2"
    assert embedder.is_local_model is True
    assert embedder.api_key is None  # No API key needed for local model

def test_embedder_accepts_custom_model():
    """Test embedder accepts custom model configuration."""
    from apps.cwe_ingestion.embedder import CWEEmbedder
    
    custom_model = "sentence-transformers/all-mpnet-base-v2"
    embedder = CWEEmbedder(model_name=custom_model)
    
    assert embedder.model_name == custom_model
    assert embedder.is_local_model is True

def test_embed_text_returns_vector():
    """Test that embed_text method returns proper vector format."""
    from apps.cwe_ingestion.embedder import CWEEmbedder
    
    # Skip this test if sentence-transformers is not available
    try:
        embedder = CWEEmbedder()
    except ImportError:
        pytest.skip("sentence-transformers not available")
    
    test_text = "Cross-site Scripting vulnerability in web applications"
    embedding = embedder.embed_text(test_text)
    
    # Should return numpy array or list of floats
    assert isinstance(embedding, (np.ndarray, list))
    assert len(embedding) > 0
    
    # Should have consistent dimension (typically 384 for MiniLM)
    if isinstance(embedding, np.ndarray):
        assert embedding.shape[0] > 0
    else:
        assert len(embedding) > 0

def test_embed_batch_processes_multiple_texts():
    """Test that embedder can process multiple CWE descriptions efficiently."""
    from apps.cwe_ingestion.embedder import CWEEmbedder
    
    try:
        embedder = CWEEmbedder()
    except ImportError:
        pytest.skip("sentence-transformers not available")
    
    test_texts = [
        "Cross-site Scripting vulnerability",
        "SQL Injection vulnerability", 
        "Buffer overflow in C applications"
    ]
    
    embeddings = embedder.embed_batch(test_texts)
    
    assert len(embeddings) == 3
    assert all(len(emb) > 0 for emb in embeddings)

def test_no_api_keys_required_for_local_model():
    """Test that local model doesn't require API keys."""
    from apps.cwe_ingestion.embedder import CWEEmbedder
    
    try:
        embedder = CWEEmbedder()
    except ImportError:
        pytest.skip("sentence-transformers not available")
    
    # Local model should not require API keys
    assert embedder.api_key is None
    assert hasattr(embedder, 'is_local_model')
    assert embedder.is_local_model is True

def test_embedder_handles_empty_text():
    """Test that embedder handles empty text gracefully."""
    from apps.cwe_ingestion.embedder import CWEEmbedder
    
    try:
        embedder = CWEEmbedder()
    except ImportError:
        pytest.skip("sentence-transformers not available")
    
    # Test empty string
    result = embedder.embed_text("")
    assert result is not None
    
    # Test None input
    with pytest.raises(Exception):
        embedder.embed_text(None)

def test_embedder_vector_consistency():
    """Test that embedder produces consistent vectors for same input."""
    from apps.cwe_ingestion.embedder import CWEEmbedder
    
    try:
        embedder = CWEEmbedder()
    except ImportError:
        pytest.skip("sentence-transformers not available")
    
    test_text = "SQL Injection vulnerability"
    
    embedding1 = embedder.embed_text(test_text)
    embedding2 = embedder.embed_text(test_text)
    
    # Should produce identical embeddings for same text
    np.testing.assert_array_almost_equal(embedding1, embedding2)