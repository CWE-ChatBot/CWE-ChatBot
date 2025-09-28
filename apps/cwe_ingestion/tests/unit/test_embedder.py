# apps/cwe_ingestion/tests/unit/test_embedder.py

import numpy as np
import pytest
import os


def test_cwe_embedder_class_exists():
    """Test CWEEmbedder class can be imported and instantiated."""
    from apps.cwe_ingestion.embedder import CWEEmbedder

    embedder = CWEEmbedder()
    assert embedder is not None


def test_cwe_embedder_uses_mock_fallback():
    """Test CWEEmbedder falls back to mock embedder when sentence-transformers unavailable."""
    from apps.cwe_ingestion.embedder import CWEEmbedder

    embedder = CWEEmbedder()

    # Check configuration (works with or without sentence-transformers)
    assert embedder.model_name == "all-MiniLM-L6-v2"
    assert embedder.is_local_model is True
    assert embedder.api_key is None
    assert embedder.embedding_dimension == 3072


def test_cwe_embedder_custom_model():
    """Test CWEEmbedder accepts custom model configuration."""
    from apps.cwe_ingestion.embedder import CWEEmbedder

    custom_model = "all-mpnet-base-v2"
    embedder = CWEEmbedder(model_name=custom_model)

    assert embedder.model_name == custom_model
    assert embedder.is_local_model is True


def test_cwe_embed_text_returns_vector():
    """Test that embed_text method returns proper vector format."""
    from apps.cwe_ingestion.embedder import CWEEmbedder

    embedder = CWEEmbedder()
    test_text = "Cross-site Scripting vulnerability in web applications"
    embedding = embedder.embed_text(test_text)

    # Should return numpy array
    assert isinstance(embedding, np.ndarray)
    assert embedding.shape[0] == 3072  # Standardized mock dimension
    assert len(embedding) > 0


def test_cwe_embed_batch_processes_multiple_texts():
    """Test that embedder can process multiple CWE descriptions efficiently."""
    from apps.cwe_ingestion.embedder import CWEEmbedder

    embedder = CWEEmbedder()
    test_texts = [
        "Cross-site Scripting vulnerability",
        "SQL Injection vulnerability",
        "Buffer overflow in C applications"
    ]

    embeddings = embedder.embed_batch(test_texts)

    assert len(embeddings) == 3
    assert all(isinstance(emb, np.ndarray) for emb in embeddings)
    assert all(len(emb) == 3072 for emb in embeddings)


def test_cwe_embedder_handles_empty_text():
    """Test that embedder handles empty text gracefully."""
    from apps.cwe_ingestion.embedder import CWEEmbedder

    embedder = CWEEmbedder()

    # Test empty string
    result = embedder.embed_text("")
    assert isinstance(result, np.ndarray)
    assert len(result) == 3072

    # Test None input
    with pytest.raises(ValueError):
        embedder.embed_text(None)


def test_cwe_embedder_vector_consistency():
    """Test that embedder produces consistent vectors for same input."""
    from apps.cwe_ingestion.embedder import CWEEmbedder

    embedder = CWEEmbedder()
    test_text = "SQL Injection vulnerability"

    embedding1 = embedder.embed_text(test_text)
    embedding2 = embedder.embed_text(test_text)

    # Should produce identical embeddings for same text (deterministic mock)
    np.testing.assert_array_equal(embedding1, embedding2)


def test_gemini_embedder_requires_api_key():
    """Test that GeminiEmbedder requires API key."""
    from apps.cwe_ingestion.embedder import GeminiEmbedder

    # Clear API key for this test
    original_key = os.environ.get('GEMINI_API_KEY')
    if 'GEMINI_API_KEY' in os.environ:
        del os.environ['GEMINI_API_KEY']

    try:
        with pytest.raises(ValueError, match="GEMINI_API_KEY environment variable is required"):
            GeminiEmbedder()
    finally:
        # Restore original key
        if original_key:
            os.environ['GEMINI_API_KEY'] = original_key


def test_gemini_embedder_configuration():
    """Test GeminiEmbedder configuration with valid API key."""
    from apps.cwe_ingestion.embedder import GeminiEmbedder

    # Mock API key for testing
    test_api_key = "AIzaSyDummyTestKeyFor_Unit_Testing_Only_12345678"

    try:
        embedder = GeminiEmbedder(api_key=test_api_key)

        # Check configuration
        assert embedder.is_local_model is False
        assert embedder.embedding_dimension == 3072
        assert embedder.get_embedding_dimension() == 3072
        assert "AIzaSyDu..." in embedder.api_key_masked  # Masked key

    except ImportError:
        pytest.skip("google-generativeai not available")


def test_gemini_embed_text_validation():
    """Test GeminiEmbedder input validation without API calls."""
    from apps.cwe_ingestion.embedder import GeminiEmbedder

    test_api_key = "AIzaSyDummyTestKeyFor_Unit_Testing_Only_12345678"

    try:
        embedder = GeminiEmbedder(api_key=test_api_key)

        # Test None input validation
        with pytest.raises(ValueError, match="Text cannot be None"):
            embedder.embed_text(None)

    except ImportError:
        pytest.skip("google-generativeai not available")
