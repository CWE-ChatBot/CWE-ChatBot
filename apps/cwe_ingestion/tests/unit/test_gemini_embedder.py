# apps/cwe_ingestion/tests/unit/test_gemini_embedder.py
"""
Tests for GeminiEmbedder class implementation.
Following TDD Cycles 2.1a-2.3a from Implementation Plan.
"""
import os
from unittest.mock import patch

import numpy as np
import pytest


def test_gemini_embedder_class_exists():
    """Test GeminiEmbedder class can be imported and instantiated."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    from embedder import GeminiEmbedder

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
        embedder = GeminiEmbedder()
        assert embedder is not None
        # This test MUST fail first - GeminiEmbedder doesn't exist yet


def test_gemini_embedder_requires_api_key():
    """Test that GeminiEmbedder fails gracefully without API key."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    from embedder import GeminiEmbedder

    # Should raise clear error without API key
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError, match="GEMINI_API_KEY"):
            GeminiEmbedder()


def test_gemini_embedder_dimension_configuration():
    """Test that GeminiEmbedder configures 3072 dimensions correctly."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    from embedder import GeminiEmbedder

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
        embedder = GeminiEmbedder()
        assert embedder.get_embedding_dimension() == 3072


def test_gemini_api_request_format():
    """Test that API requests are formatted correctly for gemini-embedding-001."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    from embedder import GeminiEmbedder

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
        embedder = GeminiEmbedder()

        # Mock the API call to inspect request format
        with patch('google.generativeai.embed_content') as mock_embed:
            mock_embed.return_value = {'embedding': [0.1] * 3072}

            embedder.embed_text("Test CWE content")

            # Verify API call format (updated to match current implementation)
            mock_embed.assert_called_once_with(
                model="models/gemini-embedding-001",
                content="Test CWE content"
            )


def test_gemini_response_processing():
    """Test that API responses are processed into proper numpy arrays."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    from embedder import GeminiEmbedder

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
        embedder = GeminiEmbedder()

        mock_response = {'embedding': [0.1] * 3072}
        with patch('google.generativeai.embed_content', return_value=mock_response):
            result = embedder.embed_text("Test content")

            assert isinstance(result, np.ndarray)
            assert result.shape == (3072,)
            assert result.dtype == np.float32


def test_gemini_batch_embedding():
    """Test that GeminiEmbedder can process multiple texts efficiently."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    from embedder import GeminiEmbedder

    test_texts = [
        "Cross-site Scripting vulnerability",
        "SQL Injection vulnerability",
        "Buffer overflow in C applications"
    ]

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
        embedder = GeminiEmbedder()

        # Mock API responses for batch
        mock_responses = [{'embedding': [0.1 + i*0.1] * 3072} for i in range(3)]
        with patch('google.generativeai.embed_content', side_effect=mock_responses):
            embeddings = embedder.embed_batch(test_texts)

            assert len(embeddings) == 3
            assert all(emb.shape == (3072,) for emb in embeddings)
