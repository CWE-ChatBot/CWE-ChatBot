"""
Tests for Gemini embedding service wrapper.
"""

import os
import pytest
from unittest.mock import patch
from src.processing.embedding_service import EmbeddingService


class TestEmbeddingService:
    def test_initialization_with_api_key(self):
        service = EmbeddingService(api_key="test-key")
        assert service.model == "models/embedding-001"
        assert service.dimensions == 3072

    def test_initialization_with_env_var(self):
        with patch.dict('os.environ', {'GEMINI_API_KEY': 'env-test-key'}):
            service = EmbeddingService()
            assert service.model == "models/embedding-001"
            assert service.dimensions == 3072

    def test_initialization_without_api_key_raises_error(self):
        with patch.dict('os.environ', {}, clear=True):
            with pytest.raises(ValueError, match="GEMINI_API_KEY"):
                EmbeddingService()

    def test_custom_model_and_dimensions(self):
        service = EmbeddingService(api_key="test-key", model="custom-model", dimensions=1024)
        assert service.model == "custom-model"
        assert service.dimensions == 1024

    @patch('src.processing.embedding_service.GeminiEmbedder')
    def test_embed_query_success(self, mock_embedder_cls):
        mock_embedder = mock_embedder_cls.return_value
        import numpy as np
        mock_embedder.embed_text.return_value = np.ones(3072, dtype=np.float32)

        service = EmbeddingService(api_key="test-key")
        result = service.embed_query(" test query ")
        assert len(result) == 3072
        assert isinstance(result, list)
        assert all(isinstance(x, float) for x in result)
        mock_embedder.embed_text.assert_called_once_with("test query")

    def test_embed_query_invalid_input(self):
        service = EmbeddingService(api_key="test-key")
        with pytest.raises(ValueError):
            service.embed_query("")
        with pytest.raises(ValueError):
            service.embed_query(None)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            service.embed_query(123)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            service.embed_query("   ")

    @patch('src.processing.embedding_service.GeminiEmbedder')
    def test_embed_query_dimension_mismatch(self, mock_embedder_cls):
        mock_embedder = mock_embedder_cls.return_value
        import numpy as np
        mock_embedder.embed_text.return_value = np.ones(10, dtype=np.float32)
        service = EmbeddingService(api_key="test-key")
        with pytest.raises(ValueError, match="Expected 3072D, got 10"):
            service.embed_query("test query")

    @patch('src.processing.embedding_service.GeminiEmbedder')
    def test_embed_batch_success_and_errors(self, mock_embedder_cls):
        mock_embedder = mock_embedder_cls.return_value
        import numpy as np
        # Return a valid vector, then raise, then valid
        side = [np.ones(3072, dtype=np.float32), Exception("API error"), np.ones(3072, dtype=np.float32)]

        def side_effect(arg):
            val = side.pop(0)
            if isinstance(val, Exception):
                raise val
            return val

        mock_embedder.embed_text.side_effect = side_effect
        service = EmbeddingService(api_key="test-key")
        result = service.embed_batch(["q1", "q2", "q3"], batch_size=2)
        assert len(result) == 3
        assert len(result[0]) == 3072
        assert result[1] == [0.0] * 3072  # error path becomes zeros
        assert len(result[2]) == 3072

    def test_get_model_info(self):
        service = EmbeddingService(api_key="test-key")
        info = service.get_model_info()
        assert info == {"model": "models/embedding-001", "dimensions": 3072, "provider": "Gemini"}
