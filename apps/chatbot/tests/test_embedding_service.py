"""
Tests for OpenAI embedding service.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.processing.embedding_service import EmbeddingService
import openai


class TestEmbeddingService:
    """Test embedding service functionality."""
    
    def test_initialization_with_api_key(self):
        """Test service initialization with provided API key."""
        service = EmbeddingService(api_key="test-key")
        assert service.model == "text-embedding-3-small"
        assert service.dimensions == 1536
    
    def test_initialization_with_env_var(self):
        """Test service initialization using environment variable."""
        with patch.dict('os.environ', {'OPENAI_API_KEY': 'env-test-key'}):
            service = EmbeddingService()
            assert service.model == "text-embedding-3-small"
            assert service.dimensions == 1536
    
    def test_initialization_without_api_key_raises_error(self):
        """Test that missing API key raises ValueError."""
        with patch.dict('os.environ', {}, clear=True):
            with pytest.raises(ValueError, match="OpenAI API key must be provided"):
                EmbeddingService()
    
    def test_custom_model_and_dimensions(self):
        """Test initialization with custom model and dimensions."""
        service = EmbeddingService(
            api_key="test-key",
            model="custom-model",
            dimensions=768
        )
        assert service.model == "custom-model"
        assert service.dimensions == 768
    
    @patch('src.processing.embedding_service.OpenAI')
    def test_embed_query_success(self, mock_openai_client):
        """Test successful embedding generation."""
        # Mock the OpenAI response
        mock_response = Mock()
        mock_response.data = [Mock()]
        mock_response.data[0].embedding = [0.1, 0.2, 0.3] * 512  # 1536 dimensions
        
        mock_client_instance = Mock()
        mock_client_instance.embeddings.create.return_value = mock_response
        mock_openai_client.return_value = mock_client_instance
        
        service = EmbeddingService(api_key="test-key")
        result = service.embed_query("test query")
        
        assert len(result) == 1536
        assert isinstance(result, list)
        assert all(isinstance(x, float) for x in result)
        
        # Verify API call
        mock_client_instance.embeddings.create.assert_called_once_with(
            model="text-embedding-3-small",
            input="test query",
            dimensions=1536
        )
    
    @patch('src.processing.embedding_service.OpenAI')
    def test_embed_query_with_openai_api_error(self, mock_openai_client):
        """Test handling of OpenAI API errors."""
        mock_client_instance = Mock()
        mock_client_instance.embeddings.create.side_effect = Exception("API Error")
        mock_openai_client.return_value = mock_client_instance
        
        service = EmbeddingService(api_key="test-key")
        
        with pytest.raises(Exception):
            service.embed_query("test query")
    
    def test_embed_query_invalid_input(self):
        """Test embedding with invalid input."""
        service = EmbeddingService(api_key="test-key")
        
        # Test empty string
        with pytest.raises(ValueError, match="Query must be a non-empty string"):
            service.embed_query("")
        
        # Test None
        with pytest.raises(ValueError, match="Query must be a non-empty string"):
            service.embed_query(None)
        
        # Test non-string
        with pytest.raises(ValueError, match="Query must be a non-empty string"):
            service.embed_query(123)
        
        # Test whitespace only
        with pytest.raises(ValueError, match="Query cannot be empty"):
            service.embed_query("   ")
    
    @patch('src.processing.embedding_service.OpenAI')
    def test_embed_query_dimension_mismatch(self, mock_openai_client):
        """Test handling of dimension mismatch."""
        # Mock response with wrong dimensions
        mock_response = Mock()
        mock_response.data = [Mock()]
        mock_response.data[0].embedding = [0.1, 0.2, 0.3]  # Only 3 dimensions instead of 1536
        
        mock_client_instance = Mock()
        mock_client_instance.embeddings.create.return_value = mock_response
        mock_openai_client.return_value = mock_client_instance
        
        service = EmbeddingService(api_key="test-key")
        
        with pytest.raises(ValueError, match="Expected 1536 dimensions, got 3"):
            service.embed_query("test query")
    
    @patch('src.processing.embedding_service.OpenAI')
    def test_embed_batch_success(self, mock_openai_client):
        """Test successful batch embedding generation."""
        # Mock the OpenAI response for batch
        mock_response = Mock()
        mock_response.data = [Mock(), Mock(), Mock()]
        for i, item in enumerate(mock_response.data):
            item.embedding = [0.1 * (i + 1)] * 1536
        
        mock_client_instance = Mock()
        mock_client_instance.embeddings.create.return_value = mock_response
        mock_openai_client.return_value = mock_client_instance
        
        service = EmbeddingService(api_key="test-key")
        queries = ["query 1", "query 2", "query 3"]
        result = service.embed_batch(queries)
        
        assert len(result) == 3
        assert all(len(embedding) == 1536 for embedding in result)
        
        # Verify API call
        mock_client_instance.embeddings.create.assert_called_once_with(
            model="text-embedding-3-small",
            input=queries,
            dimensions=1536
        )
    
    @patch('src.processing.embedding_service.OpenAI')
    def test_embed_batch_with_empty_queries(self, mock_openai_client):
        """Test batch embedding with empty queries."""
        mock_client_instance = Mock()
        mock_openai_client.return_value = mock_client_instance
        
        service = EmbeddingService(api_key="test-key")
        
        # Test empty list
        result = service.embed_batch([])
        assert result == []
        
        # Test list with empty strings
        result = service.embed_batch(["", "   ", ""])
        assert len(result) == 3
        assert all(embedding == [0.0] * 1536 for embedding in result)
    
    @patch('src.processing.embedding_service.OpenAI')
    def test_embed_batch_with_api_error(self, mock_openai_client):
        """Test batch embedding with API error handling."""
        mock_client_instance = Mock()
        mock_client_instance.embeddings.create.side_effect = Exception("API Error")
        mock_openai_client.return_value = mock_client_instance
        
        service = EmbeddingService(api_key="test-key")
        queries = ["query 1", "query 2"]
        result = service.embed_batch(queries)
        
        # Should return zero embeddings for failed batch
        assert len(result) == 2
        assert all(embedding == [0.0] * 1536 for embedding in result)
    
    @patch('src.processing.embedding_service.OpenAI')
    def test_embed_batch_large_batches(self, mock_openai_client):
        """Test batch embedding with large batches (batching logic)."""
        def create_mock_response(batch_size):
            """Create a mock response for a given batch size."""
            mock_response = Mock()
            mock_response.data = [Mock() for _ in range(batch_size)]
            for item in mock_response.data:
                item.embedding = [0.1] * 1536
            return mock_response
        
        # Set up mock to return appropriate responses for each call
        mock_client_instance = Mock()
        # For 250 queries with batch_size=100: 100, 100, 50
        mock_client_instance.embeddings.create.side_effect = [
            create_mock_response(100),  # First batch
            create_mock_response(100),  # Second batch  
            create_mock_response(50)    # Third batch
        ]
        mock_openai_client.return_value = mock_client_instance
        
        service = EmbeddingService(api_key="test-key")
        
        # Create 250 queries (should require 3 batches of 100, 100, 50)
        queries = [f"query {i}" for i in range(250)]
        result = service.embed_batch(queries, batch_size=100)
        
        assert len(result) == 250
        assert all(len(embedding) == 1536 for embedding in result)
        
        # Should have made 3 API calls
        assert mock_client_instance.embeddings.create.call_count == 3
    
    def test_get_model_info(self):
        """Test model information retrieval."""
        service = EmbeddingService(api_key="test-key")
        info = service.get_model_info()
        
        expected_info = {
            "model": "text-embedding-3-small",
            "dimensions": 1536,
            "provider": "OpenAI"
        }
        
        assert info == expected_info
    
    def test_custom_model_info(self):
        """Test model info with custom configuration."""
        service = EmbeddingService(
            api_key="test-key",
            model="custom-model",
            dimensions=768
        )
        info = service.get_model_info()
        
        expected_info = {
            "model": "custom-model",
            "dimensions": 768,
            "provider": "OpenAI"
        }
        
        assert info == expected_info
    
    @patch('src.processing.embedding_service.OpenAI')
    def test_query_preprocessing(self, mock_openai_client):
        """Test query preprocessing (whitespace handling)."""
        mock_response = Mock()
        mock_response.data = [Mock()]
        mock_response.data[0].embedding = [0.1] * 1536
        
        mock_client_instance = Mock()
        mock_client_instance.embeddings.create.return_value = mock_response
        mock_openai_client.return_value = mock_client_instance
        
        service = EmbeddingService(api_key="test-key")
        
        # Query with leading/trailing whitespace
        result = service.embed_query("  test query  ")
        
        assert len(result) == 1536
        
        # Verify the API was called with stripped query
        mock_client_instance.embeddings.create.assert_called_once_with(
            model="text-embedding-3-small",
            input="test query",  # Should be stripped
            dimensions=1536
        )


if __name__ == "__main__":
    pytest.main([__file__])