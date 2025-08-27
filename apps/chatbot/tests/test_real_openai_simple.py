"""
Simplified real OpenAI API integration test.
Tests the ACTUAL OpenAI API without complex module dependencies.
"""

import pytest
import os
import sys
import logging
from pathlib import Path

# Import environment loader from src (handle path issues gracefully)
try:
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    from config.env_loader import load_env_auto, get_env_info
    ENV_LOADED = load_env_auto()
    if ENV_LOADED:
        env_info = get_env_info()
        logging.info(f"✅ Environment loaded from: {env_info['loaded_from']}")
except ImportError as e:
    logging.warning(f"Could not import environment loader: {e}")
    ENV_LOADED = bool(os.getenv("OPENAI_API_KEY"))


def requires_openai_api():
    """Decorator to skip tests if OpenAI API key is not available."""
    return pytest.mark.skipif(
        not ENV_LOADED or not os.getenv("OPENAI_API_KEY"),
        reason="OpenAI API key not available. Set OPENAI_API_KEY in /home/chris/work/env/.env"
    )


class TestRealOpenAIIntegration:
    """Test real OpenAI API integration following CLAUDE.md principles."""
    
    @requires_openai_api()
    def test_real_openai_embedding_api(self):
        """Test actual OpenAI text-embedding-3-small API calls."""
        try:
            import openai
        except ImportError:
            pytest.skip("openai package not installed")
        
        # Use real API key
        api_key = os.getenv("OPENAI_API_KEY")
        client = openai.Client(api_key=api_key)
        
        # Test real API call
        test_query = "Cross-site scripting vulnerability in web applications"
        
        response = client.embeddings.create(
            input=test_query,
            model="text-embedding-3-small"
        )
        
        embedding = response.data[0].embedding
        
        # Verify real API response
        assert isinstance(embedding, list), "Embedding should be a list"
        assert len(embedding) == 1536, f"Expected 1536 dimensions, got {len(embedding)}"
        assert all(isinstance(x, float) for x in embedding), "All values should be floats"
        assert sum(abs(x) for x in embedding) > 0, "Embedding should not be all zeros"
        
        # Log success
        logging.info(f"✅ Real OpenAI API test passed: {len(embedding)} dimensions, sum={sum(abs(x) for x in embedding):.2f}")
    
    @requires_openai_api()
    def test_real_batch_embeddings(self):
        """Test real batch embedding API calls."""
        try:
            import openai
        except ImportError:
            pytest.skip("openai package not installed")
        
        api_key = os.getenv("OPENAI_API_KEY")
        client = openai.Client(api_key=api_key)
        
        # Test batch queries related to CWE
        queries = [
            "SQL injection database vulnerability",
            "Buffer overflow memory corruption", 
            "Input validation security control",
            "Cross-site scripting XSS attack"
        ]
        
        response = client.embeddings.create(
            input=queries,
            model="text-embedding-3-small"
        )
        
        # Verify batch response
        assert len(response.data) == len(queries), "Should return embedding for each query"
        
        for i, data in enumerate(response.data):
            embedding = data.embedding
            assert len(embedding) == 1536, f"Query {i}: Expected 1536 dimensions"
            assert sum(abs(x) for x in embedding) > 0, f"Query {i}: Should not be zeros"
        
        # Verify embeddings are different for different queries
        embeddings = [data.embedding for data in response.data]
        assert embeddings[0] != embeddings[1], "Different queries should produce different embeddings"
        
        logging.info(f"✅ Real batch API test passed: {len(queries)} queries processed")
    
    @requires_openai_api()
    def test_embedding_consistency(self):
        """Test that the same query produces consistent embeddings."""
        try:
            import openai
        except ImportError:
            pytest.skip("openai package not installed")
        
        api_key = os.getenv("OPENAI_API_KEY")
        client = openai.Client(api_key=api_key)
        
        query = "CWE-79 cross-site scripting vulnerability"
        
        # Get embedding twice
        response1 = client.embeddings.create(input=query, model="text-embedding-3-small")
        response2 = client.embeddings.create(input=query, model="text-embedding-3-small")
        
        embedding1 = response1.data[0].embedding
        embedding2 = response2.data[0].embedding
        
        # Embeddings should be identical for the same query
        assert embedding1 == embedding2, "Same query should produce identical embeddings"
        
        logging.info("✅ Embedding consistency test passed")
    
    @requires_openai_api()
    def test_cwe_related_embeddings(self):
        """Test embeddings for CWE-related security queries."""
        try:
            import openai
        except ImportError:
            pytest.skip("openai package not installed")
        
        api_key = os.getenv("OPENAI_API_KEY")
        client = openai.Client(api_key=api_key)
        
        # CWE-specific test queries
        cwe_queries = [
            "CWE-79 improper neutralization cross-site scripting",
            "CWE-89 SQL injection database vulnerability",
            "CWE-120 buffer overflow memory corruption",
            "CWE-20 improper input validation"
        ]
        
        for query in cwe_queries:
            response = client.embeddings.create(
                input=query, 
                model="text-embedding-3-small"
            )
            
            embedding = response.data[0].embedding
            
            # Verify each CWE query produces valid embeddings
            assert len(embedding) == 1536
            assert sum(abs(x) for x in embedding) > 0
            
            # Log the embedding strength for analysis
            embedding_strength = sum(abs(x) for x in embedding)
            logging.info(f"CWE Query: '{query}' -> Strength: {embedding_strength:.2f}")


if __name__ == "__main__":
    # Run tests directly
    if ENV_LOADED and os.getenv("OPENAI_API_KEY"):
        print("✅ Environment loaded. Running real OpenAI integration tests.")
        print("⚠️  WARNING: These tests make real API calls.")
    else:
        print("⚠️  OpenAI API key not found. Tests will be skipped.")
    
    pytest.main([__file__, "-v"])