"""
Real integration tests for CWE ChatBot hybrid RAG pipeline.
Tests with actual PostgreSQL + pgvector and OpenAI API when configured.

These tests follow CLAUDE.md principles:
- Test real behavior, not mocked behavior  
- Verify it works with the real system (no mocks!)
- Understand the ACTUAL integration

Environment Variables (can be loaded from ../../env/.env):
- POSTGRES_HOST: PostgreSQL host (default: localhost)
- POSTGRES_PORT: PostgreSQL port (default: 5432) 
- POSTGRES_DATABASE: Database name (default: cwe_chatbot_test)
- POSTGRES_USER: Database user (default: postgres)
- POSTGRES_PASSWORD: Database password (required)
- OPENAI_API_KEY: OpenAI API key (required for embedding tests)

Usage:
  # Skip if no real database configured
  pytest apps/chatbot/tests/test_real_integration.py
  
  # Run with environment file
  cd /path/to/project && pytest apps/chatbot/tests/test_real_integration.py
  
  # Run with explicit environment variables  
  POSTGRES_PASSWORD=test123 OPENAI_API_KEY=sk-... pytest apps/chatbot/tests/test_real_integration.py
"""

import pytest
import os
import sys
import logging
from pathlib import Path
from typing import List, Dict, Any
import asyncio

# Add src to path first
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Import application components
try:
    from config import Config
    from processing.embedding_service import EmbeddingService  
    from security.input_sanitizer import InputSanitizer
    from processing.cwe_extractor import CWEExtractor
except ImportError as e:
    print(f"Warning: Could not import application components: {e}")

# Load environment using configurable loader
def load_environment():
    """Load environment using the configurable environment loader."""
    try:
        # Import environment loader (handle import issues gracefully)
        from config.env_loader import load_env_auto, get_env_info
        
        success = load_env_auto()
        if success:
            env_info = get_env_info()
            logging.info(f"✅ Environment loaded from: {env_info.get('loaded_from')}")
        return success
    except ImportError as e:
        logging.warning(f"Could not import environment loader: {e}")
        # Fallback: check if required vars are already set
        return bool(os.getenv("POSTGRES_PASSWORD") and os.getenv("OPENAI_API_KEY"))

# Load environment on module import
load_environment()

# Add src to path for imports - handle both direct execution and pytest
src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Import basic components (database-dependent components imported in tests)
try:
    from config import Config
    from processing.query_processor import QueryProcessor
    from processing.embedding_service import EmbeddingService
    from formatting.response_formatter import ResponseFormatter
    from retrieval.base_retriever import CWEResult
except ImportError as e:
    print(f"⚠️  Component import error: {e}")
    print("📁 Run from project root with: poetry run python apps/chatbot/tests/test_real_integration.py")
    # Don't exit here - let environment check proceed


# Test configuration
INTEGRATION_REQUIRED_ENVS = [
    "POSTGRES_PASSWORD",
    "OPENAI_API_KEY"
]

def check_integration_env() -> bool:
    """Check if all required environment variables are set for real integration testing."""
    missing = [env for env in INTEGRATION_REQUIRED_ENVS if not os.getenv(env)]
    if missing:
        logging.warning(f"Real integration tests skipped. Missing env vars: {missing}")
        return False
    return True


def requires_real_integration(func):
    """Decorator to skip tests if real integration environment is not configured."""
    return pytest.mark.skipif(
        not check_integration_env(),
        reason="Real integration environment not configured. Set POSTGRES_PASSWORD and OPENAI_API_KEY"
    )(func)


class TestRealDatabaseIntegration:
    """Real integration tests with actual PostgreSQL + pgvector database."""
    
    @pytest.fixture(scope="class")
    def real_config(self):
        """Real database configuration from environment variables."""
        if not check_integration_env():
            pytest.skip("Real database environment not configured")
            
        config = Config()
        # Override with test database settings
        config.pg_database = os.getenv("POSTGRES_DATABASE", "cwe_chatbot_test")
        config.pg_host = os.getenv("POSTGRES_HOST", "localhost") 
        config.pg_port = int(os.getenv("POSTGRES_PORT", "5432"))
        config.pg_user = os.getenv("POSTGRES_USER", "postgres")
        config.pg_password = os.getenv("POSTGRES_PASSWORD")
        config.openai_api_key = os.getenv("OPENAI_API_KEY")
        
        return config
    
    @pytest.fixture(scope="class")
    def real_embedding_service(self, real_config):
        """Real OpenAI embedding service (makes actual API calls)."""
        return EmbeddingService(
            api_key=real_config.openai_api_key,
            model=real_config.embedding_model,
            dimensions=real_config.embedding_dimensions
        )
    
    @requires_real_integration
    def test_database_connection(self, real_config):
        """Test actual database connection and pgvector extension."""
        try:
            import psycopg2
            from pgvector.psycopg2 import register_vector
        except ImportError:
            pytest.skip("psycopg2 and pgvector dependencies not installed")
        
        # Test database connection
        connection = psycopg2.connect(**real_config.get_pg_config())
        register_vector(connection)
        
        with connection.cursor() as cursor:
            # Verify pgvector extension is available
            cursor.execute("SELECT extname FROM pg_extension WHERE extname = 'vector';")
            result = cursor.fetchone()
            assert result is not None, "pgvector extension not installed"
            
            # Verify CWE embeddings table exists
            cursor.execute("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name = 'cwe_embeddings';
            """)
            result = cursor.fetchone()
            assert result is not None, "cwe_embeddings table does not exist"
            
            # Verify test data exists
            cursor.execute("SELECT COUNT(*) FROM cwe_embeddings;")
            count = cursor.fetchone()[0]
            assert count > 0, "No test CWE data found in database"
            
        connection.close()
    
    @requires_real_integration
    def test_dense_retriever_real_database(self, real_config, real_embedding_service):
        """Test dense retriever with real PostgreSQL + pgvector database."""
        try:
            from src.retrieval.dense_retriever import ChatBotDenseRetriever
        except ImportError:
            pytest.skip("Database dependencies not available")
        
        # Initialize dense retriever with real database
        dense_retriever = ChatBotDenseRetriever(
            pg_config=real_config.get_pg_config(),
            embedding_service=real_embedding_service
        )
        
        # Test real database connection
        assert dense_retriever.connection is not None
        
        # Test embedding generation and search  
        test_query = "Cross-site scripting vulnerabilities"
        results = dense_retriever.search(test_query, k=3)
        
        # Verify real results
        assert isinstance(results, list)
        assert len(results) > 0, "No results returned from dense retriever"
        assert len(results) <= 3, "More results returned than requested"
        
        # Verify result structure
        for result in results:
            assert isinstance(result, CWEResult)
            assert result.cwe_id.startswith("CWE-")
            assert len(result.name) > 0
            assert len(result.description) > 0
            assert 0 <= result.confidence_score <= 1
            assert result.source_method == "dense"
        
        # Verify semantic search worked (XSS should match CWE-79)
        cwe_ids = [r.cwe_id for r in results]
        assert "CWE-79" in cwe_ids, "Semantic search should find CWE-79 for XSS query"
        
        dense_retriever.close_connection()
    
    @requires_real_integration  
    def test_sparse_retriever_real_database(self, real_config):
        """Test sparse BM25 retriever with real PostgreSQL database."""
        try:
            from src.retrieval.sparse_retriever import ChatBotSparseRetriever
        except ImportError:
            pytest.skip("Database dependencies not available")
        
        # Initialize sparse retriever with real database
        sparse_retriever = ChatBotSparseRetriever(pg_config=real_config.get_pg_config())
        
        # Test real database connection and BM25 setup
        assert sparse_retriever.connection is not None
        assert sparse_retriever.bm25 is not None
        
        # Test keyword-based search
        test_query = "SQL injection database"
        results = sparse_retriever.search(test_query, k=3)
        
        # Verify real results  
        assert isinstance(results, list)
        assert len(results) > 0, "No results returned from sparse retriever"
        
        # Verify result structure
        for result in results:
            assert isinstance(result, CWEResult)
            assert result.cwe_id.startswith("CWE-")
            assert result.source_method == "sparse"
        
        # Verify keyword matching worked (SQL should match CWE-89)
        cwe_ids = [r.cwe_id for r in results]
        assert "CWE-89" in cwe_ids, "Keyword search should find CWE-89 for SQL injection query"
        
        sparse_retriever.close_connection()
    
    @requires_real_integration
    def test_hybrid_rag_manager_real_system(self, real_config, real_embedding_service):
        """Test complete hybrid RAG manager with real PostgreSQL + OpenAI API."""
        try:
            from retrieval.hybrid_rag_manager import HybridRAGManager
            
            # Initialize hybrid RAG manager with real services
            hybrid_rag = HybridRAGManager(
                pg_config=real_config.get_pg_config(),
                embedding_service=real_embedding_service,
                weights=real_config.get_hybrid_weights()
            )
            
            # Test different search strategies
            test_cases = [
                {
                    "query": "buffer overflow memory corruption",
                    "strategy": "hybrid",
                    "expected_cwe": "CWE-120"
                },
                {
                    "query": "CWE-89",
                    "strategy": "direct", 
                    "expected_cwe": "CWE-89",
                    "cwe_ids": {"CWE-89"}
                },
                {
                    "query": "input validation security",
                    "strategy": "dense",
                    "expected_cwe": "CWE-20"
                }
            ]
            
            for test_case in test_cases:
                query = test_case["query"]
                strategy = test_case["strategy"]
                expected_cwe = test_case["expected_cwe"]
                
                # Perform real search
                if strategy == "direct":
                    results = hybrid_rag.search(
                        query, k=5, strategy=strategy, 
                        cwe_ids=test_case.get("cwe_ids", set())
                    )
                else:
                    results = hybrid_rag.search(query, k=5, strategy=strategy)
                
                # Verify real results
                assert isinstance(results, list), f"Results should be list for {strategy} search"
                assert len(results) > 0, f"No results returned for {strategy} search: {query}"
                
                # Verify expected CWE is found
                found_cwe_ids = [r.cwe_id for r in results]
                assert expected_cwe in found_cwe_ids, f"Expected {expected_cwe} not found in {strategy} search results: {found_cwe_ids}"
                
                # Verify score fusion for hybrid
                if strategy == "hybrid":
                    source_methods = [r.source_method for r in results]
                    # Should have results from multiple sources or hybrid scoring
                    assert any(method in ["dense", "sparse", "hybrid"] for method in source_methods)
            
            hybrid_rag.close_connections()
            
        except ImportError:
            pytest.skip("Database dependencies not available")
    
    @requires_real_integration
    def test_end_to_end_pipeline_real_systems(self, real_config, real_embedding_service):
        """Test complete end-to-end pipeline with real systems (no mocks!)."""
        # Initialize all real components
        query_processor = QueryProcessor(
            max_input_length=real_config.max_input_length,
            strict_mode=real_config.enable_strict_sanitization
        )
        
        try:
            from retrieval.hybrid_rag_manager import HybridRAGManager
            hybrid_rag = HybridRAGManager(
                pg_config=real_config.get_pg_config(),
                embedding_service=real_embedding_service,
                weights=real_config.get_hybrid_weights()
            )
        except ImportError:
            pytest.skip("Database dependencies not available")
        
        response_formatter = ResponseFormatter(
            max_results_display=real_config.max_retrieval_results,
            show_confidence_scores=True,
            show_source_methods=True
        )
        
        # Test complete pipeline with real user queries
        test_queries = [
            "Tell me about CWE-79",  # Direct lookup
            "How to prevent SQL injection attacks?",  # Prevention guidance
            "Buffer overflow vulnerabilities in C programs"  # General security query
        ]
        
        for user_query in test_queries:
            # Step 1: Real query processing with security validation
            processed_query = query_processor.preprocess_query(user_query)
            assert processed_query['sanitized_query'] == user_query  # Should pass security
            
            # Step 2: Real retrieval from PostgreSQL
            if processed_query['search_strategy'] == 'direct_lookup':
                results = hybrid_rag.search(
                    processed_query['sanitized_query'],
                    k=real_config.max_retrieval_results,
                    strategy="direct",
                    cwe_ids=processed_query['cwe_ids']
                )
            else:
                results = hybrid_rag.search(
                    processed_query['sanitized_query'],
                    k=real_config.max_retrieval_results,
                    strategy="hybrid"
                )
            
            # Verify real results
            assert len(results) > 0, f"No real results for query: {user_query}"
            
            # Step 3: Real response formatting
            if processed_query['query_type'] == 'direct_cwe_lookup' and len(results) == 1:
                response = response_formatter.format_direct_cwe_result(results[0])
            else:
                response = response_formatter.format_search_summary(results, processed_query)
            
            # Verify real formatted response
            assert len(response) > 0, "Empty response from formatter"
            assert "CWE-" in response, "Response should contain CWE references"
            
            # Log successful test
            logging.info(f"✅ End-to-end test passed for query: '{user_query}' -> {len(results)} results")
        
        hybrid_rag.close_connections()


class TestRealOpenAIIntegration:
    """Real integration tests with actual OpenAI API."""
    
    @requires_real_integration
    def test_real_embedding_service(self):
        """Test embedding service with real OpenAI API calls."""
        embedding_service = EmbeddingService(
            api_key=os.getenv("OPENAI_API_KEY"),
            model="text-embedding-3-small",
            dimensions=1536
        )
        
        # Test real API call
        test_queries = [
            "Cross-site scripting vulnerability",
            "SQL injection attack prevention", 
            "Buffer overflow in C programming"
        ]
        
        for query in test_queries:
            # Make real API call
            embedding = embedding_service.embed_query(query)
            
            # Verify real response
            assert isinstance(embedding, list), "Embedding should be a list"
            assert len(embedding) == 1536, f"Expected 1536 dimensions, got {len(embedding)}"
            assert all(isinstance(x, float) for x in embedding), "All embedding values should be floats"
            
            # Verify non-zero embedding (real API should return meaningful vectors)
            assert sum(abs(x) for x in embedding) > 0, "Embedding should not be all zeros"
            
            logging.info(f"✅ Real OpenAI embedding test passed for: '{query}'")
    
    @requires_real_integration
    def test_batch_embedding_real_api(self):
        """Test batch embeddings with real OpenAI API."""
        embedding_service = EmbeddingService(
            api_key=os.getenv("OPENAI_API_KEY")
        )
        
        queries = [
            "XSS cross-site scripting",
            "SQL injection database",
            "Buffer overflow memory",
            "Input validation security"
        ]
        
        # Make real batch API call
        embeddings = embedding_service.embed_batch(queries)
        
        # Verify real batch response
        assert len(embeddings) == len(queries), "Should return embedding for each query"
        
        for i, embedding in enumerate(embeddings):
            assert len(embedding) == 1536, f"Query {i}: Expected 1536 dimensions"
            assert sum(abs(x) for x in embedding) > 0, f"Query {i}: Embedding should not be zeros"
        
        # Verify embeddings are different (real API should generate unique vectors)
        assert embeddings[0] != embeddings[1], "Different queries should produce different embeddings"


class TestConfigurationValidation:
    """Test configuration and environment setup for real integration."""
    
    def test_config_validation_with_real_values(self):
        """Test configuration validation with real environment values."""
        if not check_integration_env():
            pytest.skip("Real integration environment not configured")
        
        config = Config()
        config.pg_password = os.getenv("POSTGRES_PASSWORD")
        config.openai_api_key = os.getenv("OPENAI_API_KEY")
        
        # Should not raise ValueError with real values
        config.validate_config()
        
        # Verify configuration is properly set
        assert config.pg_password is not None
        assert config.openai_api_key is not None
        assert config.hybrid_dense_weight + config.hybrid_sparse_weight == 1.0


if __name__ == "__main__":
    # Run tests with real integration if environment is configured
    if check_integration_env():
        print("✅ Real integration environment detected. Running tests with actual PostgreSQL + OpenAI API.")
        print("⚠️  WARNING: These tests make real API calls and may incur costs.")
    else:
        print("⚠️  Real integration environment not configured.")
        print("   Set POSTGRES_PASSWORD and OPENAI_API_KEY to run real integration tests.")
        print("   Tests will be skipped.")
    
    pytest.main([__file__, "-v"])