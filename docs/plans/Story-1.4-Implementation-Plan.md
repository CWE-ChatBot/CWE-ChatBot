# Story 1.4: Gemini-Optimized CWE Data Ingestion Pipeline - Implementation Plan

**Status**: Ready for Implementation
**Story ID**: 1.4
**Date**: September 17, 2025
**Priority**: High

## Overview

This implementation plan details the complete TDD-based approach to integrate Google's gemini-embedding-001 model into the existing CWE data ingestion pipeline. The plan builds upon Story 1.3's solid foundation of 33 passing tests and secure architecture patterns.

## Pre-Implementation Analysis

### Current Foundation (Story 1.3)
- ✅ **Solid Test Foundation**: 33 passing tests provide regression safety
- ✅ **Secure Architecture**: XXE protection, environment variable handling established
- ✅ **Modular Design**: Separate `embedder.py` ready for enhancement
- ✅ **Dependencies**: Poetry-managed with comprehensive test coverage

### Key Implementation Goals
1. Add GeminiEmbedder class alongside existing CWEEmbedder (preserve backward compatibility)
2. Upgrade vector database to handle 3072-dimensional embeddings
3. Integrate Gemini API with robust security controls
4. Maintain existing test coverage while adding Gemini-specific tests
5. Provide measurable quality improvements in semantic similarity

## Phase Breakdown with TDD Cycles

### Phase 1: Environment Setup and Dependencies (Day 1)

#### 1.1 Dependencies and Environment Configuration
**TDD Cycle 1.1a: Google Generative AI Dependency**

**RED**: Write failing test for missing google-generativeai dependency
```bash
# Test file: tests/unit/test_gemini_dependencies.py
poetry run pytest tests/unit/test_gemini_dependencies.py::test_google_generativeai_available -v
# Expected: ImportError for google.generativeai
```

**GREEN**: Add dependency to pyproject.toml
```toml
google-generativeai = "^0.3.0"  # Latest stable version
```

**REFACTOR**: Update poetry.lock and verify clean dependency resolution
```bash
poetry install
poetry run pytest tests/unit/test_gemini_dependencies.py::test_google_generativeai_available -v
# Expected: PASS
```

**TDD Cycle 1.1b: Environment Variable Template**

**RED**: Write failing test for GEMINI_API_KEY environment handling
```bash
poetry run pytest tests/unit/test_gemini_environment.py::test_gemini_api_key_required -v
# Expected: Test fails because environment validation doesn't exist
```

**GREEN**: Create environment validation utility
**REFACTOR**: Add to .env.example template

**Security Validation Checkpoint**:
- [ ] Verify GEMINI_API_KEY is not hardcoded anywhere
- [ ] Confirm graceful failure when API key missing
- [ ] Test environment variable validation

### Phase 2: GeminiEmbedder Implementation (Days 2-3)

#### 2.1 Core GeminiEmbedder Class
**TDD Cycle 2.1a: Basic Class Structure**

**RED**: Write failing test for GeminiEmbedder class existence
```python
# File: tests/unit/test_gemini_embedder.py
def test_gemini_embedder_class_exists():
    """Test GeminiEmbedder class can be imported and instantiated."""
    from apps.cwe_ingestion.embedder import GeminiEmbedder

    embedder = GeminiEmbedder()
    assert embedder is not None
    # This test MUST fail first - GeminiEmbedder doesn't exist yet
```

**Test Command**:
```bash
poetry run pytest tests/unit/test_gemini_embedder.py::test_gemini_embedder_class_exists -v
# Expected: ImportError - GeminiEmbedder not found
```

**GREEN**: Create minimal GeminiEmbedder class
```python
# File: apps/cwe_ingestion/embedder.py (append to existing file)
class GeminiEmbedder:
    """Google Gemini embedding model for high-quality CWE embeddings."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.is_local_model = False
        self.embedding_dimension = 3072  # gemini-embedding-001 default
```

**REFACTOR**: Verify test passes
```bash
poetry run pytest tests/unit/test_gemini_embedder.py::test_gemini_embedder_class_exists -v
# Expected: PASS
```

**TDD Cycle 2.1b: API Key Initialization**

**RED**: Write failing test for API key handling
```python
def test_gemini_embedder_requires_api_key():
    """Test that GeminiEmbedder fails gracefully without API key."""
    from apps.cwe_ingestion.embedder import GeminiEmbedder

    # Should raise clear error without API key
    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        embedder = GeminiEmbedder()
```

**Test Command**:
```bash
poetry run pytest tests/unit/test_gemini_embedder.py::test_gemini_embedder_requires_api_key -v
# Expected: Test fails - no validation exists yet
```

**GREEN**: Implement API key validation
```python
def __init__(self, api_key: Optional[str] = None):
    self.api_key = api_key or os.getenv('GEMINI_API_KEY')
    if not self.api_key:
        raise ValueError(
            "GEMINI_API_KEY environment variable is required for Gemini embeddings. "
            "Please set it with your Google AI API key."
        )
```

**REFACTOR**: Test passes and error message is user-friendly

**TDD Cycle 2.1c: Embedding Dimension Configuration**

**RED**: Write failing test for 3072-dimensional output
```python
def test_gemini_embedder_dimension_configuration():
    """Test that GeminiEmbedder configures 3072 dimensions correctly."""
    from apps.cwe_ingestion.embedder import GeminiEmbedder

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
        embedder = GeminiEmbedder()
        assert embedder.get_embedding_dimension() == 3072
```

**GREEN**: Implement dimension method and configuration
**REFACTOR**: Ensure consistency with base class interface

#### 2.2 API Integration Implementation

**TDD Cycle 2.2a: API Request Formation**

**RED**: Write failing test for API request structure
```python
def test_gemini_api_request_format():
    """Test that API requests are formatted correctly for gemini-embedding-001."""
    from apps.cwe_ingestion.embedder import GeminiEmbedder

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
        embedder = GeminiEmbedder()

        # Mock the API call to inspect request format
        with patch('google.generativeai.embed_content') as mock_embed:
            mock_embed.return_value = {'embedding': [0.1] * 3072}

            embedder.embed_text("Test CWE content")

            # Verify API call format
            mock_embed.assert_called_once_with(
                model="models/embedding-001",
                content="Test CWE content",
                output_dimensionality=3072
            )
```

**GREEN**: Implement API request logic
**REFACTOR**: Add error handling and logging

**TDD Cycle 2.2b: API Response Handling**

**RED**: Write failing test for response processing
```python
def test_gemini_response_processing():
    """Test that API responses are processed into proper numpy arrays."""
    from apps.cwe_ingestion.embedder import GeminiEmbedder

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
        embedder = GeminiEmbedder()

        mock_response = {'embedding': [0.1] * 3072}
        with patch('google.generativeai.embed_content', return_value=mock_response):
            result = embedder.embed_text("Test content")

            assert isinstance(result, np.ndarray)
            assert result.shape == (3072,)
            assert result.dtype == np.float32
```

**GREEN**: Implement response processing
**REFACTOR**: Add input validation and error handling

#### 2.3 Batch Processing Implementation

**TDD Cycle 2.3a: Batch Embedding Method**

**RED**: Write failing test for batch processing
```python
def test_gemini_batch_embedding():
    """Test that GeminiEmbedder can process multiple texts efficiently."""
    from apps.cwe_ingestion.embedder import GeminiEmbedder

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
```

**GREEN**: Implement batch processing with rate limiting
**REFACTOR**: Add progress logging and error handling

**Security Validation Checkpoint**:
- [ ] API key never logged or exposed in error messages
- [ ] Input sanitization prevents injection attacks
- [ ] Rate limiting prevents API abuse
- [ ] Proper error handling for API failures

### Phase 3: Vector Database Schema Updates (Day 4)

#### 3.1 ChromaDB Configuration Update

**TDD Cycle 3.1a: Vector Storage Dimensionality**

**RED**: Write failing test for 3072-dimensional vector storage
```python
def test_vector_store_handles_3072_dimensions():
    """Test that vector store can handle Gemini's 3072-dimensional embeddings."""
    from apps.cwe_ingestion.vector_store import ChromaVectorStore
    import numpy as np

    # Create test vector with 3072 dimensions
    test_vector = np.random.rand(3072).astype(np.float32)
    test_metadata = {"cwe_id": "CWE-79", "name": "Cross-site Scripting"}

    vector_store = ChromaVectorStore()
    vector_store.add_embedding("CWE-79", test_vector, test_metadata)

    # Should store and retrieve without dimension errors
    retrieved = vector_store.query_similar("CWE-79", top_k=1)
    assert len(retrieved) == 1
```

**GREEN**: Update ChromaDB configuration for 3072 dimensions
**REFACTOR**: Ensure backward compatibility with existing vectors

**TDD Cycle 3.1b: Cosine Similarity Metric Verification**

**RED**: Write failing test for similarity metric configuration
```python
def test_cosine_similarity_metric_configured():
    """Test that ChromaDB uses cosine similarity for text embeddings."""
    from apps.cwe_ingestion.vector_store import ChromaVectorStore

    vector_store = ChromaVectorStore()

    # Verify distance metric configuration
    collection_metadata = vector_store.get_collection_metadata()
    assert collection_metadata.get('hnsw:space') == 'cosine'
```

**GREEN**: Configure cosine similarity metric
**REFACTOR**: Add configuration validation

#### 3.2 Migration Strategy for Existing Data

**TDD Cycle 3.2a: Dimension Compatibility Check**

**RED**: Write test for handling mixed-dimension vectors
```python
def test_handles_mixed_dimension_vectors():
    """Test system handles both 384 and 3072 dimensional vectors gracefully."""
    from apps.cwe_ingestion.vector_store import ChromaVectorStore

    vector_store = ChromaVectorStore()

    # Test with both dimension types
    old_vector = np.random.rand(384).astype(np.float32)  # Story 1.3 format
    new_vector = np.random.rand(3072).astype(np.float32)  # Gemini format

    # Should handle both without errors
    vector_store.add_embedding("CWE-78", old_vector, {"source": "story_1_3"})
    vector_store.add_embedding("CWE-79", new_vector, {"source": "gemini"})

    # Queries should work for both
    results_old = vector_store.query_similar_by_vector(old_vector, top_k=1)
    results_new = vector_store.query_similar_by_vector(new_vector, top_k=1)

    assert len(results_old) == 1
    assert len(results_new) == 1
```

**GREEN**: Implement dimension detection and handling
**REFACTOR**: Add migration utilities for existing data

**Security Validation Checkpoint**:
- [ ] Vector database access controls properly configured
- [ ] No sensitive data exposure in vector metadata
- [ ] Proper validation of vector dimensions

### Phase 4: Pipeline Integration (Day 5)

#### 4.1 Pipeline Configuration Updates

**TDD Cycle 4.1a: Embedder Selection Logic**

**RED**: Write failing test for embedder selection
```python
def test_pipeline_selects_gemini_embedder():
    """Test that pipeline uses GeminiEmbedder when configured."""
    from apps.cwe_ingestion.pipeline import CWEPipeline

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key', 'EMBEDDER_TYPE': 'gemini'}):
        pipeline = CWEPipeline()

        # Should initialize with GeminiEmbedder
        assert pipeline.embedder.__class__.__name__ == 'GeminiEmbedder'
        assert pipeline.embedder.embedding_dimension == 3072
```

**GREEN**: Update pipeline to support embedder selection
**REFACTOR**: Maintain backward compatibility with CWEEmbedder

**TDD Cycle 4.1b: Configuration Validation**

**RED**: Write failing test for configuration validation
```python
def test_pipeline_validates_gemini_configuration():
    """Test that pipeline validates Gemini configuration before processing."""
    from apps.cwe_ingestion.pipeline import CWEPipeline

    # Missing API key should raise clear error
    with patch.dict(os.environ, {'EMBEDDER_TYPE': 'gemini'}, clear=True):
        with pytest.raises(ValueError, match="GEMINI_API_KEY"):
            CWEPipeline()
```

**GREEN**: Add configuration validation logic
**REFACTOR**: Provide helpful error messages for misconfiguration

#### 4.2 End-to-End Pipeline Testing

**TDD Cycle 4.2a: Complete Pipeline Integration**

**RED**: Write failing integration test for full pipeline
```python
def test_complete_gemini_pipeline_integration():
    """Test complete pipeline from CWE parsing to Gemini embedding storage."""
    from apps.cwe_ingestion.pipeline import CWEPipeline

    # Mock CWE data
    test_cwe_data = [
        {"id": "CWE-79", "name": "Cross-site Scripting", "description": "XSS vulnerability"}
    ]

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key', 'EMBEDDER_TYPE': 'gemini'}):
        pipeline = CWEPipeline()

        # Mock Gemini API response
        mock_embedding = [0.1] * 3072
        with patch('google.generativeai.embed_content', return_value={'embedding': mock_embedding}):
            pipeline.process_cwe_data(test_cwe_data)

            # Verify vector was stored with correct dimensions
            stored_vectors = pipeline.vector_store.get_all_vectors()
            assert len(stored_vectors) == 1
            assert stored_vectors[0]['vector'].shape == (3072,)
```

**GREEN**: Implement complete pipeline integration
**REFACTOR**: Add comprehensive error handling and logging

**TDD Cycle 4.2b: Quality Metrics Collection**

**RED**: Write failing test for embedding quality metrics
```python
def test_gemini_embedding_quality_metrics():
    """Test that pipeline collects quality metrics for Gemini embeddings."""
    from apps.cwe_ingestion.pipeline import CWEPipeline

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key', 'EMBEDDER_TYPE': 'gemini'}):
        pipeline = CWEPipeline()

        # Should track embedding quality metrics
        assert hasattr(pipeline, 'quality_metrics')

        # Process test data and verify metrics collection
        test_data = [{"id": "CWE-79", "description": "XSS test"}]
        pipeline.process_cwe_data(test_data)

        metrics = pipeline.get_quality_metrics()
        assert 'embedding_dimension' in metrics
        assert 'total_processed' in metrics
        assert metrics['embedding_dimension'] == 3072
```

**GREEN**: Implement quality metrics collection
**REFACTOR**: Add comprehensive metric reporting

**Security Validation Checkpoint**:
- [ ] No API keys logged during pipeline execution
- [ ] Input validation applied before all external API calls
- [ ] Error handling prevents information leakage

### Phase 5: CLI Interface Updates (Day 6)

#### 5.1 CLI Command Enhancement

**TDD Cycle 5.1a: Embedder Type Configuration**

**RED**: Write failing test for CLI embedder selection
```python
def test_cli_supports_gemini_embedder_selection():
    """Test that CLI supports selecting Gemini embedder."""
    from apps.cwe_ingestion.cli import main
    from click.testing import CliRunner

    runner = CliRunner()

    # Test CLI with gemini embedder option
    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
        result = runner.invoke(main, ['--embedder', 'gemini', '--dry-run'])

        assert result.exit_code == 0
        assert 'Using GeminiEmbedder' in result.output
        assert '3072 dimensions' in result.output
```

**GREEN**: Add CLI options for embedder selection
**REFACTOR**: Update help text and validation

**TDD Cycle 5.1b: Configuration Validation in CLI**

**RED**: Write failing test for CLI configuration validation
```python
def test_cli_validates_gemini_configuration():
    """Test that CLI validates Gemini configuration before execution."""
    from apps.cwe_ingestion.cli import main
    from click.testing import CliRunner

    runner = CliRunner()

    # Missing API key should produce helpful error
    result = runner.invoke(main, ['--embedder', 'gemini'])

    assert result.exit_code != 0
    assert 'GEMINI_API_KEY' in result.output
    assert 'environment variable' in result.output
```

**GREEN**: Add configuration validation to CLI
**REFACTOR**: Provide clear error messages and help

### Phase 6: Quality Validation and Testing (Day 7)

#### 6.1 Semantic Similarity Validation

**TDD Cycle 6.1a: Baseline Comparison Tests**

**RED**: Write failing test for quality improvement measurement
```python
def test_gemini_improves_semantic_similarity():
    """Test that Gemini embeddings provide better semantic similarity than Story 1.3 baseline."""
    from apps.cwe_ingestion.embedder import CWEEmbedder, GeminiEmbedder
    import numpy as np

    # Test queries and expected similar CWEs
    test_cases = [
        {
            "query": "Cross-site scripting attack in web application",
            "expected_similar": "CWE-79: Cross-site Scripting"
        },
        {
            "query": "SQL injection vulnerability in database query",
            "expected_similar": "CWE-89: SQL Injection"
        }
    ]

    # Compare embeddings
    local_embedder = CWEEmbedder()
    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
        gemini_embedder = GeminiEmbedder()

        for case in test_cases:
            # Generate embeddings with both models
            local_emb = local_embedder.embed_text(case["query"])
            gemini_emb = gemini_embedder.embed_text(case["query"])

            # Test that embeddings are different (not just dimension)
            assert local_emb.shape != gemini_emb.shape

            # Quality metrics should be available
            assert hasattr(gemini_embedder, 'get_quality_score')
```

**GREEN**: Implement quality comparison utilities
**REFACTOR**: Add comprehensive quality metrics

**TDD Cycle 6.1b: Retrieval Accuracy Testing**

**RED**: Write failing test for retrieval accuracy
```python
def test_gemini_retrieval_accuracy():
    """Test that Gemini embeddings improve retrieval accuracy for CWE queries."""
    from apps.cwe_ingestion.vector_store import ChromaVectorStore
    from apps.cwe_ingestion.embedder import GeminiEmbedder

    # Create test dataset with known relationships
    test_cwes = [
        {"id": "CWE-79", "description": "Cross-site Scripting (XSS) vulnerability"},
        {"id": "CWE-89", "description": "SQL Injection vulnerability"},
        {"id": "CWE-120", "description": "Buffer Copy without Checking Size"}
    ]

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
        embedder = GeminiEmbedder()
        vector_store = ChromaVectorStore()

        # Add embeddings to vector store
        for cwe in test_cwes:
            embedding = embedder.embed_text(cwe["description"])
            vector_store.add_embedding(cwe["id"], embedding, cwe)

        # Test retrieval accuracy
        query = "JavaScript injection attack in web form"
        results = vector_store.query_similar_text(query, embedder, top_k=1)

        # Should retrieve CWE-79 (XSS) as most similar
        assert results[0]['metadata']['id'] == 'CWE-79'
        assert results[0]['similarity_score'] > 0.7  # High similarity threshold
```

**GREEN**: Implement retrieval accuracy testing
**REFACTOR**: Add comprehensive test cases and benchmarks

#### 6.2 Performance and Security Validation

**TDD Cycle 6.2a: Performance Benchmarking**

**RED**: Write failing test for performance metrics
```python
def test_gemini_performance_metrics():
    """Test that Gemini embedder tracks performance metrics."""
    from apps.cwe_ingestion.embedder import GeminiEmbedder
    import time

    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
        embedder = GeminiEmbedder()

        # Should track timing and API usage
        start_time = time.time()
        embedding = embedder.embed_text("Test CWE description")
        end_time = time.time()

        # Performance metrics should be available
        metrics = embedder.get_performance_metrics()
        assert 'api_calls_made' in metrics
        assert 'total_processing_time' in metrics
        assert 'average_response_time' in metrics
```

**GREEN**: Implement performance tracking
**REFACTOR**: Add comprehensive monitoring and logging

**Security Validation Final Checkpoint**:
- [ ] **API Key Security**: No hardcoded keys, secure environment handling
- [ ] **Input Validation**: All CWE content sanitized before API calls
- [ ] **Error Handling**: No sensitive information in error messages or logs
- [ ] **Rate Limiting**: API quota protection and cost monitoring
- [ ] **Data Protection**: Only intended CWE content sent to external API

## Implementation Files and Structure

### Files to Create/Modify

#### New Test Files
```
tests/unit/test_gemini_dependencies.py       # Dependency validation tests
tests/unit/test_gemini_environment.py        # Environment configuration tests
tests/unit/test_gemini_embedder.py          # Core GeminiEmbedder tests
tests/integration/test_gemini_pipeline.py   # End-to-end integration tests
tests/integration/test_gemini_quality.py    # Quality and performance tests
```

#### Modified Files
```
apps/cwe_ingestion/embedder.py             # Add GeminiEmbedder class
apps/cwe_ingestion/pipeline.py             # Integrate embedder selection
apps/cwe_ingestion/vector_store.py         # Update for 3072 dimensions
apps/cwe_ingestion/cli.py                  # Add CLI options
pyproject.toml                             # Add google-generativeai dependency
.env.example                               # Add GEMINI_API_KEY template
```

### Environment Configuration

#### Required Environment Variables
```bash
# .env file template
GEMINI_API_KEY=your_google_ai_api_key_here
EMBEDDER_TYPE=gemini  # Options: local, gemini
VECTOR_STORE_TYPE=chromadb  # For local development
```

#### Development Commands
```bash
# Install dependencies
poetry install

# Run all tests
poetry run pytest apps/cwe_ingestion/tests/ -v

# Run specific test phase
poetry run pytest tests/unit/test_gemini_embedder.py -v

# Run integration tests
poetry run pytest tests/integration/test_gemini_pipeline.py -v

# Run CLI with Gemini embedder
poetry run python -m apps.cwe_ingestion --embedder gemini --subset 10

# Generate quality comparison report
poetry run python -m apps.cwe_ingestion --compare-embedders
```

## Test-First Implementation Order

### Day 1: Foundation Setup
1. **Morning**: Dependencies and environment setup (TDD Cycles 1.1a-1.1b)
2. **Afternoon**: Security validation for environment handling

### Day 2: Core Implementation
1. **Morning**: GeminiEmbedder class structure (TDD Cycles 2.1a-2.1c)
2. **Afternoon**: API integration basics (TDD Cycle 2.2a)

### Day 3: API Integration
1. **Morning**: Response handling and validation (TDD Cycle 2.2b)
2. **Afternoon**: Batch processing implementation (TDD Cycle 2.3a)

### Day 4: Vector Database Updates
1. **Morning**: ChromaDB configuration updates (TDD Cycles 3.1a-3.1b)
2. **Afternoon**: Migration strategy and mixed-dimension handling (TDD Cycle 3.2a)

### Day 5: Pipeline Integration
1. **Morning**: Pipeline configuration updates (TDD Cycles 4.1a-4.1b)
2. **Afternoon**: End-to-end integration testing (TDD Cycles 4.2a-4.2b)

### Day 6: CLI Interface
1. **Morning**: CLI enhancements (TDD Cycles 5.1a-5.1b)
2. **Afternoon**: User experience and error handling

### Day 7: Quality Validation
1. **Morning**: Quality comparison testing (TDD Cycles 6.1a-6.1b)
2. **Afternoon**: Performance and final security validation (TDD Cycle 6.2a)

## Success Criteria and Validation

### Acceptance Criteria Validation

#### AC1: Gemini API Integration (3072 dimensions)
**Validation Tests**:
```bash
poetry run pytest tests/unit/test_gemini_embedder.py::test_gemini_api_request_format -v
poetry run pytest tests/unit/test_gemini_embedder.py::test_gemini_response_processing -v
```

**Success Criteria**:
- [ ] GeminiEmbedder class integrates with Google's Gemini API
- [ ] Embeddings generated at 3072 dimensions
- [ ] API authentication working with GEMINI_API_KEY

#### AC2: Secure API Key Management
**Validation Tests**:
```bash
poetry run pytest tests/unit/test_gemini_environment.py -v
python3 tests/scripts/test_gemini_security.py  # Security validation script
```

**Success Criteria**:
- [ ] GEMINI_API_KEY securely handled via environment variables
- [ ] Graceful failure when API key missing
- [ ] No API keys exposed in logs or error messages

#### AC3: Quality Improvement over Story 1.3
**Validation Tests**:
```bash
poetry run pytest tests/integration/test_gemini_quality.py::test_gemini_improves_semantic_similarity -v
poetry run python -m apps.cwe_ingestion --compare-embedders --output-report
```

**Success Criteria**:
- [ ] Gemini embeddings process same CWE subset from Story 1.3
- [ ] Measurable improvement in semantic similarity scoring
- [ ] Quality metrics demonstrate enhancement over baseline

#### AC4: Vector Database Efficiency (3072 dimensions)
**Validation Tests**:
```bash
poetry run pytest tests/unit/test_vector_store.py::test_vector_store_handles_3072_dimensions -v
poetry run pytest tests/integration/test_gemini_pipeline.py::test_complete_gemini_pipeline_integration -v
```

**Success Criteria**:
- [ ] ChromaDB handles 3072-dimensional vectors efficiently
- [ ] Cosine similarity indexing configured properly
- [ ] Storage and retrieval performance acceptable

#### AC5: Local Testing and Logging Validation
**Validation Tests**:
```bash
poetry run python -m apps.cwe_ingestion --embedder gemini --subset 5 --verbose
poetry run pytest tests/integration/test_gemini_pipeline.py::test_gemini_logging_integration -v
```

**Success Criteria**:
- [ ] Local testing validates accurate retrieval for sample queries
- [ ] Logging confirms successful Gemini API integration
- [ ] No sensitive information exposed in logs

### Security Requirements Validation

#### Authentication Security
```bash
python3 tests/scripts/test_gemini_api_security.py
```
- [ ] GEMINI_API_KEY format validation
- [ ] API key expiration detection
- [ ] Secure credential handling

#### Input Validation Security
```bash
python3 tests/scripts/test_gemini_input_validation.py
```
- [ ] CWE data sanitization before API calls
- [ ] Injection attack prevention
- [ ] Malformed request handling

#### Data Protection Security
```bash
python3 tests/scripts/test_gemini_data_protection.py
```
- [ ] Only intended CWE data sent to API
- [ ] No local sensitive data included
- [ ] Google AI API usage policy compliance

## Risk Mitigation Strategies

### Technical Risks

**Risk**: Gemini API quotas/rate limiting
**Mitigation**: Implement retry logic with exponential backoff, monitor usage

**Risk**: API key exposure
**Mitigation**: Environment variable validation, no logging of keys, secure error handling

**Risk**: Embedding quality regression
**Mitigation**: Comprehensive quality comparison tests, baseline preservation

**Risk**: Vector database performance
**Mitigation**: Dimension compatibility testing, migration strategy, performance benchmarks

### Dependencies and Integration Risks

**Risk**: google-generativeai library compatibility
**Mitigation**: Pin specific version, comprehensive dependency testing

**Risk**: ChromaDB configuration conflicts
**Mitigation**: Backward compatibility tests, graceful fallback mechanisms

**Risk**: Pipeline integration failures
**Mitigation**: Incremental integration testing, rollback capabilities

## Completion and Handoff

### Final Validation Checklist

#### Functional Validation
- [ ] All 5 Acceptance Criteria tests passing
- [ ] TDD test suite expanded to 50+ tests (from 33 baseline)
- [ ] CLI supports both local and Gemini embedders
- [ ] Quality metrics demonstrate improvement
- [ ] Performance meets expectations

#### Security Validation
- [ ] All security test scripts passing
- [ ] No hardcoded credentials detected
- [ ] Input validation comprehensive
- [ ] Error handling secure
- [ ] API usage compliant

#### Documentation and Handoff
- [ ] Implementation notes documented in CURATION_NOTES.md
- [ ] Quality comparison report generated
- [ ] Performance benchmarks recorded
- [ ] Known limitations documented
- [ ] Next steps for production deployment outlined

### Success Metrics

**Quantitative Measures**:
- Test coverage maintains ≥90% for new code
- Semantic similarity improvement ≥15% over Story 1.3 baseline
- API response time ≤2 seconds per embedding
- Zero security vulnerabilities in final scan

**Qualitative Measures**:
- Clean integration with existing codebase
- Maintainable code following project standards
- Clear error messages and user experience
- Comprehensive documentation for future developers

## Next Steps Post-Implementation

1. **Production Deployment Preparation**: Cloud environment configuration
2. **Monitoring and Alerting**: API usage tracking, cost monitoring
3. **Performance Optimization**: Batch processing improvements, caching strategies
4. **Integration with Story 2.1**: NLU and query matching pipeline connection

This implementation plan provides a complete, test-driven approach to successfully integrating Google's Gemini embedding model while maintaining the security and quality standards established in Story 1.3.