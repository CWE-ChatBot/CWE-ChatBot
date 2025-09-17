# apps/cwe_ingestion/tests/unit/test_pipeline_gemini.py
"""
Tests for pipeline integration with Gemini embedder.
Following TDD Cycle 4.1a from Implementation Plan.
"""
import os
import shutil
import tempfile
from unittest.mock import patch

import pytest


def test_pipeline_supports_gemini_embedder_selection():
    """Test that pipeline can be configured to use Gemini embedder."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    # Import components individually to avoid relative import issues

    # Import the CWEIngestionPipeline after patching imports
    import pipeline
    from pipeline import CWEIngestionPipeline

    temp_dir = tempfile.mkdtemp()
    try:
        with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
            # Should be able to create pipeline with Gemini embedder
            pipeline = CWEIngestionPipeline(
                storage_path=temp_dir,
                embedder_type="gemini"
            )

            # Verify Gemini embedder is used
            assert hasattr(pipeline.embedder, 'api_key_masked')
            assert pipeline.embedder.get_embedding_dimension() == 3072
            assert not pipeline.embedder.is_local_model

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_pipeline_defaults_to_local_embedder():
    """Test that pipeline defaults to local embedder when no type specified."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    from pipeline import CWEIngestionPipeline

    temp_dir = tempfile.mkdtemp()
    try:
        # Default should use local embedder
        pipeline = CWEIngestionPipeline(storage_path=temp_dir)

        # Verify local embedder is used
        assert pipeline.embedder.is_local_model
        assert pipeline.embedder.get_embedding_dimension() == 384  # MiniLM default

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_pipeline_validates_embedder_type():
    """Test that pipeline validates embedder type parameter."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))
    from pipeline import CWEIngestionPipeline

    temp_dir = tempfile.mkdtemp()
    try:
        # Should raise error for invalid embedder type
        with pytest.raises(ValueError, match="embedder_type"):
            CWEIngestionPipeline(
                storage_path=temp_dir,
                embedder_type="invalid_type"
            )

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
