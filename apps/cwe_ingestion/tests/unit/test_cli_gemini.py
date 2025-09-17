# apps/cwe_ingestion/tests/unit/test_cli_gemini.py
"""
Tests for CLI interface with Gemini embedder support.
Following TDD Cycle 5.1a from Implementation Plan.
"""
import os
import shutil
import tempfile
from unittest.mock import patch

from click.testing import CliRunner


def test_cli_supports_gemini_embedder_option():
    """Test that CLI supports --embedder-type gemini option."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

    # Import CLI components
    try:
        from cli import cli
    except ImportError:
        # Handle relative import issues
        import cli
        cli = cli.cli

    runner = CliRunner()
    temp_dir = tempfile.mkdtemp()

    try:
        with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
            with patch('pipeline.CWEIngestionPipeline.run_ingestion', return_value=True):
                result = runner.invoke(cli, [
                    'ingest',
                    '--storage-path', temp_dir,
                    '--embedder-type', 'gemini',
                    '--target-cwes', 'CWE-79'
                ])

                # Should succeed (exit code 0)
                assert result.exit_code == 0
                assert 'ingestion completed successfully' in result.output

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_cli_defaults_to_local_embedder():
    """Test that CLI defaults to local embedder when no type specified."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

    try:
        from cli import cli
    except ImportError:
        import cli
        cli = cli.cli

    runner = CliRunner()
    temp_dir = tempfile.mkdtemp()

    try:
        with patch('pipeline.CWEIngestionPipeline.run_ingestion', return_value=True):
            result = runner.invoke(cli, [
                'ingest',
                '--storage-path', temp_dir,
                '--target-cwes', 'CWE-79'
            ])

            # Should succeed with default (local) embedder
            assert result.exit_code == 0

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_cli_validates_embedder_type():
    """Test that CLI validates embedder type parameter."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

    try:
        from cli import cli
    except ImportError:
        import cli
        cli = cli.cli

    runner = CliRunner()
    temp_dir = tempfile.mkdtemp()

    try:
        result = runner.invoke(cli, [
            'ingest',
            '--storage-path', temp_dir,
            '--embedder-type', 'invalid_type',
            '--target-cwes', 'CWE-79'
        ])

        # Should fail with error message
        assert result.exit_code != 0
        # The CLI should show some error about invalid embedder type

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
