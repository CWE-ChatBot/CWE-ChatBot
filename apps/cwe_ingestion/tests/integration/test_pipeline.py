# apps/cwe_ingestion/tests/integration/test_pipeline.py
import tempfile
from pathlib import Path


def test_complete_pipeline_integration():
    """Test the complete CWE ingestion pipeline with sample data."""
    from apps.cwe_ingestion.pipeline import CWEIngestionPipeline

    # Create sample CWE XML data for testing
    sample_xml = '''<?xml version="1.0" encoding="UTF-8"?>
    <Weakness_Catalog>
        <Weaknesses>
            <Weakness ID="79" Name="Cross-site Scripting" Abstraction="Base" Status="Stable">
                <Description>
                    <Description_Summary>The software does not neutralize user input that could lead to XSS</Description_Summary>
                </Description>
                <Extended_Description>
                    Cross-site scripting attacks can lead to session hijacking and data theft.
                </Extended_Description>
                <Alternate_Terms>
                    <Alternate_Term>
                        <Term>XSS</Term>
                        <Description>Common abbreviation</Description>
                    </Alternate_Term>
                </Alternate_Terms>
                <Observed_Examples>
                    <Observed_Example>
                        <Reference>CVE-2002-0738</Reference>
                        <Description>XSS in web application</Description>
                    </Observed_Example>
                </Observed_Examples>
                <Related_Weaknesses>
                    <Related_Weakness Nature="ChildOf" CWE_ID="20" View_ID="1000"/>
                </Related_Weaknesses>
            </Weakness>
            <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Status="Stable">
                <Description>
                    <Description_Summary>The software constructs SQL queries using external input</Description_Summary>
                </Description>
            </Weakness>
        </Weaknesses>
    </Weakness_Catalog>'''

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test XML file
        xml_file = Path(temp_dir) / "test_cwe.xml"
        with open(xml_file, 'w') as f:
            f.write(sample_xml)

        # Initialize pipeline with test data
        storage_path = Path(temp_dir) / "vector_db"
        pipeline = CWEIngestionPipeline(
            storage_path=str(storage_path),
            target_cwes=['CWE-79', 'CWE-89']
        )

        # Test individual components

        # 1. Test parser
        cwe_data = pipeline.parser.parse_file(str(xml_file), ['CWE-79', 'CWE-89'])
        assert len(cwe_data) == 2

        # Verify parsed data structure
        cwe_79 = next((cwe for cwe in cwe_data if cwe['id'] == '79'), None)
        assert cwe_79 is not None
        assert cwe_79['name'] == 'Cross-site Scripting'
        assert 'XSS' in cwe_79['full_text']  # Verify full_text is built

        # 2. Test embedder
        pipeline._generate_embeddings(cwe_data)

        for cwe in cwe_data:
            assert 'embedding' in cwe
            assert len(cwe['embedding']) > 0

        # 3. Test vector store
        stored_count = pipeline._store_embeddings(cwe_data)
        assert stored_count == 2

        # 4. Test querying
        query_embedding = pipeline.embedder.embed_text("cross site scripting vulnerability")
        results = pipeline.vector_store.query_similar(query_embedding, n_results=5)

        # Should find similar CWEs
        assert len(results) >= 1

        # 5. Verify vector store stats
        stats = pipeline.vector_store.get_collection_stats()
        assert stats['count'] >= 2


def test_cli_interface_integration():
    """Test that CLI interface can be imported and has expected commands."""
    import click.testing

    from apps.cwe_ingestion.cli import cli

    runner = click.testing.CliRunner()

    # Test --help command
    result = runner.invoke(cli, ['--help'])
    assert result.exit_code == 0
    assert 'CWE Data Ingestion Pipeline' in result.output

    # Test status command help
    result = runner.invoke(cli, ['status', '--help'])
    assert result.exit_code == 0
    assert 'Show CWE ingestion pipeline status' in result.output

    # Test query command help
    result = runner.invoke(cli, ['query', '--help'])
    assert result.exit_code == 0
    assert 'Query for similar CWEs' in result.output


def test_pipeline_error_handling():
    """Test that pipeline handles errors gracefully."""
    from apps.cwe_ingestion.pipeline import CWEIngestionPipeline

    with tempfile.TemporaryDirectory() as temp_dir:
        pipeline = CWEIngestionPipeline(storage_path=temp_dir)

        # Test with empty target CWEs
        pipeline.target_cwes = []

        # Pipeline should handle gracefully even with empty targets
        assert hasattr(pipeline, 'run_ingestion')

        # Test status retrieval
        status = pipeline.get_pipeline_status()
        assert 'target_cwes' in status
        assert 'storage_path' in status
