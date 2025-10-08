# apps/cwe_ingestion/tests/integration/test_pipeline.py
import os
import tempfile
from pathlib import Path


def test_complete_pipeline_integration():
    """Test the complete CWE ingestion pipeline with PostgreSQL storage."""
    import sys

    # Add the cwe_ingestion directory to the path for imports
    cwe_ingestion_path = Path(__file__).parent.parent.parent
    sys.path.insert(0, str(cwe_ingestion_path))

    from pipeline import CWEIngestionPipeline

    # Set up test database URL
    test_db_url = os.environ.get(
        "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/cwe"
    )
    os.environ["DATABASE_URL"] = test_db_url

    # Create sample CWE XML data for testing
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
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
    </Weakness_Catalog>"""

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test XML file
        xml_file = Path(temp_dir) / "test_cwe.xml"
        with open(xml_file, "w") as f:
            f.write(sample_xml)

        # Initialize pipeline with PostgreSQL (no storage_path needed)
        pipeline = CWEIngestionPipeline(
            target_cwes=["79", "89"],  # Use simple IDs for compatibility
            embedder_type="local",
            use_chunked=True,  # Test chunked PostgreSQL storage
        )

        # Test the complete pipeline with the sample XML file

        # 1. Test parser with file
        cwe_data = pipeline.parser.parse_file(str(xml_file), ["79", "89"])
        assert len(cwe_data) == 2

        # Verify parsed data structure (using Pydantic models)
        cwe_79 = next((cwe for cwe in cwe_data if cwe.ID == "79"), None)
        assert cwe_79 is not None
        assert cwe_79.Name == "Cross-site Scripting"

        # 2. Test embedding generation
        texts_to_embed = [entry.to_searchable_text() for entry in cwe_data]
        embeddings = pipeline.embedder.embed_batch(texts_to_embed)
        assert len(embeddings) == 2
        assert len(embeddings[0]) == pipeline.embedder.get_embedding_dimension()

        # 3. Test chunked storage with real data structures
        from models import entry_to_sections

        chunk_count = 0
        for entry in cwe_data:
            sections = entry_to_sections(entry)
            chunk_count += len(sections)

        # Should have multiple chunks per CWE
        assert chunk_count >= 4  # At least 2 sections per CWE

        # 4. Test vector store storage
        chunk_payloads = []
        for entry in cwe_data:
            sections = entry_to_sections(entry)
            texts = [s["text"] for s in sections]
            embs = pipeline.embedder.embed_batch(texts)

            for s, emb in zip(sections, embs):
                chunk_payloads.append(
                    {
                        "cwe_id": f"CWE-{entry.ID}",
                        "section": s["section"],
                        "section_rank": s["section_rank"],
                        "name": entry.Name,
                        "full_text": s["text"],
                        "alternate_terms_text": "",
                        "embedding": emb,
                    }
                )

        stored_count = pipeline.vector_store.store_batch(chunk_payloads)
        assert stored_count == len(chunk_payloads)

        # 5. Test querying
        query_embedding = pipeline.embedder.embed_text(
            "cross site scripting vulnerability"
        )
        results = pipeline.vector_store.query_similar(query_embedding, n_results=5)

        # Should find similar CWEs
        assert len(results) >= 1

        # Should find CWE-79 as top result
        top_result = results[0]
        assert "79" in top_result["metadata"]["cwe_id"]

        # 6. Test hybrid retrieval
        hybrid_results = pipeline.vector_store.query_hybrid(
            query_text="cross site scripting",
            query_embedding=query_embedding,
            k_vec=10,
            limit_chunks=5,
        )
        assert len(hybrid_results) >= 1

        # 7. Verify vector store stats
        stats = pipeline.vector_store.get_collection_stats()
        assert stats["count"] >= stored_count


def test_cli_interface_integration():
    """Test that CLI interface can be imported and has expected commands."""
    import sys

    import click.testing

    # Add the cwe_ingestion directory to the path for imports
    cwe_ingestion_path = Path(__file__).parent.parent.parent
    sys.path.insert(0, str(cwe_ingestion_path))

    from cli import cli

    runner = click.testing.CliRunner()

    # Test --help command
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "CWE Data Ingestion Pipeline" in result.output

    # Test ingest command help
    result = runner.invoke(cli, ["ingest", "--help"])
    assert result.exit_code == 0
    assert "Run the complete CWE ingestion pipeline" in result.output

    # Test query command help
    result = runner.invoke(cli, ["query", "--help"])
    assert result.exit_code == 0
    assert "Query similar CWEs" in result.output

    # Test multi-database command help
    result = runner.invoke(cli, ["ingest-multi", "--help"])
    assert result.exit_code == 0
    assert "multiple databases" in result.output


def test_multi_database_pipeline_integration():
    """Test the multi-database pipeline functionality."""
    from apps.cwe_ingestion.multi_db_pipeline import (
        DatabaseTarget,
        MultiDatabaseCWEPipeline,
    )

    # Set up test database URL
    test_db_url = os.environ.get(
        "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/cwe"
    )
    os.environ["DATABASE_URL"] = test_db_url

    # Create database targets for testing (both pointing to same DB for testing)
    targets = [
        DatabaseTarget(
            name="test_local",
            database_url=test_db_url,
            use_chunked=True,
            description="Test local database",
        ),
        DatabaseTarget(
            name="test_prod",
            database_url=test_db_url,
            use_chunked=False,  # Test different storage modes
            description="Test production database",
        ),
    ]

    # Initialize multi-database pipeline
    pipeline = MultiDatabaseCWEPipeline(
        database_targets=targets,
        target_cwes=["79"],  # Single CWE for testing
        embedder_type="local",
        embedding_model="all-MiniLM-L6-v2",
    )

    # Verify pipeline configuration
    assert len(pipeline.database_targets) == 2
    assert pipeline.embedding_dim == 3072  # Standardized local embedder dimension
    assert hasattr(pipeline, "embedder")

    # Test that both storage modes are configured correctly
    local_target = next(t for t in targets if t.name == "test_local")
    prod_target = next(t for t in targets if t.name == "test_prod")

    assert local_target.use_chunked is True
    assert prod_target.use_chunked is False


def test_pipeline_error_handling():
    """Test that pipeline handles errors gracefully."""
    from apps.cwe_ingestion.pipeline import CWEIngestionPipeline

    # Set up test database URL
    test_db_url = os.environ.get(
        "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/cwe"
    )
    os.environ["DATABASE_URL"] = test_db_url

    # Test pipeline initialization with different configurations
    pipeline = CWEIngestionPipeline(
        target_cwes=[], embedder_type="local", use_chunked=True  # Empty target CWEs
    )

    # Pipeline should handle gracefully even with empty targets
    assert hasattr(pipeline, "run")
    assert hasattr(pipeline, "embedder")
    assert hasattr(pipeline, "vector_store")

    # Test different storage modes
    chunked_pipeline = CWEIngestionPipeline(use_chunked=True)
    single_pipeline = CWEIngestionPipeline(use_chunked=False)

    assert chunked_pipeline.vector_store.__class__.__name__ == "PostgresChunkStore"
    assert single_pipeline.vector_store.__class__.__name__ == "PostgresVectorStore"


def test_database_environment_configuration():
    """Test that database environment variables are properly handled."""
    from apps.cwe_ingestion.multi_db_pipeline import create_database_targets_from_env

    # Test with no environment variables (should raise error)
    original_local = os.environ.get("LOCAL_DATABASE_URL")
    original_prod = os.environ.get("PROD_DATABASE_URL")
    original_db = os.environ.get("DATABASE_URL")

    # Clear all database URLs
    for key in ["LOCAL_DATABASE_URL", "PROD_DATABASE_URL", "DATABASE_URL"]:
        if key in os.environ:
            del os.environ[key]

    try:
        create_database_targets_from_env()
        assert False, "Should have raised ValueError for missing database URLs"
    except ValueError as e:
        assert "No database targets found" in str(e)

    # Test with local database URL
    test_db_url = "postgresql://postgres:postgres@localhost:5432/cwe"
    os.environ["LOCAL_DATABASE_URL"] = test_db_url

    targets = create_database_targets_from_env()
    assert len(targets) == 1
    assert targets[0].name == "local"
    assert targets[0].database_url == test_db_url

    # Restore original environment
    if original_local:
        os.environ["LOCAL_DATABASE_URL"] = original_local
    if original_prod:
        os.environ["PROD_DATABASE_URL"] = original_prod
    if original_db:
        os.environ["DATABASE_URL"] = original_db
