#!/usr/bin/env python3
# apps/cwe_ingestion/cli.py
"""
Command-line interface for CWE data ingestion pipeline.
"""
import logging
import sys

import click

try:
    # Try relative import (when run as part of package)
    from .pipeline import CWEIngestionPipeline
except ImportError:
    # Fall back to absolute import (when run directly or in tests)
    from pipeline import CWEIngestionPipeline

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)


@click.group()
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.pass_context
def cli(ctx, debug):
    """CWE Data Ingestion Pipeline - Download, parse, embed, and store CWE data."""
    ctx.ensure_object(dict)
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('apps.cwe_ingestion').setLevel(logging.DEBUG)

    click.echo("🔧 CWE Data Ingestion Pipeline")


@cli.command()
@click.option('--storage-path', '-s', default='./cwe_vector_db',
              help='Path to vector database storage directory')
@click.option('--target-cwes', '-c', multiple=True,
              help='Specific CWE IDs to ingest (e.g., CWE-79)')
@click.option('--force-download', '-f', is_flag=True,
              help='Force re-download of CWE data')
@click.option('--embedding-model', '-m', default='all-MiniLM-L6-v2',
              help='Sentence transformer model name (used with --embedder-type local)')
@click.option('--embedder-type', '-e', default='local',
              type=click.Choice(['local', 'gemini'], case_sensitive=False),
              help='Embedder type: local (default) or gemini')
def ingest(storage_path: str, target_cwes: tuple, force_download: bool,
           embedding_model: str, embedder_type: str):
    """Run the complete CWE ingestion pipeline."""

    target_cwe_list = list(target_cwes) if target_cwes else None

    pipeline = CWEIngestionPipeline(
        storage_path=storage_path,
        target_cwes=target_cwe_list,
        embedding_model=embedding_model,
        embedder_type=embedder_type
    )

    success = pipeline.run_ingestion(force_download=force_download)

    if success:
        click.echo("✅ CWE ingestion completed successfully!")
        sys.exit(0)
    else:
        click.echo("❌ CWE ingestion failed!")
        sys.exit(1)


@cli.command()
@click.option('--storage-path', '-s', default='./cwe_vector_db',
              help='Path to vector database storage directory')
def status(storage_path: str):
    """Show CWE ingestion pipeline status."""

    pipeline = CWEIngestionPipeline(storage_path=storage_path)

    status_info = pipeline.get_pipeline_status()

    click.echo("📋 CWE Ingestion Pipeline Status")
    click.echo(f"Target CWEs: {len(status_info['target_cwes'])}")
    click.echo(f"Storage Path: {status_info['storage_path']}")
    click.echo(f"Embedding Model: {status_info['embedding_model']}")

    db_stats = status_info['vector_store_stats']
    if 'error' not in db_stats:
        click.echo(f"Vector DB Count: {db_stats['count']} CWEs stored")
    else:
        click.echo(f"Vector DB Error: {db_stats['error']}")


@cli.command()
@click.option('--storage-path', '-s', default='./cwe_vector_db',
              help='Path to vector database storage directory')
@click.option('--query', '-q', required=True,
              help='Text to search for similar CWEs')
@click.option('--n-results', '-n', default=5,
              help='Number of similar CWEs to return')
def query(storage_path: str, query_text: str, n_results: int):
    """Query for similar CWEs based on text similarity."""

    pipeline = CWEIngestionPipeline(storage_path=storage_path)

    # Generate embedding for query
    query_embedding = pipeline.embedder.embed_text(query_text)

    # Search for similar CWEs
    results = pipeline.vector_store.query_similar(query_embedding, n_results)

    click.echo(f"🔍 Similar CWEs for: '{query_text}'")
    click.echo("-" * 50)

    if not results:
        click.echo("No similar CWEs found.")
        return

    for i, result in enumerate(results):
        metadata = result.get('metadata', {})
        distance = result.get('distance', 'N/A')

        click.echo(f"{i+1}. CWE-{metadata.get('cwe_id', 'N/A')}: {metadata.get('name', 'N/A')}")
        click.echo(f"   Distance: {distance}")
        click.echo(f"   Description: {metadata.get('description', 'N/A')[:100]}...")
        click.echo()


@cli.command()
@click.option('--storage-path', '-s', default='./cwe_vector_db',
              help='Path to vector database storage directory')
@click.confirmation_option(prompt='Are you sure you want to reset the vector database?')
def reset(storage_path: str):
    """Reset the vector database (WARNING: This will delete all stored data!)."""

    pipeline = CWEIngestionPipeline(storage_path=storage_path)

    if pipeline.vector_store.reset_collection():
        click.echo("✅ Vector database has been reset.")
    else:
        click.echo("❌ Failed to reset vector database.")


if __name__ == '__main__':
    cli()
