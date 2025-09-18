# apps/cwe_ingestion/cli.py (only changed/new parts)
import os
...
@click.command()
@click.option('--storage-path', '-s', default='./cwe_vector_db',
              help='Path to vector database storage directory (for Chroma)')
@click.option('--query', '-q', 'query_text', required=True,
              help='Text to search for similar CWEs')
@click.option('--n-results', '-n', default=5, help='Number of results to return')
@click.option('--hybrid', is_flag=True, help='Use hybrid retrieval (Postgres only)')
@click.option('--w-vec', default=0.65, type=float, show_default=True, help='Weight for vector score')
@click.option('--w-fts', default=0.25, type=float, show_default=True, help='Weight for full-text score')
@click.option('--w-alias', default=0.10, type=float, show_default=True, help='Weight for alias similarity')
def query(storage_path: str, query_text: str, n_results: int, hybrid: bool, w_vec: float, w_fts: float, w_alias: float):
    """Query for similar CWEs (vector or hybrid)."""

    # DB choice via env (simple)
    vector_db_type = os.getenv("VECTOR_DB_TYPE", "chromadb").lower()
    pipeline = CWEIngestionPipeline(storage_path=storage_path)

    # Generate embedding for query (works for both local & gemini)
    query_embedding = pipeline.embedder.embed_text(query_text)

    click.echo(f"🔍 Query: '{query_text}'")
    click.echo("-" * 50)

    if vector_db_type == "postgresql" and hybrid:
        # Use hybrid retrieval
        if not hasattr(pipeline.vector_store, "query_hybrid"):
            click.echo("Hybrid retrieval not available (vector store missing query_hybrid).")
            ctx = click.get_current_context()
            ctx.exit(2)
        results = pipeline.vector_store.query_hybrid(
            query_text=query_text,
            query_embedding=query_embedding,
            k_vec=max(n_results * 5, 25),
            limit=n_results,
            w_vec=w_vec, w_fts=w_fts, w_alias=w_alias
        )
        if not results:
            click.echo("No results.")
            return
        for i, res in enumerate(results, 1):
            md = res["metadata"]
            scores = res.get("scores", {})
            click.echo(f"{i}. {md.get('cwe_id')}: {md.get('name')}")
            click.echo(f"   hybrid={scores.get('hybrid', 0):.3f} vec={scores.get('vec', 0):.3f} fts={scores.get('fts', 0):.3f} alias={scores.get('alias', 0):.3f}")
            click.echo(f"   {res['document'][:140]}...")
            click.echo()
    else:
        # Vector-only (Chroma or Postgres fallback)
        results = pipeline.vector_store.query_similar(query_embedding, n_results)
        if not results:
            click.echo("No results.")
            return
        for i, res in enumerate(results, 1):
            md = res.get("metadata", {})
            click.echo(f"{i}. CWE-{md.get('cwe_id', 'N/A')}: {md.get('name', 'N/A')}")
            click.echo(f"   Distance: {res.get('distance', 'N/A')}")
            click.echo(f"   {res.get('document','')[:140]}...")
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
