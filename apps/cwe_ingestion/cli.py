# apps/cwe_ingestion/cli.py
#!/usr/bin/env python3
import logging
import sys
import click

try:
    # Relative imports (when used as module)
    from .pg_chunk_store import PostgresChunkStore
    from .pg_vector_store import PostgresVectorStore
    from .pipeline import CWEIngestionPipeline
except ImportError:
    # Absolute imports (when run directly)
    from pg_chunk_store import PostgresChunkStore
    from pg_vector_store import PostgresVectorStore
    from pipeline import CWEIngestionPipeline

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

@click.group()
@click.option('--debug', is_flag=True, help='Enable debug logging')
def cli(debug):
    """CWE Data Ingestion Pipeline (PostgreSQL + pgvector only)"""
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    click.echo("🔧 CWE Data Ingestion Pipeline (PostgreSQL)")

@cli.command()
@click.option('--target-cwes', '-c', multiple=True, help='Specific CWE IDs to ingest (e.g., CWE-79)')
@click.option('--embedding-model', '-m', default='all-MiniLM-L6-v2', help='Local model name when --embedder-type=local')
@click.option('--embedder-type', '-e', default='local', type=click.Choice(['local', 'gemini'], case_sensitive=False))
@click.option('--chunked/--single', default=True, help='Store as chunked rows (recommended)')
def ingest(target_cwes, embedding_model, embedder_type, chunked):
    """Run the complete CWE ingestion pipeline (Postgres-only)."""
    pipeline = CWEIngestionPipeline(
        target_cwes=list(target_cwes) if target_cwes else None,
        embedding_model=embedding_model,
        embedder_type=embedder_type,
        use_chunked=chunked
    )
    ok = pipeline.run()
    click.echo("✅ CWE ingestion completed successfully!" if ok else "❌ CWE ingestion failed!")
    sys.exit(0 if ok else 1)

@cli.command()
@click.option('--query', '-q', 'query_text', required=True, help='Text to search')
@click.option('--n-results', '-n', default=5, help='Number of CWEs to return')
@click.option('--hybrid', is_flag=True, help='Use hybrid retrieval (recommended)')
@click.option('--chunked/--single', default=True, help='Search chunked store or single-row store')
@click.option('--w-vec', default=0.65, type=float, show_default=True)
@click.option('--w-fts', default=0.25, type=float, show_default=True)
@click.option('--w-alias', default=0.10, type=float, show_default=True)
@click.option('--boost-section', type=click.Choice(
    ['Mitigations','Abstract','Extended','Examples','Related','Title','Aliases'], case_sensitive=False),
    default=None
)
def query(query_text, n_results, hybrid, chunked, w_vec, w_fts, w_alias, boost_section):
    """Query similar CWEs (Postgres-only)."""
    pipe = CWEIngestionPipeline(use_chunked=chunked)
    qemb = pipe.embedder.embed_text(query_text)

    click.echo(f"🔍 Query: '{query_text}'\n" + "-"*50)

    if not hybrid:
        # Vector-only fallback
        results = pipe.vector_store.query_similar(qemb, n_results)
        if not results:
            click.echo("No results."); return
        for i, r in enumerate(results, 1):
            md = r.get("metadata", {})
            click.echo(f"{i}. {md.get('cwe_id','?')}: {md.get('name','?')}")
            click.echo(f"   Distance: {r.get('distance','N/A')}")
            click.echo(f"   {r.get('document','')[:180]}...\n")
        return

    # HYBRID path — branch by concrete store type so kwargs match signatures
    store = pipe.vector_store

    if isinstance(store, PostgresChunkStore):
        results = store.query_hybrid(
            query_text=query_text,
            query_embedding=qemb,
            k_vec=max(n_results * 5, 50),
            limit_chunks=max(n_results * 3, 15),
            w_vec=w_vec, w_fts=w_fts, w_alias=w_alias,
            section_intent_boost=boost_section or _infer_section_intent(query_text),
            section_boost_value=0.15
        )
        if not results:
            click.echo("No results."); return

        # Group top chunks by CWE and show best 1–2 per CWE
        from collections import defaultdict
        grouped = defaultdict(list)
        for r in results:
            grouped[r["metadata"]["cwe_id"]].append(r)

        ranked = sorted(
            ((cid, max(ch["scores"]["hybrid"] for ch in chunks)) for cid, chunks in grouped.items()),
            key=lambda x: x[1],
            reverse=True
        )[:n_results]

        for rank, (cid, score) in enumerate(ranked, 1):
            best = sorted(grouped[cid], key=lambda ch: (-ch["scores"]["hybrid"], ch["metadata"]["section_rank"]))[:2]
            name = best[0]["metadata"]["name"]
            click.echo(f"{rank}. {cid}: {name}  (score={score:.3f})")
            for ch in best:
                md, sc = ch["metadata"], ch["scores"]
                click.echo(f"   ▸ [{md['section']}] hybrid={sc['hybrid']:.3f} vec={sc['vec']:.3f} fts={sc['fts']:.3f} alias={sc['alias']:.3f}")
                click.echo(f"     {ch['document'][:180]}...")
            click.echo()

    elif isinstance(store, PostgresVectorStore):
        results = store.query_hybrid(
            query_text=query_text,
            query_embedding=qemb,
            k_vec=max(n_results * 5, 25),
            limit=n_results,
            w_vec=w_vec, w_fts=w_fts, w_alias=w_alias
        )
        if not results:
            click.echo("No results."); return

        for i, res in enumerate(results, 1):
            md, sc = res["metadata"], res["scores"]
            click.echo(f"{i}. {md['cwe_id']}: {md['name']}  (hybrid={sc['hybrid']:.3f})")
            click.echo(f"   vec={sc['vec']:.3f} fts={sc['fts']:.3f} alias={sc['alias']:.3f}")
            click.echo(f"   {res['document'][:180]}...\n")

    else:
        click.echo("Unknown vector store type.")

def _infer_section_intent(q: str):
    ql = q.lower()
    if any(k in ql for k in ["prevent","mitigat","remediat","fix"]):
        return "Mitigations"
    return None

@cli.command()
@click.option('--chunked/--single', default=True, help='Check chunked store or single-row store')
def stats(chunked):
    """Show database health and collection statistics."""
    import os

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        click.echo("❌ DATABASE_URL environment variable is required")
        sys.exit(1)

    try:
        # Create the appropriate store type
        if chunked:
            click.echo("📊 PostgreSQL Chunked Store Health Check")
            click.echo("-" * 40)
            store = PostgresChunkStore()
            store_type = "chunked (cwe_chunks table)"
        else:
            click.echo("📊 PostgreSQL Single Store Health Check")
            click.echo("-" * 40)
            store = PostgresVectorStore()
            store_type = "single-row (cwe_embeddings table)"

        # Test database connection
        try:
            stats = store.get_collection_stats()
            click.echo(f"✅ Database connection: OK")
            click.echo(f"📦 Storage type: {store_type}")
            click.echo(f"🎯 Collection: {stats['collection_name']}")
            click.echo(f"📈 Record count: {stats['count']:,}")

            if stats['count'] > 0:
                click.echo(f"💡 Vector dimensions: {store.dims}")
                click.echo("✅ Database is healthy and contains data")
            else:
                click.echo("⚠️  Database is healthy but empty - run 'ingest' command first")

        except Exception as db_error:
            click.echo(f"❌ Database connection failed: {db_error}")
            sys.exit(1)

    except Exception as e:
        click.echo(f"❌ Health check failed: {e}")
        sys.exit(1)

@cli.command()
@click.option('--target-cwes', '-c', multiple=True, help='Specific CWE IDs to ingest (e.g., CWE-79)')
@click.option('--embedding-model', '-m', default='all-MiniLM-L6-v2', help='Local model name when --embedder-type=local')
@click.option('--embedder-type', '-e', default='local', type=click.Choice(['local', 'gemini'], case_sensitive=False))
@click.option('--local-chunked/--local-single', default=True, help='Local database storage mode')
@click.option('--prod-chunked/--prod-single', default=True, help='Production database storage mode')
def ingest_multi(target_cwes, embedding_model, embedder_type, local_chunked, prod_chunked):
    """
    Run CWE ingestion to multiple databases with embeddings generated once.

    Requires environment variables:
    - LOCAL_DATABASE_URL or DATABASE_URL (for local/development database)
    - PROD_DATABASE_URL or PRODUCTION_DATABASE_URL (for production database)

    Examples:
    LOCAL_DATABASE_URL='postgresql://postgres:password@localhost:5432/cwe'
    PROD_DATABASE_URL='postgresql://username@project:region:instance/dbname'  # Google Cloud SQL IAM

    This command generates embeddings once and stores them in both databases,
    significantly reducing costs when using Gemini embeddings.
    """
    try:
        try:
            from .multi_db_pipeline import MultiDatabaseCWEPipeline, create_database_targets_from_env
        except ImportError:
            from multi_db_pipeline import MultiDatabaseCWEPipeline, create_database_targets_from_env
    except ImportError as e:
        click.echo(f"❌ Multi-database pipeline not available: {e}")
        sys.exit(1)

    try:
        # Get database targets from environment
        targets = create_database_targets_from_env()

        # Override chunked settings from CLI
        for target in targets:
            if target.name == "local":
                target.use_chunked = local_chunked
            elif target.name == "production":
                target.use_chunked = prod_chunked

        click.echo(f"🎯 Multi-database ingestion configured for {len(targets)} targets:")
        for target in targets:
            storage_mode = "chunked" if target.use_chunked else "single-row"
            click.echo(f"   • {target.name}: {target.description} ({storage_mode})")

        if embedder_type == "gemini":
            click.echo("💰 Using Gemini embeddings - cost optimized with single generation!")

        # Create and run pipeline
        pipeline = MultiDatabaseCWEPipeline(
            database_targets=targets,
            target_cwes=list(target_cwes) if target_cwes else None,
            embedder_type=embedder_type,
            embedding_model=embedding_model
        )

        ok = pipeline.run()

        if ok:
            click.echo("✅ Multi-database CWE ingestion completed successfully!")
            click.echo("💡 Embeddings were generated once and distributed to all targets.")
        else:
            click.echo("❌ Multi-database CWE ingestion failed!")

        sys.exit(0 if ok else 1)

    except Exception as e:
        click.echo(f"❌ Multi-database ingestion failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    cli()
