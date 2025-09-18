# apps/cwe_ingestion/multi_db_pipeline.py
"""
Multi-database CWE ingestion pipeline for cost-effective embedding generation.
Generates embeddings once and distributes to multiple PostgreSQL databases.
"""
import logging
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

try:
    # Relative imports (when used as module)
    from .downloader import CWEDownloader
    from .embedder import CWEEmbedder, GeminiEmbedder
    from .parser import CWEParser
    from .pg_vector_store import PostgresVectorStore
    from .pg_chunk_store import PostgresChunkStore
    from .models import entry_to_sections
except ImportError:
    # Absolute imports (when run directly)
    from downloader import CWEDownloader
    from embedder import CWEEmbedder, GeminiEmbedder
    from parser import CWEParser
    from pg_vector_store import PostgresVectorStore
    from pg_chunk_store import PostgresChunkStore
    from models import entry_to_sections

logger = logging.getLogger(__name__)


class DatabaseTarget:
    """Configuration for a database target."""

    def __init__(
        self,
        name: str,
        database_url: str,
        use_chunked: bool = True,
        description: str = ""
    ):
        self.name = name
        self.database_url = database_url
        self.use_chunked = use_chunked
        self.description = description or name


class MultiDatabaseCWEPipeline:
    """
    CWE ingestion pipeline that generates embeddings once and stores them
    in multiple PostgreSQL databases to reduce embedding costs.
    """

    def __init__(
        self,
        database_targets: List[DatabaseTarget],
        target_cwes: Optional[List[str]] = None,
        source_url: str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        embedder_type: str = "local",
        embedding_model: str = "all-MiniLM-L6-v2",
    ):
        self.database_targets = database_targets
        self.target_cwes = target_cwes
        self.source_url = source_url

        if not database_targets:
            raise ValueError("At least one database target must be specified")

        if embedder_type not in ("local", "gemini"):
            raise ValueError("embedder_type must be 'local' or 'gemini'")

        # Initialize embedder (shared across all databases)
        if embedder_type == "gemini":
            self.embedder = GeminiEmbedder()
            self.embedding_dim = 3072
            logger.info("Initialized Gemini embedder (3072-D) for multi-database ingestion.")
        else:
            self.embedder = CWEEmbedder(model_name=embedding_model)
            self.embedding_dim = self.embedder.get_embedding_dimension()
            logger.info(f"Initialized local embedder '{embedding_model}' ({self.embedding_dim}-D) for multi-database ingestion.")

        # Core components
        self.downloader = CWEDownloader(source_url=self.source_url)
        self.parser = CWEParser()

        logger.info(f"Configured for {len(database_targets)} database targets:")
        for target in database_targets:
            storage_mode = "chunked" if target.use_chunked else "single-row"
            logger.info(f"  - {target.name}: {target.description} ({storage_mode})")

    def run(self) -> bool:
        """Execute the multi-database pipeline end-to-end."""
        temp_dir = tempfile.mkdtemp()
        try:
            logger.info("--- Starting Multi-Database CWE Ingestion Pipeline ---")

            # Step 1: Download and parse CWE data
            xml_path = self._download_and_extract(temp_dir)
            cwe_entries = self.parser.parse_file(xml_path, self.target_cwes)

            if not cwe_entries:
                logger.warning("No CWE entries parsed. Aborting.")
                return False

            logger.info(f"Parsed {len(cwe_entries)} CWE entries for multi-database ingestion.")

            # Step 2: Generate embeddings once (cost optimization)
            embedding_data = self._generate_embeddings_once(cwe_entries)

            if not embedding_data:
                logger.error("Failed to generate embeddings. Aborting.")
                return False

            # Step 3: Store in all target databases
            success_count = self._store_in_all_databases(embedding_data)

            total_targets = len(self.database_targets)
            if success_count == total_targets:
                logger.info(f"✅ Successfully ingested data into all {total_targets} database targets.")
                return True
            elif success_count > 0:
                logger.warning(f"⚠️ Partial success: {success_count}/{total_targets} databases updated.")
                return False
            else:
                logger.error("❌ Failed to ingest data into any database targets.")
                return False

        except Exception as e:
            logger.critical(f"Multi-database pipeline failed: {e}", exc_info=True)
            return False
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.debug(f"Cleaned up temporary directory: {temp_dir}")

    def _generate_embeddings_once(self, cwe_entries) -> Dict[str, Any]:
        """
        Generate embeddings once for all entries and prepare data structures
        for both chunked and single-row storage modes.
        """
        logger.info("🔄 Generating embeddings once for all database targets...")

        embedding_data = {
            "single_row": [],
            "chunked": [],
            "metadata": {
                "total_entries": len(cwe_entries),
                "embedding_dim": self.embedding_dim,
                "embedder_type": type(self.embedder).__name__
            }
        }

        # Determine what storage modes we need
        needs_single = any(not target.use_chunked for target in self.database_targets)
        needs_chunked = any(target.use_chunked for target in self.database_targets)

        # Generate single-row embeddings if needed
        if needs_single:
            single_row_data = self._generate_single_row_embeddings(cwe_entries)
            embedding_data["single_row"] = single_row_data
            logger.info(f"✅ Generated {len(single_row_data)} single-row embeddings.")

        # Generate chunked embeddings if needed
        if needs_chunked:
            chunked_data = self._generate_chunked_embeddings(cwe_entries)
            embedding_data["chunked"] = chunked_data
            logger.info(f"✅ Generated {len(chunked_data)} chunked embeddings.")

        return embedding_data

    def _generate_single_row_embeddings(self, cwe_entries) -> List[Dict[str, Any]]:
        """Generate embeddings for single-row storage mode."""
        texts_to_embed: List[str] = []
        aliases_by_id: Dict[str, str] = {}

        for entry in cwe_entries:
            aliases = []
            if getattr(entry, "AlternateTerms", None):
                aliases = [t.Term for t in entry.AlternateTerms if getattr(t, "Term", None)]
            alias_line = "; ".join(sorted(set(a for a in aliases if a)))
            aliases_by_id[entry.ID] = alias_line

            ft = entry.to_searchable_text()
            if alias_line:
                ft = f"Aliases: {alias_line}\n\n{ft}"
            texts_to_embed.append(ft)

        embeddings = self.embedder.embed_batch(texts_to_embed)

        documents_to_store: List[Dict[str, Any]] = []
        for entry, embedding, full_text in zip(cwe_entries, embeddings, texts_to_embed):
            doc = entry.to_embedding_data()
            doc["full_text"] = full_text
            doc["embedding"] = embedding
            doc["alternate_terms_text"] = aliases_by_id.get(entry.ID, "")
            documents_to_store.append(doc)

        return documents_to_store

    def _generate_chunked_embeddings(self, cwe_entries) -> List[Dict[str, Any]]:
        """Generate embeddings for chunked storage mode."""
        chunk_payloads: List[Dict[str, Any]] = []

        for entry in cwe_entries:
            sections = entry_to_sections(entry)
            if not sections:
                continue

            texts = [s["text"] for s in sections]
            embs = self.embedder.embed_batch(texts)

            alias_line = ""
            if getattr(entry, "AlternateTerms", None):
                alias_line = "; ".join(sorted({t.Term for t in entry.AlternateTerms if getattr(t, "Term", None)}))

            for s, emb in zip(sections, embs):
                chunk_payloads.append({
                    "cwe_id": f"CWE-{entry.ID}",
                    "section": s["section"],
                    "section_rank": s["section_rank"],
                    "name": entry.Name,
                    "full_text": s["text"],
                    "alternate_terms_text": s["text"] if s["section"] == "Aliases" else alias_line,
                    "embedding": emb,
                })

        return chunk_payloads

    def _store_in_all_databases(self, embedding_data: Dict[str, Any]) -> int:
        """Store the pre-generated embeddings in all target databases."""
        success_count = 0

        for target in self.database_targets:
            try:
                logger.info(f"📥 Storing data in {target.name} ({target.description})...")

                # Create appropriate vector store for this target
                if target.use_chunked:
                    vector_store = PostgresChunkStore(
                        dims=self.embedding_dim,
                        database_url=target.database_url
                    )
                    data_to_store = embedding_data["chunked"]
                    storage_type = "chunked"
                else:
                    vector_store = PostgresVectorStore(
                        table="cwe_embeddings",
                        dims=self.embedding_dim,
                        database_url=target.database_url
                    )
                    data_to_store = embedding_data["single_row"]
                    storage_type = "single-row"

                if not data_to_store:
                    logger.warning(f"No {storage_type} data available for {target.name}")
                    continue

                # Store the data
                stored = vector_store.store_batch(data_to_store)
                logger.info(f"✅ {target.name}: Stored {stored} {storage_type} records.")

                # Verify the storage
                stats = vector_store.get_collection_stats()
                logger.info(f"📊 {target.name} stats: {stats}")

                success_count += 1

            except Exception as e:
                logger.error(f"❌ Failed to store data in {target.name}: {e}")
                continue

        return success_count

    def _download_and_extract(self, temp_dir: str) -> str:
        """Download the MITRE CWE ZIP and extract the XML."""
        zip_path = Path(temp_dir) / "cwe_data.zip"
        xml_path = Path(temp_dir) / "cwec_latest.xml"
        self.downloader.download_file(str(zip_path))
        self.downloader._extract_cwe_xml(str(zip_path), str(xml_path))
        return str(xml_path)


def create_database_targets_from_env() -> List[DatabaseTarget]:
    """
    Create database targets from environment variables.
    Supports LOCAL_DATABASE_URL and PROD_DATABASE_URL.

    For Google Cloud SQL with IAM authentication, PROD_DATABASE_URL should be:
    postgresql://username@host:5432/dbname

    IAM authentication is handled via:
    - GOOGLE_APPLICATION_CREDENTIALS environment variable
    - gcloud auth application-default login
    - Cloud Run/GCE service account (automatic)
    """
    import os

    targets = []

    # Local database (typically Docker)
    local_url = os.environ.get("LOCAL_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if local_url:
        targets.append(DatabaseTarget(
            name="local",
            database_url=local_url,
            use_chunked=True,
            description="Local development database"
        ))

    # Production database (Google Cloud SQL with IAM)
    prod_url = os.environ.get("PROD_DATABASE_URL") or os.environ.get("PRODUCTION_DATABASE_URL")
    if prod_url:
        # Check if this looks like a Google Cloud SQL IAM connection
        if "@" in prod_url and ":" not in prod_url.split("@")[0].split("://")[1]:
            # Looks like postgresql://username@host:port/db (no password)
            description = "Production database (Google Cloud SQL + IAM)"
        else:
            description = "Production database"

        targets.append(DatabaseTarget(
            name="production",
            database_url=prod_url,
            use_chunked=True,
            description=description
        ))

    if not targets:
        raise ValueError(
            "No database targets found. Set LOCAL_DATABASE_URL and/or PROD_DATABASE_URL environment variables.\n"
            "Examples:\n"
            "  LOCAL_DATABASE_URL='postgresql://postgres:password@localhost:5432/cwe'\n"
            "  PROD_DATABASE_URL='postgresql://username@project:region:instance/dbname'  # Google Cloud SQL IAM"
        )

    return targets

def create_google_cloud_sql_url(
    project_id: str,
    region: str,
    instance_name: str,
    database_name: str,
    username: str
) -> str:
    """
    Create a Google Cloud SQL connection URL for IAM authentication.

    Args:
        project_id: GCP project ID
        region: Cloud SQL region (e.g., 'us-central1')
        instance_name: Cloud SQL instance name
        database_name: Database name
        username: IAM database username (usually service account email without @project.iam)

    Returns:
        Connection URL for Google Cloud SQL with IAM authentication
    """
    # Google Cloud SQL connection format for IAM
    host = f"{project_id}:{region}:{instance_name}"
    return f"postgresql://{username}@{host}/{database_name}"