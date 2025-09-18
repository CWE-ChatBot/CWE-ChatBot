# apps/cwe_ingestion/pipeline.py
"""
Main CWE ingestion pipeline orchestrator.
Combines downloader, parser, embedder, and vector store into a unified workflow.
"""
import logging
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional

try:
    from .downloader import CWEDownloader
    from .embedder import CWEEmbedder, GeminiEmbedder
    from .parser import CWEParser
    from .vector_store import CWEVectorStore
except ImportError:
    from downloader import CWEDownloader
    from embedder import CWEEmbedder, GeminiEmbedder
    from parser import CWEParser
    from vector_store import CWEVectorStore

logger = logging.getLogger(__name__)

class CWEIngestionPipeline:
    """Main pipeline for downloading, parsing, embedding, and storing CWE data."""

    def __init__(
        self,
        storage_path: str = "./vector_db",
        target_cwes: Optional[List[str]] = None, # Set to None to ingest all
        source_url: str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        embedder_type: str = "local",
        embedding_model: str = "all-MiniLM-L6-v2",
    ):
        self.storage_path = storage_path
        self.target_cwes = target_cwes
        self.source_url = source_url
        self.embedding_model = embedding_model

        # Validate and initialize components
        if embedder_type not in ["local", "gemini"]:
            raise ValueError(
                f"Invalid embedder_type '{embedder_type}'. "
                "Must be 'local' or 'gemini'."
            )

        self.downloader = CWEDownloader(source_url=self.source_url)
        self.parser = CWEParser()
        self.vector_store = CWEVectorStore(storage_path=self.storage_path)

        if embedder_type == "gemini":
            self.embedder = GeminiEmbedder()
            logger.info("Initialized Gemini embedder.")
        else:
            self.embedder = CWEEmbedder(model_name=self.embedding_model)
            logger.info(f"Initialized local embedder: {self.embedding_model}")

        ingestion_scope = (
            f"{len(self.target_cwes)} target CWEs" if self.target_cwes else "all CWEs"
        )
        logger.info(f"Pipeline initialized to ingest {ingestion_scope}.")

    def run(self) -> bool:
        """
        Executes the complete CWE ingestion pipeline.

        Returns:
            True if ingestion completed successfully, False otherwise.
        """
        temp_dir = tempfile.mkdtemp()
        try:
            logger.info("--- Starting CWE Ingestion Pipeline ---")

            # 1. Download & Extract
            xml_path = self._download_and_extract(temp_dir)

            # 2. Parse XML to Pydantic Models
            cwe_entries = self.parser.parse_file(xml_path, self.target_cwes)
            if not cwe_entries:
                logger.warning(
                    "Parsing completed, but no CWE entries were extracted. Aborting."
                )
                return False

            # 3. Generate Embeddings
            logger.info(
                f"Generating embeddings for {len(cwe_entries)} CWE entries..."
            )
            texts_to_embed = [
                entry.to_searchable_text() for entry in cwe_entries
            ]
            embeddings = self.embedder.embed_batch(texts_to_embed)

            # 4. Prepare data for storage
            documents_to_store = []
            for entry, embedding in zip(cwe_entries, embeddings):
                doc = entry.to_embedding_data()
                doc['embedding'] = embedding
                documents_to_store.append(doc)

            # 5. Store in Vector Database
            logger.info("Storing documents in the vector database...")
            stored_count = self.vector_store.store_batch(documents_to_store)
            logger.info(f"Successfully stored {stored_count} CWE documents.")

            # 6. Verification
            self._verify_ingestion()
            logger.info("--- CWE Ingestion Pipeline Completed Successfully ---")
            return True

        except Exception as e:
            logger.critical(
                f"Pipeline failed with a critical error: {e}", exc_info=True
            )
            return False
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.debug(f"Cleaned up temporary directory: {temp_dir}")

    def _download_and_extract(self, temp_dir: str) -> str:
        """Downloads and extracts the CWE XML file."""
        logger.info(f"Downloading CWE data from {self.source_url}...")
        zip_path = Path(temp_dir) / "cwe_data.zip"
        xml_path = Path(temp_dir) / "cwec_latest.xml"

        self.downloader.download_file(str(zip_path))
        self.downloader._extract_cwe_xml(str(zip_path), str(xml_path))

        return str(xml_path)

    def _verify_ingestion(self) -> None:
        """Verifies ingestion by checking collection stats."""
        try:
            stats = self.vector_store.get_collection_stats()
            logger.info(f"Verification successful. Vector store stats: {stats}")
        except Exception as e:
            logger.error(f"Verification step failed: {e}")
