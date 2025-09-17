# apps/cwe_ingestion/pipeline.py
"""
Main CWE ingestion pipeline orchestrator.
Combines all components into a unified workflow.
"""
import logging
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

try:
    # Try relative imports (when run as part of package)
    from .downloader import CWEDownloader
    from .embedder import CWEEmbedder, GeminiEmbedder
    from .parser import CWEParser
    from .vector_store import CWEVectorStore
except ImportError:
    # Fall back to absolute imports (when run directly or in tests)
    from downloader import CWEDownloader
    from embedder import CWEEmbedder, GeminiEmbedder
    from parser import CWEParser
    from vector_store import CWEVectorStore

logger = logging.getLogger(__name__)


class CWEIngestionPipeline:
    """Main pipeline for CWE data ingestion."""

    # Default target CWEs as specified in the story
    DEFAULT_TARGET_CWES = ['CWE-79', 'CWE-89', 'CWE-20', 'CWE-78', 'CWE-22']

    def __init__(
        self,
        storage_path: str = "./vector_db",
        target_cwes: Optional[List[str]] = None,
        source_url: str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        embedding_model: str = "all-MiniLM-L6-v2",
        embedder_type: str = "local"
    ):
        self.storage_path = storage_path
        self.target_cwes = target_cwes or self.DEFAULT_TARGET_CWES
        self.source_url = source_url
        self.embedding_model = embedding_model
        self.embedder_type = embedder_type

        # Validate embedder type
        valid_embedder_types = ["local", "gemini"]
        if embedder_type not in valid_embedder_types:
            raise ValueError(
                f"Invalid embedder_type '{embedder_type}'. "
                f"Must be one of: {valid_embedder_types}"
            )

        self.logger = logger

        # Initialize components
        self.downloader = CWEDownloader(source_url=source_url)
        self.parser = CWEParser()

        # Initialize embedder based on type
        if embedder_type == "gemini":
            self.embedder = GeminiEmbedder()
            logger.info("Initialized Gemini embedder (3072 dimensions)")
        else:  # local
            self.embedder = CWEEmbedder(model_name=embedding_model)
            logger.info(f"Initialized local embedder: {embedding_model}")

        self.vector_store = CWEVectorStore(storage_path=storage_path)

        logger.info(f"Pipeline initialized for {len(self.target_cwes)} target CWEs")

    def run_ingestion(self, force_download: bool = False) -> bool:
        """
        Run the complete CWE ingestion pipeline.

        Args:
            force_download: Whether to force re-download of CWE data

        Returns:
            bool: True if ingestion completed successfully
        """
        try:
            logger.info("Starting CWE data ingestion pipeline")

            # Step 1: Download CWE data
            temp_file = self._download_cwe_data(force_download)

            # Step 2: Parse and extract target CWEs
            cwe_data = self._parse_cwe_data(temp_file)

            if not cwe_data:
                logger.error("No CWE data extracted")
                return False

            # Step 3: Generate embeddings
            self._generate_embeddings(cwe_data)

            # Step 4: Store in vector database
            stored_count = self._store_embeddings(cwe_data)

            logger.info(f"Ingestion completed successfully. Stored {stored_count} CWEs.")

            # Step 5: Verification
            self._verify_ingestion()

            return True

        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            return False

    def _download_cwe_data(self, force_download: bool = False) -> str:
        """Download CWE data and extract XML."""
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = Path(temp_dir) / "cwe_data.zip"
            xml_path = Path(temp_dir) / "cwe_data.xml"

            # Download ZIP file
            self.downloader.download_file(str(zip_path))

            # Extract XML from ZIP
            self.downloader._extract_cwe_xml(str(zip_path), str(xml_path))

            return str(xml_path)

    def _parse_cwe_data(self, xml_file: str) -> List[Dict]:
        """Parse CWE XML and extract target CWEs."""
        logger.info(f"Parsing CWE data for {len(self.target_cwes)} target CWEs")

        cwe_data = self.parser.parse_file(xml_file, self.target_cwes)

        logger.info(f"Extracted {len(cwe_data)} CWEs from XML")
        return cwe_data

    def _generate_embeddings(self, cwe_data: List[Dict]) -> None:
        """Generate embeddings for all CWE texts."""
        logger.info("Generating embeddings for CWE descriptions")

        texts = [cwe['full_text'] for cwe in cwe_data]
        embeddings = self.embedder.embed_batch(texts)

        # Add embeddings back to CWE data
        for cwe, embedding in zip(cwe_data, embeddings):
            cwe['embedding'] = embedding

        logger.info(f"Generated {len(embeddings)} embeddings")

    def _store_embeddings(self, cwe_data: List[Dict]) -> int:
        """Store CWE data and embeddings in vector database."""
        logger.info("Storing CWE embeddings in vector database")

        stored_count = self.vector_store.store_batch(cwe_data)

        logger.info(f"Stored {stored_count} CWE embeddings")
        return stored_count

    def _verify_ingestion(self) -> None:
        """Verify that ingestion was successful."""
        stats = self.vector_store.get_collection_stats()
        logger.info(f"Verification: {stats}")

    def get_pipeline_status(self) -> Dict:
        """Get current pipeline status and configuration."""
        return {
            'target_cwes': self.target_cwes,
            'storage_path': self.storage_path,
            'embedding_model': self.embedding_model,
            'vector_store_stats': self.vector_store.get_collection_stats()
        }
