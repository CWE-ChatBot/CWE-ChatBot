# apps/cwe_ingestion/pipeline.py
"""
PostgreSQL-only CWE ingestion pipeline (single-row or chunked) with optional Gemini embeddings.
"""

import logging
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

if TYPE_CHECKING:
    # Type checking imports
    from .downloader import CWEDownloader
    from .embedder import CWEEmbedder, GeminiEmbedder
    from .models import entry_to_sections
    from .parser import CWEParser
    from .pg_chunk_store import PostgresChunkStore
    from .pg_vector_store import PostgresVectorStore
else:
    # Runtime imports - try relative first, fall back to absolute
    try:
        from .downloader import CWEDownloader
        from .embedder import CWEEmbedder, GeminiEmbedder
        from .models import entry_to_sections
        from .parser import CWEParser
        from .pg_chunk_store import PostgresChunkStore
        from .pg_vector_store import PostgresVectorStore
    except ImportError:
        from downloader import CWEDownloader  # type: ignore[no-redef]
        from embedder import CWEEmbedder, GeminiEmbedder  # type: ignore[no-redef]
        from models import entry_to_sections  # type: ignore[no-redef]
        from parser import CWEParser  # type: ignore[no-redef]
        from pg_chunk_store import PostgresChunkStore  # type: ignore[no-redef]
        from pg_vector_store import PostgresVectorStore  # type: ignore[no-redef]

logger = logging.getLogger(__name__)


class CWEIngestionPipeline:
    """Main pipeline for downloading, parsing, embedding, and storing CWE data (Postgres only)."""

    embedder: Union["CWEEmbedder", "GeminiEmbedder"]
    vector_store: Union["PostgresChunkStore", "PostgresVectorStore"]
    downloader: "CWEDownloader"
    parser: "CWEParser"

    def __init__(
        self,
        target_cwes: Optional[List[str]] = None,  # None -> ingest all
        source_url: str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        embedder_type: str = "local",  # "local" | "gemini"
        embedding_model: str = "all-MiniLM-L6-v2",
        use_chunked: bool = True,  # True -> use PostgresChunkStore
    ) -> None:
        self.target_cwes = target_cwes
        self.source_url = source_url

        if embedder_type not in ("local", "gemini"):
            raise ValueError("embedder_type must be 'local' or 'gemini'")

        # Embedder
        if embedder_type == "gemini":
            self.embedder = GeminiEmbedder()
            self.embedding_dim = 3072
            logger.info("Initialized Gemini embedder (3072-D).")
        else:
            self.embedder = CWEEmbedder(model_name=embedding_model)
            self.embedding_dim = self.embedder.get_embedding_dimension()
            logger.info(
                f"Initialized local embedder '{embedding_model}' ({self.embedding_dim}-D)."
            )

        # Core components
        self.use_chunked = bool(use_chunked)
        self.downloader = CWEDownloader(source_url=self.source_url)
        self.parser = CWEParser()
        if self.use_chunked:
            self.vector_store = PostgresChunkStore(dims=self.embedding_dim)
            logger.info("Using PostgresChunkStore (chunked).")
        else:
            self.vector_store = PostgresVectorStore(
                table="cwe_embeddings", dims=self.embedding_dim
            )
            logger.info("Using PostgresVectorStore (single-row).")

    def run(self) -> bool:
        """Execute the pipeline end-to-end."""
        temp_dir = tempfile.mkdtemp()
        try:
            logger.info("--- Starting CWE Ingestion Pipeline (Postgres-only) ---")
            xml_path = self._download_and_extract(temp_dir)

            # Parse XML to models
            cwe_entries = self.parser.parse_file(xml_path, self.target_cwes)
            if not cwe_entries:
                logger.warning("No CWE entries parsed. Aborting.")
                return False

            if self.use_chunked and isinstance(self.vector_store, PostgresChunkStore):
                ok = self._run_chunked(cwe_entries)
            else:
                ok = self._run_single(cwe_entries)

            if ok:
                logger.info("--- CWE Ingestion Pipeline Completed Successfully ---")
            return ok

        except Exception as e:
            logger.critical(f"Pipeline failed: {e}", exc_info=True)
            return False
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.debug(f"Cleaned up temporary directory: {temp_dir}")

    def _run_single(self, cwe_entries: List[Any]) -> bool:
        """Single-row mode: build full_text (with one Aliases line), embed, store."""
        texts_to_embed: List[str] = []
        aliases_by_id: Dict[str, str] = {}

        for entry in cwe_entries:
            aliases = []
            if getattr(entry, "AlternateTerms", None):
                aliases = [
                    t.Term for t in entry.AlternateTerms if getattr(t, "Term", None)
                ]
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

        # Type narrowing: _run_single only called when use_chunked=False (PostgresVectorStore)
        if isinstance(self.vector_store, PostgresVectorStore):
            stored = self.vector_store.store_batch(documents_to_store)
            logger.info(f"Stored {stored} single-row docs.")
            self._verify_ingestion()
            return stored > 0
        return False

    def _run_chunked(self, cwe_entries: List[Any]) -> bool:
        """Chunked mode: split each entry into semantic sections, embed, store."""
        chunk_payloads: List[Dict[str, Any]] = []

        for entry in cwe_entries:
            sections = entry_to_sections(entry)  # [{section, section_rank, text}, ...]
            if not sections:
                continue

            texts = [s["text"] for s in sections]
            embs = self.embedder.embed_batch(texts)

            alias_line = ""
            if getattr(entry, "AlternateTerms", None):
                alias_line = "; ".join(
                    sorted(
                        {
                            t.Term
                            for t in entry.AlternateTerms
                            if getattr(t, "Term", None)
                        }
                    )
                )

            for s, emb in zip(sections, embs):
                chunk_payloads.append(
                    {
                        "cwe_id": f"CWE-{entry.ID}",
                        "section": s["section"],
                        "section_rank": s["section_rank"],
                        "name": entry.Name,
                        "full_text": s["text"],
                        "alternate_terms_text": s["text"]
                        if s["section"] == "Aliases"
                        else alias_line,
                        "embedding": emb,
                    }
                )

        if not chunk_payloads:
            logger.warning("No chunk payloads to store.")
            return False

        # Type narrowing: _run_chunked only called when use_chunked=True (PostgresChunkStore)
        if isinstance(self.vector_store, PostgresChunkStore):
            stored = self.vector_store.store_chunks(chunk_payloads)
            logger.info(f"Stored {stored} chunks.")
            self._verify_ingestion()
            return stored > 0
        return False

    def _download_and_extract(self, temp_dir: str) -> str:
        """Download the MITRE CWE ZIP and extract the XML."""
        zip_path = Path(temp_dir) / "cwe_data.zip"
        xml_path = Path(temp_dir) / "cwec_latest.xml"
        self.downloader.download_file(str(zip_path))
        self.downloader._extract_cwe_xml(str(zip_path), str(xml_path))
        return str(xml_path)

    def _verify_ingestion(self) -> None:
        """Log collection stats from the vector store."""
        try:
            stats = self.vector_store.get_collection_stats()
            logger.info(f"Vector store stats: {stats}")
        except Exception as e:
            logger.error(f"Verification failed: {e}")
