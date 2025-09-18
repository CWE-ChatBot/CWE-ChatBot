# apps/cwe_ingestion/pipeline.py (only the parts shown are new/changed)
import os
...
try:
    from .pg_vector_store import PostgresVectorStore  # NEW
except ImportError:
    # allow running without Postgres deps in some envs
    PostgresVectorStore = None

class CWEIngestionPipeline:
    def __init__(..., embedder_type: str = "local", embedding_model: str = "all-MiniLM-L6-v2"):
        ...
        # Choose vector store
        vector_db_type = os.getenv("VECTOR_DB_TYPE", "chromadb").lower()
        if vector_db_type == "postgresql":
            if not PostgresVectorStore:
                raise ImportError("PostgresVectorStore not available; install psycopg.")
            dims = 3072 if embedder_type == "gemini" else 384
            self.vector_store = PostgresVectorStore(table="cwe_embeddings", dims=dims)
            logger.info("Using PostgresVectorStore (hybrid-ready)")
        else:
            self.vector_store = CWEVectorStore(storage_path=self.storage_path)
            logger.info("Using ChromaDB vector store")

        # Embedders unchanged
        if embedder_type == "gemini":
            self.embedder = GeminiEmbedder()
        else:
            self.embedder = CWEEmbedder(model_name=self.embedding_model)
        ...

    def run(self) -> bool:
        ...
        # 2) Parse XML -> CWEEntry models
        cwe_entries = self.parser.parse_file(xml_path, self.target_cwes)
        if not cwe_entries:
            ...
        # 3) Build text for embedding, include Aliases line (tiny boost, once)
        texts_to_embed = []
        aliases_by_id = {}
        for entry in cwe_entries:
            # collect alternate terms for Postgres FTS/boosts
            aliases = []
            if entry.AlternateTerms:
                aliases = [t.Term for t in entry.AlternateTerms if t and getattr(t, "Term", None)]
            aliases_by_id[entry.ID] = "; ".join(sorted({a for a in aliases if a}))

            ft = entry.to_searchable_text()
            if aliases_by_id[entry.ID]:
                ft = f"Aliases: {aliases_by_id[entry.ID]}\n\n" + ft  # light duplication near top
            texts_to_embed.append(ft)

        # 4) Embeddings
        embeddings = self.embedder.embed_batch(texts_to_embed)

        # 5) Prepare docs for storage (Postgres or Chroma)
        documents_to_store = []
        for entry, embedding, full_text in zip(cwe_entries, embeddings, texts_to_embed):
            doc = entry.to_embedding_data()
            doc["full_text"] = full_text
            doc["embedding"] = embedding
            # Extra fields that Postgres uses (safe to include for Chroma; it will ignore)
            doc["alternate_terms_text"] = aliases_by_id.get(entry.ID, "")
            documents_to_store.append(doc)

        # 6) Store
        stored_count = self.vector_store.store_batch(documents_to_store)
        logger.info(f"Successfully stored {stored_count} CWE documents.")
        ...
