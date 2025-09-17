# apps/cwe_ingestion/vector_store.py
"""
Vector database integration for CWE embeddings using ChromaDB.
"""
import logging
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

logger = logging.getLogger(__name__)


class CWEVectorStore:
    """ChromaDB-based vector store for CWE embeddings and metadata."""

    def __init__(self, storage_type: str = "chromadb", storage_path: str = "./chroma_db"):
        self.storage_type = storage_type
        self.storage_path = storage_path
        self.collection_name = "cwe_embeddings"

        try:
            # Initialize ChromaDB client
            import chromadb
            from chromadb.config import Settings

            # Create storage directory if it doesn't exist
            Path(storage_path).mkdir(parents=True, exist_ok=True)

            # Initialize persistent client
            self.client = chromadb.PersistentClient(
                path=storage_path,
                settings=Settings(
                    anonymized_telemetry=False,  # Disable telemetry for privacy
                    allow_reset=False  # Security: prevent accidental resets
                )
            )

            # Create or get collection
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"description": "CWE embeddings and metadata"}
            )

            logger.info(f"ChromaDB vector store initialized at {storage_path}")

        except Exception as e:
            logger.error(f"Failed to initialize ChromaDB: {e}")
            raise

    def store_cwe(self, cwe_data: Dict) -> bool:
        """
        Store CWE data and embedding in vector database.

        Args:
            cwe_data: Dictionary containing CWE info and embedding

        Returns:
            bool: True if storage successful
        """
        try:
            doc_id = f"cwe-{cwe_data['id']}"

            # Convert numpy array to list for ChromaDB
            embedding = cwe_data['embedding']
            if isinstance(embedding, np.ndarray):
                embedding = embedding.tolist()

            metadata = {
                'cwe_id': cwe_data['id'],
                'name': cwe_data['name'],
                'abstraction': cwe_data.get('abstraction', ''),
                'status': cwe_data.get('status', ''),
                'description': cwe_data.get('description', '')
            }

            # Store in ChromaDB
            self.collection.add(
                ids=[doc_id],
                embeddings=[embedding],
                documents=[cwe_data['full_text']],
                metadatas=[metadata]
            )

            logger.debug(f"Stored CWE-{cwe_data['id']} in vector database")
            return True

        except Exception as e:
            logger.error(f"Failed to store CWE-{cwe_data.get('id', 'unknown')}: {e}")
            return False

    def store_batch(self, cwe_batch: List[Dict]) -> int:
        """Store multiple CWEs in batch for efficiency."""
        try:
            ids = []
            embeddings = []
            documents = []
            metadatas = []

            for cwe_data in cwe_batch:
                doc_id = f"cwe-{cwe_data['id']}"
                ids.append(doc_id)

                # Convert embedding to list
                embedding = cwe_data['embedding']
                if isinstance(embedding, np.ndarray):
                    embedding = embedding.tolist()
                embeddings.append(embedding)

                documents.append(cwe_data['full_text'])

                metadata = {
                    'cwe_id': cwe_data['id'],
                    'name': cwe_data['name'],
                    'abstraction': cwe_data.get('abstraction', ''),
                    'status': cwe_data.get('status', ''),
                    'description': cwe_data.get('description', '')
                }
                metadatas.append(metadata)

            # Batch insert
            self.collection.add(
                ids=ids,
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas
            )

            logger.info(f"Stored batch of {len(cwe_batch)} CWEs")
            return len(cwe_batch)

        except Exception as e:
            logger.error(f"Failed to store CWE batch: {e}")
            return 0

    def query_similar(self, query_embedding: np.ndarray, n_results: int = 5) -> List[Dict]:
        """
        Query for similar CWEs based on embedding similarity.

        Args:
            query_embedding: Embedding vector to search for
            n_results: Number of similar CWEs to return

        Returns:
            List of similar CWEs with metadata
        """
        try:
            if isinstance(query_embedding, np.ndarray):
                query_embedding = query_embedding.tolist()

            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results,
                include=['documents', 'metadatas', 'distances']
            )

            # Format results
            formatted_results = []
            if results.get('documents') and len(results['documents']) > 0:
                for i in range(len(results['documents'][0])):
                    result = {
                        'document': results['documents'][0][i],
                        'metadata': results['metadatas'][0][i] if results.get('metadatas') else {},
                        'distance': results['distances'][0][i] if results.get('distances') else None
                    }
                    formatted_results.append(result)

            return formatted_results

        except Exception as e:
            logger.error(f"Failed to query similar CWEs: {e}")
            return []

    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the collection."""
        try:
            count = self.collection.count()
            return {
                'collection_name': self.collection_name,
                'count': count,
                'storage_path': self.storage_path
            }
        except Exception as e:
            logger.error(f"Failed to get collection stats: {e}")
            return {'error': str(e)}

    def reset_collection(self) -> bool:
        """Reset the collection (use with caution)."""
        try:
            self.client.delete_collection(self.collection_name)
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"description": "CWE embeddings and metadata"}
            )
            logger.warning(f"Collection {self.collection_name} has been reset")
            return True
        except Exception as e:
            logger.error(f"Failed to reset collection: {e}")
            return False
