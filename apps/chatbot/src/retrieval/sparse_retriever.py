"""
Sparse BM25 retriever with keyphrase boosting using PostgreSQL data.
Implements keyword-based search using BM25 algorithm.
"""

import logging
from typing import List, Dict, Any, Optional
import psycopg2
from rank_bm25 import BM25Okapi

from .base_retriever import ChatBotBaseRetriever, CWEResult


logger = logging.getLogger(__name__)


class ChatBotSparseRetriever(ChatBotBaseRetriever):
    """
    Sparse BM25 retriever with keyphrase boosting.
    
    Loads CWE text data from PostgreSQL and performs BM25-based keyword search.
    """
    
    def __init__(self, pg_config: Dict[str, str]):
        """
        Initialize the sparse retriever.
        
        Args:
            pg_config: PostgreSQL connection configuration
        """
        self.pg_config = pg_config
        self.connection = None
        self.table_name = "cwe_embeddings"
        self.entries = []
        self.bm25 = None
        self.cwe_id_to_index = {}
        
        # Initialize database connection and load data
        self._connect()
        self._load_cwe_entries()
        self._setup_bm25()
        
        logger.info(f"Initialized ChatBotSparseRetriever with {len(self.entries)} entries")
    
    def _connect(self) -> None:
        """Establish connection to PostgreSQL database."""
        try:
            self.connection = psycopg2.connect(**self.pg_config)
            logger.info("Connected to PostgreSQL database for sparse retrieval")
        except psycopg2.Error as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            raise ConnectionError(f"Database connection failed: {e}")
    
    def _load_cwe_entries(self) -> None:
        """Load CWE entries from PostgreSQL for BM25 indexing."""
        if not self.connection:
            self._connect()
        
        try:
            with self.connection.cursor() as cursor:
                sql = """
                SELECT cwe_id, name, description, full_text, metadata
                FROM {table_name}
                ORDER BY cwe_id;
                """.format(table_name=self.table_name)
                
                cursor.execute(sql)
                rows = cursor.fetchall()
                
                self.entries = []
                self.cwe_id_to_index = {}
                
                for i, row in enumerate(rows):
                    cwe_id, name, description, full_text, metadata = row
                    
                    entry = {
                        'cwe_id': cwe_id,
                        'name': name or '',
                        'description': description or '',
                        'full_text': full_text or '',
                        'metadata': metadata or {},
                        'search_text': self._prepare_search_text(cwe_id, name, description, full_text)
                    }
                    
                    self.entries.append(entry)
                    self.cwe_id_to_index[cwe_id] = i
                
                logger.info(f"Loaded {len(self.entries)} CWE entries from database")
                
        except psycopg2.Error as e:
            logger.error(f"Failed to load CWE entries: {e}")
            raise
    
    def _prepare_search_text(self, cwe_id: str, name: str, description: str, full_text: str) -> str:
        """
        Prepare searchable text by combining all relevant fields.
        
        Args:
            cwe_id: CWE identifier
            name: CWE name
            description: CWE description  
            full_text: Full CWE text content
            
        Returns:
            Combined search text
        """
        # Combine all text fields with appropriate weighting
        search_text = f"{cwe_id} {name} {description}"
        
        # Add full text if available
        if full_text:
            search_text += f" {full_text}"
        
        return search_text.lower()
    
    def _setup_bm25(self) -> None:
        """Set up BM25 index from loaded entries."""
        if not self.entries:
            logger.warning("No entries loaded, cannot setup BM25")
            return
        
        # Tokenize search text for each entry
        tokenized_corpus = [entry['search_text'].split() for entry in self.entries]
        
        # Create BM25 index
        self.bm25 = BM25Okapi(tokenized_corpus)
        logger.info("BM25 index created successfully")
    
    def search(self, query: str, k: int = 5, **kwargs) -> List[CWEResult]:
        """
        Perform BM25-based keyword search.
        
        Args:
            query: Search query string
            k: Number of results to return
            **kwargs: Additional parameters (keyphrases, boost_terms, etc.)
            
        Returns:
            List of CWEResult objects ranked by BM25 score
        """
        if not query or not query.strip() or not self.bm25:
            return []
        
        try:
            # Tokenize query
            query_tokens = query.lower().strip().split()
            
            # Apply keyphrase boosting if provided
            keyphrases = kwargs.get('keyphrases', {})
            boosted_tokens = self._apply_keyphrase_boosting(query_tokens, keyphrases)
            
            # Get BM25 scores
            scores = self.bm25.get_scores(boosted_tokens)
            
            # Get top-k results
            top_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]
            
            # Convert to CWEResult objects
            results = []
            for idx in top_indices:
                if scores[idx] > 0:  # Only include results with positive scores
                    entry = self.entries[idx]
                    
                    result = CWEResult(
                        cwe_id=entry['cwe_id'],
                        name=entry['name'],
                        description=entry['description'],
                        confidence_score=float(scores[idx]),
                        source_method="sparse",
                        metadata=entry['metadata']
                    )
                    results.append(result)
            
            logger.debug(f"Sparse search returned {len(results)} results")
            return results
            
        except Exception as e:
            logger.error(f"Sparse search failed: {e}")
            return []
    
    def search_with_keyphrases(
        self, 
        query: str, 
        keyphrases: Dict[str, List[str]], 
        k: int = 5
    ) -> List[CWEResult]:
        """
        Enhanced search with keyphrase boosting.
        
        Args:
            query: Original search query
            keyphrases: Dictionary of keyphrase categories and terms
            k: Number of results to return
            
        Returns:
            List of CWEResult objects with boosted scoring
        """
        return self.search(query, k=k, keyphrases=keyphrases)
    
    def _apply_keyphrase_boosting(
        self, 
        query_tokens: List[str], 
        keyphrases: Dict[str, List[str]],
        boost_factor: float = 1.5
    ) -> List[str]:
        """
        Apply keyphrase boosting to query tokens.
        
        Args:
            query_tokens: Original query tokens
            keyphrases: Extracted keyphrases by category
            boost_factor: Factor by which to boost keyphrase terms
            
        Returns:
            Enhanced token list with boosted terms
        """
        if not keyphrases:
            return query_tokens
        
        boosted_tokens = query_tokens.copy()
        
        # Add boosted versions of security terms
        for category, terms in keyphrases.items():
            for term in terms:
                term_tokens = term.lower().split()
                # Add each term multiple times based on boost factor
                boost_count = int(boost_factor)
                for _ in range(boost_count):
                    boosted_tokens.extend(term_tokens)
        
        return boosted_tokens
    
    def get_by_id(self, cwe_id: str) -> Optional[CWEResult]:
        """
        Get specific CWE by ID using index lookup.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-79")
            
        Returns:
            CWEResult if found, None otherwise
        """
        if not cwe_id or cwe_id not in self.cwe_id_to_index:
            return None
        
        idx = self.cwe_id_to_index[cwe_id]
        entry = self.entries[idx]
        
        return CWEResult(
            cwe_id=entry['cwe_id'],
            name=entry['name'],
            description=entry['description'],
            confidence_score=1.0,  # Perfect match for direct lookup
            source_method="direct",
            metadata=entry['metadata']
        )
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get retriever metadata for evaluation."""
        return {
            "retriever_type": "sparse",
            "method": "bm25",
            "total_entries": len(self.entries),
            "indexed_entries": len(self.entries) if self.bm25 else 0,
            "table_name": self.table_name
        }
    
    def __del__(self):
        """Clean up database connection."""
        if hasattr(self, 'connection') and self.connection:
            try:
                self.connection.close()
            except:
                pass  # Ignore errors during cleanup