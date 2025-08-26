"""
Hybrid RAG manager for coordinating dense and sparse retrieval methods.
Implements configurable score fusion and retrieval strategy selection.
"""

import logging
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base_retriever import CWEResult
from .dense_retriever import ChatBotDenseRetriever
from .sparse_retriever import ChatBotSparseRetriever
from ..processing.embedding_service import EmbeddingService


logger = logging.getLogger(__name__)


class HybridRAGManager:
    """
    Manages hybrid retrieval with PostgreSQL+pgvector backend and configurable weighting.
    
    Coordinates multiple retrieval methods and fuses results using configurable weights
    and sophisticated scoring algorithms.
    """
    
    def __init__(
        self,
        pg_config: Dict[str, str],
        embedding_service: Optional[EmbeddingService] = None,
        weights: Optional[Dict[str, float]] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the hybrid RAG manager.
        
        Args:
            pg_config: PostgreSQL connection configuration
            embedding_service: Service for generating embeddings
            weights: Retrieval method weights {"dense": 0.6, "sparse": 0.4}
            config: Additional configuration options
        """
        self.pg_config = pg_config
        self.weights = weights or {"dense": 0.6, "sparse": 0.4}
        self.config = config or {}
        
        # Validate weights
        if not abs(sum(self.weights.values()) - 1.0) < 0.001:
            logger.warning(f"Weights don't sum to 1.0: {self.weights}")
        
        # Initialize embedding service
        if embedding_service is None:
            self.embedding_service = EmbeddingService()
        else:
            self.embedding_service = embedding_service
        
        # Initialize retrievers
        self.dense_retriever = ChatBotDenseRetriever(pg_config, self.embedding_service)
        self.sparse_retriever = ChatBotSparseRetriever(pg_config)
        
        logger.info(f"Initialized HybridRAGManager with weights: {self.weights}")
    
    def search(
        self, 
        query: str, 
        k: int = 5, 
        strategy: str = "hybrid",
        **kwargs
    ) -> List[CWEResult]:
        """
        Perform retrieval using specified strategy.
        
        Args:
            query: Search query string
            k: Number of results to return
            strategy: Retrieval strategy ("hybrid", "dense", "sparse", "direct")
            **kwargs: Additional search parameters
            
        Returns:
            List of CWEResult objects ranked by relevance
        """
        if not query or not query.strip():
            return []
        
        try:
            if strategy == "direct":
                return self._direct_search(query, k, **kwargs)
            elif strategy == "dense":
                return self._dense_search(query, k, **kwargs)
            elif strategy == "sparse":
                return self._sparse_search(query, k, **kwargs)
            else:  # hybrid (default)
                return self._hybrid_search(query, k, **kwargs)
                
        except Exception as e:
            logger.error(f"Hybrid search failed: {e}")
            return []
    
    def _hybrid_search(
        self, 
        query: str, 
        k: int = 5,
        **kwargs
    ) -> List[CWEResult]:
        """
        Perform hybrid search with score fusion.
        
        Args:
            query: Search query
            k: Number of results to return
            **kwargs: Additional parameters (keyphrases, boost_factors, etc.)
            
        Returns:
            Fused and ranked results from both methods
        """
        # Get boost factors if provided
        boost_factors = kwargs.get('boost_factors', {"dense": 1.0, "sparse": 1.0})
        keyphrases = kwargs.get('keyphrases', {})
        
        # Perform parallel retrieval
        dense_results = []
        sparse_results = []
        
        try:
            # Use ThreadPoolExecutor for parallel retrieval
            with ThreadPoolExecutor(max_workers=2) as executor:
                # Submit both searches
                future_dense = executor.submit(
                    self.dense_retriever.search, 
                    query, 
                    k * 2  # Get more results for fusion
                )
                future_sparse = executor.submit(
                    self.sparse_retriever.search_with_keyphrases,
                    query,
                    keyphrases,
                    k * 2
                )
                
                # Collect results
                for future in as_completed([future_dense, future_sparse]):
                    if future == future_dense:
                        dense_results = future.result() or []
                    else:
                        sparse_results = future.result() or []
            
        except Exception as e:
            logger.error(f"Parallel retrieval failed: {e}")
            # Fallback to sequential retrieval
            dense_results = self.dense_retriever.search(query, k) or []
            sparse_results = self.sparse_retriever.search(query, k) or []
        
        # Apply boost factors
        self._apply_boost_factors(dense_results, boost_factors.get('dense', 1.0))
        self._apply_boost_factors(sparse_results, boost_factors.get('sparse', 1.0))
        
        # Fuse results
        fused_results = self._fuse_scores(dense_results, sparse_results)
        
        # Return top-k results
        return fused_results[:k]
    
    def _dense_search(self, query: str, k: int = 5, **kwargs) -> List[CWEResult]:
        """Perform dense-only search."""
        return self.dense_retriever.search(query, k, **kwargs)
    
    def _sparse_search(self, query: str, k: int = 5, **kwargs) -> List[CWEResult]:
        """Perform sparse-only search."""
        keyphrases = kwargs.get('keyphrases', {})
        return self.sparse_retriever.search_with_keyphrases(query, keyphrases, k)
    
    def _direct_search(self, query: str, k: int = 5, **kwargs) -> List[CWEResult]:
        """Perform direct CWE ID lookup."""
        cwe_ids = kwargs.get('cwe_ids', set())
        
        results = []
        for cwe_id in cwe_ids:
            result = self.dense_retriever.get_by_id(cwe_id)
            if result:
                results.append(result)
        
        return results[:k]
    
    def _fuse_scores(
        self, 
        dense_results: List[CWEResult], 
        sparse_results: List[CWEResult]
    ) -> List[CWEResult]:
        """
        Fuse scores from multiple retrievers using configurable weights.
        
        Args:
            dense_results: Results from dense retrieval
            sparse_results: Results from sparse retrieval
            
        Returns:
            Fused and ranked results
        """
        # Normalize scores to [0,1] range
        dense_normalized = self._normalize_scores(dense_results)
        sparse_normalized = self._normalize_scores(sparse_results)
        
        # Create combined result map
        result_map = {}
        
        # Add dense results
        for result in dense_normalized:
            cwe_id = result.cwe_id
            weighted_score = result.confidence_score * self.weights["dense"]
            
            result_map[cwe_id] = {
                'result': result,
                'dense_score': result.confidence_score,
                'sparse_score': 0.0,
                'fused_score': weighted_score,
                'methods': ['dense']
            }
        
        # Add/combine sparse results
        for result in sparse_normalized:
            cwe_id = result.cwe_id
            weighted_score = result.confidence_score * self.weights["sparse"]
            
            if cwe_id in result_map:
                # Combine with existing dense result
                existing = result_map[cwe_id]
                existing['sparse_score'] = result.confidence_score
                existing['fused_score'] += weighted_score
                existing['methods'].append('sparse')
                
                # Update result with combined metadata
                existing['result'].source_method = "hybrid"
                existing['result'].confidence_score = existing['fused_score']
                
            else:
                # Add new sparse-only result
                result_map[cwe_id] = {
                    'result': result,
                    'dense_score': 0.0,
                    'sparse_score': result.confidence_score,
                    'fused_score': weighted_score,
                    'methods': ['sparse']
                }
                result.source_method = "sparse"
                result.confidence_score = weighted_score
        
        # Sort by fused score and return results
        sorted_items = sorted(
            result_map.values(),
            key=lambda x: x['fused_score'],
            reverse=True
        )
        
        fused_results = [item['result'] for item in sorted_items]
        
        logger.debug(f"Fused {len(dense_results)} dense + {len(sparse_results)} sparse -> {len(fused_results)} results")
        return fused_results
    
    def _normalize_scores(self, results: List[CWEResult]) -> List[CWEResult]:
        """
        Normalize confidence scores to [0,1] range using min-max scaling.
        
        Args:
            results: Results to normalize
            
        Returns:
            Results with normalized scores
        """
        if not results:
            return results
        
        scores = [r.confidence_score for r in results]
        min_score = min(scores)
        max_score = max(scores)
        
        # Avoid division by zero
        if max_score == min_score:
            for result in results:
                result.confidence_score = 1.0
        else:
            score_range = max_score - min_score
            for result in results:
                normalized = (result.confidence_score - min_score) / score_range
                result.confidence_score = normalized
        
        return results
    
    def _apply_boost_factors(self, results: List[CWEResult], boost_factor: float) -> None:
        """
        Apply boost factor to result scores in-place.
        
        Args:
            results: Results to boost
            boost_factor: Multiplicative boost factor
        """
        for result in results:
            result.confidence_score *= boost_factor
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get metadata for the hybrid system."""
        dense_meta = self.dense_retriever.get_metadata()
        sparse_meta = self.sparse_retriever.get_metadata()
        
        return {
            "manager_type": "hybrid",
            "weights": self.weights,
            "config": self.config,
            "retrievers": {
                "dense": dense_meta,
                "sparse": sparse_meta
            },
            "embedding_model": self.embedding_service.get_model_info()
        }