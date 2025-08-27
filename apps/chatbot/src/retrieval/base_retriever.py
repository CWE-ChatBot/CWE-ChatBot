"""
Base retriever interface for ChatBot retrieval implementations.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class CWEResult:
    """Data class for CWE retrieval results."""
    cwe_id: str
    name: str
    description: str
    confidence_score: float
    source_method: str  # 'dense', 'sparse', or 'hybrid'
    metadata: Optional[Dict[str, Any]] = None
    # Enhanced fields for Story 2.2
    extended_description: Optional[str] = None
    abstraction: Optional[str] = None
    status: Optional[str] = None
    relationships: Optional[Dict[str, List[str]]] = None  # e.g., {"ChildOf": ["CWE-20"], "ParentOf": ["CWE-80"]}
    consequences: Optional[List[Dict[str, str]]] = None


class ChatBotBaseRetriever(ABC):
    """Base interface for ChatBot retriever implementations."""
    
    @abstractmethod
    def search(self, query: str, k: int = 5, **kwargs) -> List[CWEResult]:
        """
        Search for relevant CWE entries.
        
        Args:
            query: Search query string
            k: Number of results to return
            **kwargs: Additional search parameters
            
        Returns:
            List of CWEResult objects ranked by relevance
        """
        pass
    
    @abstractmethod
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get retriever metadata for evaluation.
        
        Returns:
            Dictionary containing retriever configuration and stats
        """
        pass
    
    def get_by_id(self, cwe_id: str) -> Optional[CWEResult]:
        """
        Get specific CWE by ID for direct lookups.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-79")
            
        Returns:
            CWEResult if found, None otherwise
        """
        # Default implementation using search
        results = self.search(f"id:{cwe_id}", k=1)
        return results[0] if results else None