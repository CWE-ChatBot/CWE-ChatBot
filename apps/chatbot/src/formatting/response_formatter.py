"""
Response formatter for CWE retrieval results.
Formats results with confidence scores and secure fallback handling.
"""

import logging
from typing import List, Dict, Any, Optional

from ..retrieval.base_retriever import CWEResult


logger = logging.getLogger(__name__)


class ResponseFormatter:
    """
    Formats RAG results for user display with security-aware error handling.
    
    Provides consistent, user-friendly formatting of CWE information while
    ensuring no internal system details are exposed.
    """
    
    # Secure fallback messages (no internal system details)
    FALLBACK_MESSAGES = {
        "no_results": "I can only provide information about Common Weakness Enumerations (CWEs). Please ask about specific vulnerabilities or security concepts.",
        "invalid_query": "I'm sorry, I can't fulfill that request. I can only help with CWE information.",
        "system_error": "I'm experiencing technical difficulties. Please try again or ask about a specific CWE."
    }
    
    def __init__(
        self, 
        max_results_display: int = 5,
        show_confidence_scores: bool = True,
        show_source_methods: bool = False
    ):
        """
        Initialize the response formatter.
        
        Args:
            max_results_display: Maximum number of results to display
            show_confidence_scores: Whether to show confidence scores
            show_source_methods: Whether to show retrieval method used
        """
        self.max_results_display = max_results_display
        self.show_confidence_scores = show_confidence_scores
        self.show_source_methods = show_source_methods
        
        logger.info("Initialized ResponseFormatter with secure fallback handling")
    
    def format_cwe_results(self, results: List[CWEResult]) -> str:
        """
        Format CWE results for user display.
        
        Args:
            results: List of CWEResult objects to format
            
        Returns:
            Formatted string for display to user
        """
        if not results:
            return self.get_fallback_response("no_results")
        
        try:
            # Limit number of displayed results
            display_results = results[:self.max_results_display]
            
            if len(display_results) == 1:
                return self._format_single_result(display_results[0])
            else:
                return self._format_multiple_results(display_results)
                
        except Exception as e:
            logger.error(f"Error formatting results: {e}")
            return self.get_fallback_response("system_error")
    
    def _format_single_result(self, result: CWEResult) -> str:
        """
        Format a single CWE result.
        
        Args:
            result: CWEResult to format
            
        Returns:
            Formatted string for single result
        """
        # Main CWE information
        formatted = f"**{result.cwe_id}: {result.name}**\\n\\n"
        formatted += f"{result.description}\\n"
        
        # Add confidence score if enabled
        if self.show_confidence_scores and result.confidence_score < 1.0:
            confidence_pct = int(result.confidence_score * 100)
            formatted += f"\\n*Confidence: {confidence_pct}%*"
        
        # Add source method if enabled
        if self.show_source_methods and result.source_method != "direct":
            formatted += f"\\n*Retrieved via: {result.source_method} search*"
        
        return formatted
    
    def _format_multiple_results(self, results: List[CWEResult]) -> str:
        """
        Format multiple CWE results.
        
        Args:
            results: List of CWEResult objects to format
            
        Returns:
            Formatted string for multiple results
        """
        formatted = f"Found {len(results)} relevant CWE entries:\\n\\n"
        
        for i, result in enumerate(results, 1):
            formatted += f"**{i}. {result.cwe_id}: {result.name}**\\n"
            
            # Truncate long descriptions for multiple results
            description = result.description
            if len(description) > 200:
                description = description[:200] + "..."
            formatted += f"{description}\\n"
            
            # Add confidence for non-perfect matches
            if self.show_confidence_scores and result.confidence_score < 1.0:
                confidence_pct = int(result.confidence_score * 100)
                formatted += f"*Confidence: {confidence_pct}%*\\n"
            
            formatted += "\\n"
        
        return formatted.strip()
    
    def format_direct_cwe_result(self, result: CWEResult) -> str:
        """
        Format result for direct CWE ID queries with enhanced detail.
        
        Args:
            result: CWEResult from direct lookup
            
        Returns:
            Detailed formatted string for direct CWE query
        """
        if not result:
            return self.get_fallback_response("no_results")
        
        try:
            formatted = f"**{result.cwe_id}: {result.name}**\\n\\n"
            formatted += f"**Description:**\\n{result.description}\\n\\n"
            
            # Add metadata if available
            if result.metadata:
                metadata = result.metadata
                
                # Add weakness abstraction level if available
                if 'abstraction' in metadata:
                    formatted += f"**Abstraction Level:** {metadata['abstraction']}\\n"
                
                # Add structure if available  
                if 'structure' in metadata:
                    formatted += f"**Structure:** {metadata['structure']}\\n"
                
                # Add status if available
                if 'status' in metadata:
                    formatted += f"**Status:** {metadata['status']}\\n"
            
            return formatted
            
        except Exception as e:
            logger.error(f"Error formatting direct result: {e}")
            return self.get_fallback_response("system_error")
    
    def get_fallback_response(self, fallback_type: str = "invalid_query") -> str:
        """
        Get secure fallback response for error conditions.
        
        Args:
            fallback_type: Type of fallback response needed
            
        Returns:
            Secure fallback message that doesn't expose internal details
        """
        return self.FALLBACK_MESSAGES.get(fallback_type, self.FALLBACK_MESSAGES["invalid_query"])
    
    def format_search_summary(
        self, 
        results: List[CWEResult], 
        query_info: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Format search results with query context summary.
        
        Args:
            results: List of search results
            query_info: Optional query processing information
            
        Returns:
            Formatted results with search context
        """
        if not results:
            return self.get_fallback_response("no_results")
        
        try:
            # Add query context if available
            context_info = ""
            if query_info:
                query_type = query_info.get('query_type', 'unknown')
                if query_type == 'direct_cwe_lookup':
                    context_info = "Direct CWE lookup:\\n\\n"
                elif query_type == 'vulnerability_inquiry':
                    context_info = "Vulnerability information:\\n\\n"
                elif query_type == 'prevention_guidance':
                    context_info = "Prevention and mitigation guidance:\\n\\n"
            
            # Format main results
            main_results = self.format_cwe_results(results)
            
            return context_info + main_results
            
        except Exception as e:
            logger.error(f"Error formatting search summary: {e}")
            return self.get_fallback_response("system_error")
    
    def format_error_response(self, error_message: str = None) -> str:
        """
        Format secure error response that doesn't expose internal details.
        
        Args:
            error_message: Internal error message (for logging only)
            
        Returns:
            Secure user-facing error message
        """
        if error_message:
            logger.warning(f"Error response triggered: {error_message}")
        
        return self.get_fallback_response("system_error")