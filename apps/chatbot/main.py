#!/usr/bin/env python3
"""
CWE ChatBot - Hybrid RAG Application
Advanced Chainlit application with NLU, security sanitization, and hybrid retrieval.
"""

import asyncio
import logging
import sys
import os
import subprocess
from pathlib import Path

import chainlit as cl

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.config import config
from src.retrieval.hybrid_rag_manager import HybridRAGManager
from src.processing.query_processor import QueryProcessor
from src.processing.embedding_service import EmbeddingService
from src.formatting.response_formatter import ResponseFormatter


# Configure logging
logging.basicConfig(
    level=getattr(logging, config.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global components (initialized on startup)
query_processor = None
hybrid_rag_manager = None
response_formatter = None


def initialize_components():
    """Initialize all chatbot components with error handling."""
    global query_processor, hybrid_rag_manager, response_formatter
    
    try:
        # Validate configuration
        config.validate_config()
        logger.info("Configuration validated successfully")
        
        # Initialize query processor with security settings
        query_processor = QueryProcessor(
            max_input_length=config.max_input_length,
            strict_mode=config.enable_strict_sanitization
        )
        
        # Initialize embedding service
        embedding_service = EmbeddingService(
            api_key=config.openai_api_key,
            model=config.embedding_model,
            dimensions=config.embedding_dimensions
        )
        
        # Initialize hybrid RAG manager
        hybrid_rag_manager = HybridRAGManager(
            pg_config=config.get_pg_config(),
            embedding_service=embedding_service,
            weights=config.get_hybrid_weights()
        )
        
        # Initialize response formatter
        response_formatter = ResponseFormatter(
            max_results_display=config.max_retrieval_results,
            show_confidence_scores=True,
            show_source_methods=config.enable_debug_logging
        )
        
        logger.info("All components initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Component initialization failed: {e}")
        return False


@cl.on_chat_start
async def start():
    """Initialize the chat session with a welcome message."""
    welcome_message = """Hello! Welcome to the CWE ChatBot! 🛡️

I'm here to help you with Common Weakness Enumeration (CWE) information. You can:

• Ask about specific CWEs (e.g., "Tell me about CWE-79")
• Search for vulnerabilities by type (e.g., "SQL injection vulnerabilities") 
• Get prevention guidance (e.g., "How to prevent buffer overflows")
• Learn about security concepts and best practices

What would you like to know about cybersecurity weaknesses?"""
    
    await cl.Message(content=welcome_message).send()


@cl.on_message
async def main(message: cl.Message):
    """Handle incoming messages with full NLU and retrieval pipeline."""
    
    # Check if components are initialized
    if not all([query_processor, hybrid_rag_manager, response_formatter]):
        error_msg = response_formatter.get_fallback_response("system_error") if response_formatter else "System is initializing. Please try again in a moment."
        await cl.Message(content=error_msg).send()
        return
    
    try:
        user_query = message.content.strip()
        logger.info(f"Processing user query of length {len(user_query)}")
        
        # Step 1: Query preprocessing with security validation
        try:
            processed_query = query_processor.preprocess_query(user_query)
            logger.debug(f"Query type: {processed_query['query_type']}")
        except (ValueError, TypeError) as e:
            # Security validation failed
            logger.warning(f"Query rejected by security validation: {e}")
            error_response = response_formatter.get_fallback_response("invalid_query")
            await cl.Message(content=error_response).send()
            return
        
        # Step 2: Determine search strategy
        search_strategy = processed_query.get('search_strategy', 'hybrid_search')
        
        # Step 3: Perform retrieval based on strategy
        if search_strategy == "direct_lookup":
            # Direct CWE ID lookup
            results = hybrid_rag_manager.search(
                processed_query['sanitized_query'],
                k=config.max_retrieval_results,
                strategy="direct",
                cwe_ids=processed_query['cwe_ids']
            )
        else:
            # Hybrid, dense, or sparse search
            search_method = "hybrid" if search_strategy == "hybrid_search" else search_strategy.replace("_search", "")
            results = hybrid_rag_manager.search(
                processed_query['sanitized_query'],
                k=config.max_retrieval_results,
                strategy=search_method,
                keyphrases=processed_query['keyphrases'],
                boost_factors=processed_query['boost_factors']
            )
        
        # Step 4: Format response
        if processed_query['query_type'] == 'direct_cwe_lookup' and len(results) == 1:
            response = response_formatter.format_direct_cwe_result(results[0])
        else:
            response = response_formatter.format_search_summary(results, processed_query)
        
        # Step 5: Send response to user
        await cl.Message(content=response).send()
        
        logger.info(f"Successfully processed query, returned {len(results)} results")
        
    except Exception as e:
        # Secure error handling - never expose internal details
        logger.error(f"Error processing query: {e}", exc_info=True)
        error_response = response_formatter.get_fallback_response("system_error")
        await cl.Message(content=error_response).send()


def main_cli():
    """CLI entry point for running the application."""
    # Initialize components on startup
    if not initialize_components():
        logger.error("Failed to initialize components. Exiting.")
        sys.exit(1)
    
    logger.info("CWE ChatBot is ready to serve requests")


if __name__ == "__main__":
    # This allows running the app directly with: python main.py
    main_cli()
    
    # SECURITY FIX: Replace os.system() with secure subprocess.run()
    # This prevents shell command injection vulnerabilities
    try:
        subprocess.run([
            "python", "-m", "chainlit", "run", "main.py",
            "--host", "0.0.0.0", "--port", "8080"
        ], check=True, cwd=Path(__file__).parent)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to start Chainlit server: {e}")
        sys.exit(1)
    except FileNotFoundError:
        logger.error("Chainlit not found. Please install with: pip install chainlit")
        sys.exit(1)