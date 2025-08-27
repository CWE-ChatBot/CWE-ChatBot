"""
Secure SQL query builder for CWE ChatBot retrieval operations.
Prevents SQL injection attacks by using proper parameterized queries and table name validation.
"""

from typing import Set, Dict, Any
from psycopg2 import sql
import logging

logger = logging.getLogger(__name__)


class SecureQueryBuilder:
    """
    Secure SQL query builder that prevents SQL injection attacks.
    
    Uses psycopg2.sql.Identifier() for table names and proper parameterization
    for all user data to prevent SQL injection vulnerabilities.
    """
    
    # Whitelist of allowed table names to prevent table name injection
    ALLOWED_TABLES: Set[str] = {
        "cwe_embeddings",
        "users", 
        "conversations",
        "messages"
    }
    
    def __init__(self):
        """Initialize the secure query builder."""
        pass
    
    def validate_table_name(self, table_name: str) -> str:
        """
        Validate that table name is in the allowed whitelist.
        
        Args:
            table_name: The table name to validate
            
        Returns:
            The validated table name
            
        Raises:
            ValueError: If table name is not in the allowed list
        """
        if table_name not in self.ALLOWED_TABLES:
            logger.warning(f"Attempted access to non-allowed table: {table_name}")
            raise ValueError(f"Table name not allowed: {table_name}. Allowed tables: {sorted(self.ALLOWED_TABLES)}")
        
        return table_name
    
    def build_vector_similarity_query(self, table_name: str) -> sql.Composable:
        """
        Build a secure vector similarity search query.
        
        Args:
            table_name: Name of the table to search (must be in whitelist)
            
        Returns:
            psycopg2.sql.Composable query object
            
        Raises:
            ValueError: If table name is not allowed
        """
        validated_table = self.validate_table_name(table_name)
        
        return sql.SQL("""
            SELECT 
                cwe_id,
                name,
                description,
                1 - (embedding <=> %s) as similarity_score,
                metadata
            FROM {}
            WHERE 1 - (embedding <=> %s) > %s
            ORDER BY embedding <=> %s
            LIMIT %s;
        """).format(sql.Identifier(validated_table))
    
    def build_direct_cwe_lookup_query(self, table_name: str) -> sql.Composable:
        """
        Build a secure direct CWE ID lookup query.
        
        Args:
            table_name: Name of the table to search (must be in whitelist)
            
        Returns:
            psycopg2.sql.Composable query object
            
        Raises:
            ValueError: If table name is not allowed
        """
        validated_table = self.validate_table_name(table_name)
        
        return sql.SQL("""
            SELECT 
                cwe_id,
                name,
                description,
                1.0 as confidence_score,
                metadata
            FROM {}
            WHERE cwe_id = %s;
        """).format(sql.Identifier(validated_table))
    
    def build_fulltext_search_query(self, table_name: str) -> sql.Composable:
        """
        Build a secure full-text search query using PostgreSQL's built-in search.
        
        Args:
            table_name: Name of the table to search (must be in whitelist)
            
        Returns:
            psycopg2.sql.Composable query object
            
        Raises:
            ValueError: If table name is not allowed
        """
        validated_table = self.validate_table_name(table_name)
        
        return sql.SQL("""
            SELECT 
                cwe_id,
                name,
                description,
                ts_rank(to_tsvector('english', full_text), plainto_tsquery('english', %s)) as relevance_score,
                metadata
            FROM {}
            WHERE to_tsvector('english', full_text) @@ plainto_tsquery('english', %s)
            ORDER BY relevance_score DESC
            LIMIT %s;
        """).format(sql.Identifier(validated_table))
    
    def build_count_query(self, table_name: str) -> sql.Composable:
        """
        Build a secure count query.
        
        Args:
            table_name: Name of the table to count (must be in whitelist)
            
        Returns:
            psycopg2.sql.Composable query object
            
        Raises:
            ValueError: If table name is not allowed
        """
        validated_table = self.validate_table_name(table_name)
        
        return sql.SQL("SELECT COUNT(*) FROM {};").format(sql.Identifier(validated_table))
    
    def build_extension_check_query(self) -> sql.Composable:
        """
        Build a query to check for pgvector extension.
        
        Returns:
            psycopg2.sql.Composable query object
        """
        return sql.SQL("SELECT extname FROM pg_extension WHERE extname = %s;")
    
    def build_table_exists_query(self, table_name: str) -> sql.Composable:
        """
        Build a secure query to check if table exists.
        
        Args:
            table_name: Name of the table to check (must be in whitelist)
            
        Returns:
            psycopg2.sql.Composable query object
            
        Raises:
            ValueError: If table name is not allowed
        """
        validated_table = self.validate_table_name(table_name)
        
        return sql.SQL("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name = %s;
        """)
    
    def build_load_cwe_entries_query(self, table_name: str) -> sql.Composable:
        """
        Build a secure query to load CWE entries for sparse retrieval.
        
        Args:
            table_name: Name of the table to load from (must be in whitelist)
            
        Returns:
            psycopg2.sql.Composable query object
            
        Raises:
            ValueError: If table name is not allowed
        """
        validated_table = self.validate_table_name(table_name)
        
        return sql.SQL("""
            SELECT cwe_id, name, description, full_text, metadata
            FROM {}
            ORDER BY cwe_id;
        """).format(sql.Identifier(validated_table))
    
    @classmethod
    def add_allowed_table(cls, table_name: str) -> None:
        """
        Add a table name to the allowed list (for testing or extensions).
        
        Args:
            table_name: Table name to add to whitelist
        """
        cls.ALLOWED_TABLES.add(table_name)
        logger.info(f"Added table to whitelist: {table_name}")
    
    @classmethod
    def remove_allowed_table(cls, table_name: str) -> None:
        """
        Remove a table name from the allowed list.
        
        Args:
            table_name: Table name to remove from whitelist
        """
        cls.ALLOWED_TABLES.discard(table_name)
        logger.info(f"Removed table from whitelist: {table_name}")


# Global instance for convenience
query_builder = SecureQueryBuilder()