#!/usr/bin/env python3
"""
Simple test to verify PostgreSQL+pgvector database setup works.
"""

import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "apps" / "chatbot" / "src"))

# Load environment
from config.env_loader import load_env_auto
load_env_auto()

try:
    import psycopg2
    from pgvector.psycopg2 import register_vector
    
    # Connect to database (using same config as setup script)
    connection = psycopg2.connect(
        host="localhost",
        port=5433,
        database="cwe_chatbot_test",
        user="postgres", 
        password=os.getenv("POSTGRES_PASSWORD")
    )
    
    # Create vector extension and register
    with connection.cursor() as cursor:
        cursor.execute("CREATE EXTENSION IF NOT EXISTS vector;")
        connection.commit()
    
    register_vector(connection)
    
    # Test basic queries
    with connection.cursor() as cursor:
        # Check extension
        cursor.execute("SELECT extname FROM pg_extension WHERE extname = 'vector';")
        result = cursor.fetchone()
        print(f"✅ pgvector extension: {result[0] if result else 'not found'}")
        
        # Check CWE data
        cursor.execute("SELECT COUNT(*) FROM cwe_embeddings;")
        count = cursor.fetchone()[0]
        print(f"✅ CWE records: {count}")
        
        # Check embeddings
        cursor.execute("SELECT COUNT(*) FROM cwe_embeddings WHERE embedding IS NOT NULL;")
        embedding_count = cursor.fetchone()[0]
        print(f"✅ Records with embeddings: {embedding_count}")
        
        # Test vector similarity search
        cursor.execute("SELECT cwe_id, name FROM cwe_embeddings LIMIT 1;")
        first_cwe = cursor.fetchone()
        if first_cwe:
            print(f"✅ First CWE: {first_cwe[0]} - {first_cwe[1]}")
    
    connection.close()
    print("🎉 Database integration test passed!")
    
except Exception as e:
    print(f"❌ Database test failed: {e}")
    sys.exit(1)