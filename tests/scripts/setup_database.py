#!/usr/bin/env python3
"""
PostgreSQL + pgvector Database Setup Script for CWE ChatBot Real Integration Testing

This script sets up a test database with:
- PostgreSQL with pgvector extension
- CWE test data with real OpenAI embeddings
- Proper schema and indexes for integration testing

Usage:
    python setup_database.py --help
    python setup_database.py --docker    # Use Docker setup
    python setup_database.py --local     # Use local PostgreSQL
    python setup_database.py --cloud     # Use Cloud SQL connection
"""

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "apps" / "chatbot" / "src"))

# Load environment
try:
    from config.env_loader import load_env_auto

    load_env_auto()
except ImportError:
    print("Warning: Could not load environment configuration")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class DatabaseSetup:
    """Handle PostgreSQL + pgvector setup for various deployment options."""

    def __init__(self, setup_type: str, **kwargs):
        self.setup_type = setup_type
        self.config = {
            "host": kwargs.get("host", "localhost"),
            "port": kwargs.get("port", 5432),
            "database": kwargs.get("database", "cwe_chatbot_test"),
            "user": kwargs.get("user", "postgres"),
            "password": kwargs.get("password", os.getenv("POSTGRES_PASSWORD")),
        }
        self.connection = None

        if not self.config["password"]:
            raise ValueError("POSTGRES_PASSWORD environment variable required")

    def setup_docker_database(self) -> bool:
        """Set up PostgreSQL + pgvector using Docker."""
        logger.info("🐳 Setting up PostgreSQL + pgvector with Docker...")

        try:
            # Check if Docker is available
            result = subprocess.run(
                ["docker", "--version"], capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.error("Docker not available or not accessible")
                return False

            logger.info(f"✅ Docker available: {result.stdout.strip()}")

            # Pull pgvector image
            logger.info("📥 Pulling pgvector/pgvector:pg16 image...")
            pull_result = subprocess.run(
                ["docker", "pull", "pgvector/pgvector:pg16"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if pull_result.returncode != 0:
                logger.error(f"Failed to pull Docker image: {pull_result.stderr}")
                return False

            # Stop existing container if running
            subprocess.run(
                ["docker", "stop", "cwe-chatbot-postgres-test"], capture_output=True
            )
            subprocess.run(
                ["docker", "rm", "cwe-chatbot-postgres-test"], capture_output=True
            )

            # Start PostgreSQL container
            logger.info("🚀 Starting PostgreSQL + pgvector container...")
            run_result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--name",
                    "cwe-chatbot-postgres-test",
                    "-e",
                    f"POSTGRES_DB={self.config['database']}",
                    "-e",
                    f"POSTGRES_USER={self.config['user']}",
                    "-e",
                    f"POSTGRES_PASSWORD={self.config['password']}",
                    "-p",
                    f"{self.config['port']}:5432",
                    "-d",
                    "pgvector/pgvector:pg16",
                ],
                capture_output=True,
                text=True,
            )

            if run_result.returncode != 0:
                logger.error(f"Failed to start container: {run_result.stderr}")
                return False

            logger.info("✅ PostgreSQL container started successfully")

            # Wait for database to be ready
            import time

            logger.info("⏳ Waiting for database to be ready...")
            for i in range(30):  # Wait up to 30 seconds
                try:
                    test_result = subprocess.run(
                        [
                            "docker",
                            "exec",
                            "cwe-chatbot-postgres-test",
                            "pg_isready",
                            "-U",
                            self.config["user"],
                            "-d",
                            self.config["database"],
                        ],
                        capture_output=True,
                        timeout=5,
                    )

                    if test_result.returncode == 0:
                        logger.info("✅ Database is ready")
                        break
                except subprocess.TimeoutExpired:
                    pass

                time.sleep(1)
                logger.info(f"⏳ Still waiting... ({i+1}/30)")
            else:
                logger.error("❌ Database failed to become ready")
                return False

            return True

        except subprocess.TimeoutExpired:
            logger.error("❌ Docker operations timed out")
            return False
        except Exception as e:
            logger.error(f"❌ Docker setup failed: {e}")
            return False

    def setup_local_database(self) -> bool:
        """Set up local PostgreSQL (assumes PostgreSQL is installed)."""
        logger.info("💻 Setting up local PostgreSQL database...")

        try:
            # Check if PostgreSQL is available
            result = subprocess.run(
                ["psql", "--version"], capture_output=True, text=True
            )
            if result.returncode != 0:
                logger.error("PostgreSQL not installed locally")
                return False

            logger.info(f"✅ PostgreSQL available: {result.stdout.strip()}")

            # Create database (may fail if it exists - that's ok)
            subprocess.run(
                [
                    "createdb",
                    "-h",
                    self.config["host"],
                    "-p",
                    str(self.config["port"]),
                    "-U",
                    self.config["user"],
                    self.config["database"],
                ],
                capture_output=True,
                env={"PGPASSWORD": self.config["password"]},
            )

            logger.info("✅ Database created or already exists")
            return True

        except Exception as e:
            logger.error(f"❌ Local setup failed: {e}")
            return False

    def connect_database(self) -> bool:
        """Connect to the PostgreSQL database."""
        try:
            import psycopg2
            from pgvector.psycopg2 import register_vector

            logger.info(
                f"🔗 Connecting to database at {self.config['host']}:{self.config['port']}..."
            )

            self.connection = psycopg2.connect(
                host=self.config["host"],
                port=self.config["port"],
                database=self.config["database"],
                user=self.config["user"],
                password=self.config["password"],
            )

            # Create pgvector extension first
            with self.connection.cursor() as cursor:
                cursor.execute("CREATE EXTENSION IF NOT EXISTS vector;")
                self.connection.commit()

            # Register pgvector
            register_vector(self.connection)

            logger.info("✅ Connected to database successfully")
            return True

        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            return False

    def create_schema(self) -> bool:
        """Create database schema with pgvector extension."""
        if not self.connection:
            logger.error("No database connection")
            return False

        try:
            with self.connection.cursor() as cursor:
                logger.info("🔧 Creating database schema...")

                # Enable pgvector extension
                cursor.execute("CREATE EXTENSION IF NOT EXISTS vector;")
                logger.info("✅ pgvector extension enabled")

                # Create CWE embeddings table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cwe_embeddings (
                        id SERIAL PRIMARY KEY,
                        cwe_id VARCHAR(20) NOT NULL UNIQUE,
                        name TEXT NOT NULL,
                        abstraction VARCHAR(50),
                        status VARCHAR(50),
                        description TEXT,
                        extended_description TEXT,
                        full_text TEXT NOT NULL,
                        embedding vector(1536),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """
                )
                logger.info("✅ CWE embeddings table created")

                # Create indexes
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_cwe_id ON cwe_embeddings(cwe_id);
                """
                )
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_embedding_cosine 
                    ON cwe_embeddings USING ivfflat (embedding vector_cosine_ops) 
                    WITH (lists = 100);
                """
                )
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_full_text_gin 
                    ON cwe_embeddings USING gin(to_tsvector('english', full_text));
                """
                )
                logger.info("✅ Database indexes created")

                # Create supporting tables
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        user_id VARCHAR(255) NOT NULL UNIQUE,
                        email VARCHAR(255),
                        role VARCHAR(50) DEFAULT 'user',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """
                )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS conversations (
                        id SERIAL PRIMARY KEY,
                        user_id VARCHAR(255) NOT NULL,
                        session_id VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """
                )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS messages (
                        id SERIAL PRIMARY KEY,
                        conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
                        message_type VARCHAR(20) NOT NULL CHECK (message_type IN ('user', 'assistant')),
                        content TEXT NOT NULL,
                        metadata JSONB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """
                )
                logger.info("✅ Supporting tables created")

            self.connection.commit()
            return True

        except Exception as e:
            logger.error(f"❌ Schema creation failed: {e}")
            self.connection.rollback()
            return False

    def load_test_data(self) -> bool:
        """Load CWE test data with real OpenAI embeddings."""
        if not self.connection:
            logger.error("No database connection")
            return False

        try:
            # Check if we have OpenAI API key for real embeddings
            openai_key = os.getenv("OPENAI_API_KEY")
            if not openai_key:
                logger.warning("No OPENAI_API_KEY - loading without embeddings")
                return self._load_test_data_no_embeddings()

            logger.info("🤖 Loading test data with real OpenAI embeddings...")

            # Import embedding service
            try:
                from processing.embedding_service import EmbeddingService

                embedding_service = EmbeddingService(api_key=openai_key)
            except ImportError:
                logger.warning(
                    "Could not import EmbeddingService - loading without embeddings"
                )
                return self._load_test_data_no_embeddings()

            # Test CWE data
            test_cwes = [
                {
                    "cwe_id": "CWE-79",
                    "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                    "abstraction": "Base",
                    "status": "Stable",
                    "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
                    "extended_description": "Cross-site scripting (XSS) vulnerabilities occur when an application includes untrusted data in a web page without proper validation or escaping.",
                    "full_text": "CWE-79 Cross-site Scripting XSS web application security input validation output encoding HTML JavaScript injection attack vector user-controllable data",
                },
                {
                    "cwe_id": "CWE-89",
                    "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                    "abstraction": "Base",
                    "status": "Stable",
                    "description": "The software constructs all or part of an SQL command using externally-influenced input from an upstream component.",
                    "extended_description": "SQL injection attacks involve inserting or injecting malicious SQL queries into application input fields.",
                    "full_text": "CWE-89 SQL injection database query parameter validation prepared statements input sanitization code injection attack",
                },
                {
                    "cwe_id": "CWE-120",
                    "name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
                    "abstraction": "Base",
                    "status": "Stable",
                    "description": "The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.",
                    "extended_description": "Buffer overflow vulnerabilities are among the most common and dangerous security issues in software applications.",
                    "full_text": "CWE-120 buffer overflow memory corruption bounds checking input validation C C++ memory safety stack heap",
                },
                {
                    "cwe_id": "CWE-20",
                    "name": "Improper Input Validation",
                    "abstraction": "Class",
                    "status": "Stable",
                    "description": "The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program.",
                    "extended_description": "Input validation is a critical security control that prevents many types of attacks.",
                    "full_text": "CWE-20 input validation sanitization filtering whitelist blacklist data validation security control",
                },
                {
                    "cwe_id": "CWE-787",
                    "name": "Out-of-bounds Write",
                    "abstraction": "Base",
                    "status": "Stable",
                    "description": "The software writes data past the end, or before the beginning, of the intended buffer.",
                    "extended_description": "Out-of-bounds write vulnerabilities can lead to memory corruption and potential code execution.",
                    "full_text": "CWE-787 out-of-bounds write memory corruption buffer overflow array bounds checking memory safety",
                },
            ]

            with self.connection.cursor() as cursor:
                for cwe in test_cwes:
                    logger.info(f"📝 Processing {cwe['cwe_id']}...")

                    # Generate real embedding
                    embedding = embedding_service.embed_query(cwe["full_text"])

                    # Insert or update CWE data
                    cursor.execute(
                        """
                        INSERT INTO cwe_embeddings 
                        (cwe_id, name, abstraction, status, description, extended_description, full_text, embedding)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (cwe_id) DO UPDATE SET
                            name = EXCLUDED.name,
                            abstraction = EXCLUDED.abstraction,
                            status = EXCLUDED.status,
                            description = EXCLUDED.description,
                            extended_description = EXCLUDED.extended_description,
                            full_text = EXCLUDED.full_text,
                            embedding = EXCLUDED.embedding,
                            updated_at = CURRENT_TIMESTAMP;
                    """,
                        (
                            cwe["cwe_id"],
                            cwe["name"],
                            cwe["abstraction"],
                            cwe["status"],
                            cwe["description"],
                            cwe["extended_description"],
                            cwe["full_text"],
                            embedding,
                        ),
                    )

                    logger.info(f"✅ {cwe['cwe_id']} loaded with real embedding")

            self.connection.commit()

            # Verify data
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM cwe_embeddings;")
                count = cursor.fetchone()[0]
                logger.info(f"✅ {count} CWE records loaded with real embeddings")

            return True

        except Exception as e:
            logger.error(f"❌ Test data loading failed: {e}")
            self.connection.rollback()
            return False

    def _load_test_data_no_embeddings(self) -> bool:
        """Load test data without embeddings (for testing schema only)."""
        logger.info("📝 Loading test data without embeddings...")

        try:
            test_cwes = [
                (
                    "CWE-79",
                    "Cross-site Scripting",
                    "Base",
                    "Stable",
                    "XSS vulnerability description",
                    "Cross-site scripting vulnerability details",
                    "CWE-79 XSS cross-site scripting web security",
                ),
                (
                    "CWE-89",
                    "SQL Injection",
                    "Base",
                    "Stable",
                    "SQL injection vulnerability description",
                    "SQL injection attack details",
                    "CWE-89 SQL injection database security",
                ),
                (
                    "CWE-120",
                    "Buffer Overflow",
                    "Base",
                    "Stable",
                    "Buffer overflow vulnerability description",
                    "Buffer overflow memory corruption details",
                    "CWE-120 buffer overflow memory corruption",
                ),
            ]

            with self.connection.cursor() as cursor:
                for cwe_data in test_cwes:
                    cursor.execute(
                        """
                        INSERT INTO cwe_embeddings 
                        (cwe_id, name, abstraction, status, description, extended_description, full_text)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (cwe_id) DO NOTHING;
                    """,
                        cwe_data,
                    )

            self.connection.commit()
            logger.info("✅ Test data loaded without embeddings")
            return True

        except Exception as e:
            logger.error(f"❌ Test data loading failed: {e}")
            self.connection.rollback()
            return False

    def verify_setup(self) -> bool:
        """Verify the database setup is working correctly."""
        if not self.connection:
            logger.error("No database connection")
            return False

        try:
            with self.connection.cursor() as cursor:
                logger.info("🔍 Verifying database setup...")

                # Check pgvector extension
                cursor.execute(
                    "SELECT extname FROM pg_extension WHERE extname = 'vector';"
                )
                if not cursor.fetchone():
                    logger.error("❌ pgvector extension not installed")
                    return False
                logger.info("✅ pgvector extension verified")

                # Check table exists
                cursor.execute(
                    """
                    SELECT table_name FROM information_schema.tables 
                    WHERE table_schema = 'public' AND table_name = 'cwe_embeddings';
                """
                )
                if not cursor.fetchone():
                    logger.error("❌ cwe_embeddings table not found")
                    return False
                logger.info("✅ cwe_embeddings table verified")

                # Check data
                cursor.execute("SELECT COUNT(*) FROM cwe_embeddings;")
                count = cursor.fetchone()[0]
                if count == 0:
                    logger.warning("⚠️ No CWE data found in database")
                    return False
                logger.info(f"✅ {count} CWE records found")

                # Test vector operations if embeddings exist
                cursor.execute(
                    "SELECT COUNT(*) FROM cwe_embeddings WHERE embedding IS NOT NULL;"
                )
                embedding_count = cursor.fetchone()[0]
                if embedding_count > 0:
                    logger.info(f"✅ {embedding_count} records have embeddings")

                    # Test similarity search
                    cursor.execute(
                        """
                        SELECT cwe_id, name FROM cwe_embeddings 
                        WHERE embedding IS NOT NULL 
                        LIMIT 1;
                    """
                    )
                    test_record = cursor.fetchone()
                    if test_record:
                        logger.info("✅ Database ready for vector similarity testing")
                else:
                    logger.info("ℹ️ Database ready (no embeddings for vector testing)")

            return True

        except Exception as e:
            logger.error(f"❌ Verification failed: {e}")
            return False

    def cleanup(self):
        """Clean up database connection."""
        if self.connection:
            self.connection.close()
            logger.info("🔒 Database connection closed")


def main():
    parser = argparse.ArgumentParser(
        description="Set up PostgreSQL + pgvector database for CWE ChatBot"
    )
    parser.add_argument("--docker", action="store_true", help="Use Docker setup")
    parser.add_argument("--local", action="store_true", help="Use local PostgreSQL")
    parser.add_argument(
        "--cloud", action="store_true", help="Use cloud database (connection only)"
    )
    parser.add_argument("--host", default="localhost", help="Database host")
    parser.add_argument("--port", type=int, default=5432, help="Database port")
    parser.add_argument("--database", default="cwe_chatbot_test", help="Database name")
    parser.add_argument("--user", default="postgres", help="Database user")
    parser.add_argument(
        "--skip-data", action="store_true", help="Skip loading test data"
    )

    args = parser.parse_args()

    if not any([args.docker, args.local, args.cloud]):
        parser.error("Must specify one of --docker, --local, or --cloud")

    try:
        # Determine setup type
        if args.docker:
            setup_type = "docker"
            port = 5433  # Use different port for Docker
        elif args.local:
            setup_type = "local"
            port = args.port
        else:  # cloud
            setup_type = "cloud"
            port = args.port

        # Initialize database setup
        db_setup = DatabaseSetup(
            setup_type=setup_type,
            host=args.host,
            port=port,
            database=args.database,
            user=args.user,
        )

        success = True

        # Set up database infrastructure
        if setup_type == "docker":
            success = db_setup.setup_docker_database()
        elif setup_type == "local":
            success = db_setup.setup_local_database()
        # For cloud, assume database already exists

        if not success:
            logger.error("❌ Database infrastructure setup failed")
            return 1

        # Connect to database
        if not db_setup.connect_database():
            logger.error("❌ Database connection failed")
            return 1

        # Create schema
        if not db_setup.create_schema():
            logger.error("❌ Schema creation failed")
            return 1

        # Load test data
        if not args.skip_data:
            if not db_setup.load_test_data():
                logger.error("❌ Test data loading failed")
                return 1

        # Verify setup
        if not db_setup.verify_setup():
            logger.error("❌ Setup verification failed")
            return 1

        logger.info("🎉 Database setup completed successfully!")
        logger.info("📊 Connection details:")
        logger.info(f"   Host: {db_setup.config['host']}")
        logger.info(f"   Port: {db_setup.config['port']}")
        logger.info(f"   Database: {db_setup.config['database']}")
        logger.info(f"   User: {db_setup.config['user']}")

        logger.info("🚀 Ready to run real integration tests:")
        logger.info(
            "   poetry run pytest apps/chatbot/tests/test_real_integration.py -v"
        )

        return 0

    except KeyboardInterrupt:
        logger.info("❌ Setup interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"❌ Setup failed: {e}")
        return 1
    finally:
        if "db_setup" in locals():
            db_setup.cleanup()


if __name__ == "__main__":
    sys.exit(main())
