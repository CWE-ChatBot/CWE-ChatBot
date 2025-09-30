# src/db.py
"""
Cloud SQL Connector helper for production Cloud Run deployment.
Provides connection pooling and IAM authentication for PostgreSQL.
"""
import os
from google.cloud.sql.connector import Connector, IPTypes
import sqlalchemy as sa

INSTANCE = os.environ["INSTANCE_CONN_NAME"]  # e.g. cwechatbot:us-central1:cwe-postgres-prod
DB_NAME = os.environ.get("DB_NAME", "postgres")  # use 'cwe_prod' after migration
DB_USER = os.environ.get("DB_IAM_USER", "cwe-postgres-sa@cwechatbot.iam")

_connector = None
_engine = None


def _getconn():
    """Get a connection to Cloud SQL using the Cloud SQL Connector."""
    global _connector
    if _connector is None:
        _connector = Connector(ip_type=IPTypes.PRIVATE)  # Private IP path
    return _connector.connect(INSTANCE, "pg8000", user=DB_USER, db=DB_NAME, enable_iam_auth=True)


def engine():
    """Get a SQLAlchemy engine with connection pooling for Cloud SQL."""
    global _engine
    if _engine is None:
        _engine = sa.create_engine(
            "postgresql+pg8000://",
            creator=_getconn,
            pool_size=2,  # Conservative for Cloud Run scaling
            max_overflow=2,
            pool_pre_ping=True,
            pool_timeout=30,
        )
    return _engine


def close():
    """Close the connector and engine (for graceful shutdown)."""
    global _connector, _engine
    if _connector:
        _connector.close()
        _connector = None
    if _engine:
        _engine.dispose()
        _engine = None