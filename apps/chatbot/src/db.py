# src/db.py
"""
Direct Private IP connection to Cloud SQL for production Cloud Run deployment.
Uses psycopg v3 with connection pooling and password authentication.
"""
import logging
import os
from functools import lru_cache
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.pool import QueuePool

logger = logging.getLogger(__name__)


def _build_url_from_env() -> URL:
    """
    Build PostgreSQL URL from environment variables using SQLAlchemy's URL.create.

    This method properly escapes/quotes password characters, avoiding URL-encoding pitfalls.

    Required environment variables:
    - DB_HOST: Private IP address of Cloud SQL instance
    - DB_NAME: Database name (e.g., 'cwe')
    - DB_USER: Database user (e.g., 'app_user')
    - DB_PASSWORD: Database password (from Secret Manager)

    Returns:
        URL: SQLAlchemy URL object with properly escaped credentials
    """
    host = os.environ["DB_HOST"]
    port = int(os.getenv("DB_PORT", "5432"))
    db = os.environ["DB_NAME"]
    user = os.environ["DB_USER"]
    pwd = os.environ["DB_PASSWORD"].strip()  # Always strip newline/whitespace
    sslmode = os.getenv("DB_SSLMODE", "require")

    # Log sanity checks (no secrets leaked)
    logger.info(
        f"DB connect params: host={host}:{port}, db={db}, user={user}, sslmode={sslmode}, pw_len={len(pwd)}, tail={repr(pwd[-2:]) if len(pwd) >= 2 else repr(pwd)}"
    )

    return URL.create(
        drivername="postgresql+psycopg",
        username=user,
        password=pwd,  # SQLAlchemy will quote/escape properly
        host=host,
        port=port,
        database=db,
    )


def warm_pool(engine: Any, size: int = 5) -> None:
    """
    Pre-establish connections to warm up the connection pool.

    This reduces latency for the first few queries by establishing
    connections during application startup.

    Args:
        engine: SQLAlchemy engine
        size: Number of connections to pre-create (default: 5)
    """
    try:
        logger.info(f"Warming connection pool with {size} connections...")
        conns = []
        for i in range(size):
            conn = engine.connect()
            conns.append(conn)
            logger.debug(f"Pre-created connection {i+1}/{size}")

        # Close all connections to return them to the pool
        for conn in conns:
            conn.close()

        logger.info(f"✓ Connection pool warmed with {size} connections")
    except Exception as e:
        logger.warning(f"Pool warming failed (non-fatal): {e}")


@lru_cache(maxsize=1)
def engine() -> Any:
    """
    Get a SQLAlchemy engine with connection pooling for Cloud SQL.

    Configuration:
    - pool_size=4: Base pool size for concurrent requests
    - max_overflow=0: No overflow (fixed pool)
    - pool_pre_ping=True: Validate connections before use
    - pool_recycle=1800: Recycle connections after 30 minutes
    - pool_use_lifo=True: Reuse recently-used connections (better for pooling)

    Returns:
        Engine: SQLAlchemy engine instance
    """
    url = _build_url_from_env()
    sslmode = os.getenv("DB_SSLMODE", "require")

    eng = create_engine(
        url,
        poolclass=QueuePool,
        pool_size=int(os.getenv("DB_POOL_SIZE", "4")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "0")),
        pool_pre_ping=True,
        pool_recycle=int(os.getenv("DB_POOL_RECYCLE_SEC", "1800")),
        pool_use_lifo=os.getenv("DB_POOL_USE_LIFO", "true").lower() == "true",
        connect_args={"sslmode": sslmode},
        future=True,
    )

    logger.info(
        f"✓ Created connection pool: size={eng.pool.size()}, overflow={eng.pool.overflow()}, sslmode={sslmode}"
    )

    # Note: Planner hints (enable_seqscan, hnsw.ef_search, etc.) are now applied
    # via transaction-scoped SET LOCAL in pg_chunk_store.py for better control

    # Warm the pool if enabled (default: true)
    if os.getenv("DB_WARM_POOL", "true").lower() == "true":
        warm_pool(eng, size=3)

    return eng


def close() -> None:
    """
    Dispose the engine and close all pooled connections.

    Call this during graceful shutdown to clean up database connections.
    """
    # Clear the lru_cache to get the actual engine instance
    eng = engine.__wrapped__()
    if eng is not None:
        logger.info("Disposing database engine and closing all connections")
        eng.dispose()
        engine.cache_clear()
