# Shim module to support test imports like `from apps.cwe_ingestion.pg_chunk_store import ...`
from .cwe_ingestion.pg_chunk_store import *  # noqa: F401,F403
