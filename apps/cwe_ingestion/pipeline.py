# Shim module to support test imports like `from apps.cwe_ingestion.pipeline import ...`
from .cwe_ingestion.pipeline import *  # noqa: F401,F403
