# Shim module to support test imports like `from apps.cwe_ingestion.downloader import ...`
from .cwe_ingestion.downloader import *  # noqa: F401,F403
