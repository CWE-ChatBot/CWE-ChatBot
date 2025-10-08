import logging
import os
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)


def load_environments() -> None:
    """
    Loads environment variables from a context-specific .env file.

    - 'local': Unified context for all local development, including testing.
    - Unset/Other: Production context for GCP, loads no .env file.
    """
    context = os.getenv("ENV_CONTEXT", "production").lower()

    path_map = {"local": Path.home() / "work" / "env" / ".env_cwe_chatbot"}

    if context not in path_map:
        logger.info(
            f"ENV_CONTEXT is '{context}'. No .env file will be loaded. "
            "Assuming production environment."
        )
        return

    path = path_map[context].resolve()

    if not path.exists():
        # If we are in a local context, this file is required. Fail loudly.
        raise FileNotFoundError(
            f"CRITICAL: ENV_CONTEXT is '{context}' but the required .env file was not found at: {path}"
        )

    # `override=True` ensures that values from the .env file win over stale shell variables.
    load_dotenv(dotenv_path=path, override=True)
    logger.info(f"✅ Loaded environment variables from: {path}")
