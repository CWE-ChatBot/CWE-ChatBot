import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Global state to track loaded environment info
_env_info: Dict[str, str] = {}


def load_environments() -> None:
    """
    Loads environment variables from a context-specific .env file.

    - 'local': Unified context for all local development, including testing.
    - Unset/Other: Production context for GCP, loads no .env file.
    """
    global _env_info
    context = os.getenv("ENV_CONTEXT", "production").lower()

    path_map = {"local": Path.home() / "work" / "env" / ".env_cwe_chatbot"}

    if context not in path_map:
        logger.info(
            f"ENV_CONTEXT is '{context}'. No .env file will be loaded. "
            "Assuming production environment."
        )
        _env_info = {"context": context, "loaded_from": "environment"}
        return

    path = path_map[context].resolve()

    if not path.exists():
        # If we are in a local context, this file is required. Fail loudly.
        raise FileNotFoundError(
            f"CRITICAL: ENV_CONTEXT is '{context}' but the required .env file was not found at: {path}"
        )

    # `override=True` ensures that values from the .env file win over stale shell variables.
    load_dotenv(dotenv_path=path, override=True)
    _env_info = {"context": context, "loaded_from": str(path)}
    logger.info(f"✅ Loaded environment variables from: {path}")


def get_env_info() -> Dict[str, str]:
    """
    Get information about the loaded environment.

    Returns:
        Dictionary with 'context' and 'loaded_from' keys
    """
    return _env_info.copy()


def load_env_auto() -> bool:
    """
    Automatically load environment based on context.

    Returns:
        True if environment was loaded successfully, False otherwise
    """
    try:
        load_environments()
        return True
    except FileNotFoundError:
        return False


class EnvironmentLoader:
    """
    Environment loader class for flexible environment variable loading.
    Supports custom search paths and explicit file paths.
    """

    def __init__(self, search_paths: Optional[List[str]] = None):
        """
        Initialize environment loader.

        Args:
            search_paths: Optional list of file paths to search for .env files
        """
        self.search_paths = search_paths or []
        self._loaded_from: Optional[str] = None

    def load_environment(self) -> bool:
        """
        Load environment from explicit path or search paths.

        Returns:
            True if environment loaded successfully, False otherwise
        """
        global _env_info

        # Check for explicit ENV_FILE_PATH
        explicit_path = os.getenv("ENV_FILE_PATH")
        if explicit_path:
            path = Path(explicit_path)
            if path.exists():
                load_dotenv(dotenv_path=path, override=True)
                self._loaded_from = str(path)
                _env_info = {"loaded_from": str(path), "source": "explicit"}
                logger.info(f"✅ Loaded environment from explicit path: {path}")
                return True
            else:
                logger.warning(f"ENV_FILE_PATH set but file not found: {path}")
                return False

        # Search custom paths
        for search_path in self.search_paths:
            path = Path(search_path)
            if path.exists():
                load_dotenv(dotenv_path=path, override=True)
                self._loaded_from = str(path)
                _env_info = {"loaded_from": str(path), "source": "search_path"}
                logger.info(f"✅ Loaded environment from search path: {path}")
                return True

        # Fall back to default behavior
        try:
            load_environments()
            self._loaded_from = _env_info.get("loaded_from")
            return True
        except FileNotFoundError:
            return False

    def get_loaded_path(self) -> Optional[str]:
        """Get the path from which environment was loaded."""
        return self._loaded_from
