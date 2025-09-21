"""
Environment file loader with configurable paths.
Provides flexible environment loading without hardcoded paths.
"""

import os
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)


class EnvironmentLoader:
    """Loads environment variables from configurable file locations."""
    
    # Default search paths (relative to project structure)
    DEFAULT_ENV_PATHS = [
        # Environment variable override
        "ENV_FILE_PATH",  # If set, use this path directly
        
        # Common development patterns
        ".env",  # Current directory
        "../.env",  # Parent directory
        "../../.env",  # Two levels up
        "../../../.env",  # Three levels up (for tests in nested dirs)
        
        # Common project structures
        "config/.env",
        "env/.env",
        "../env/.env",
        "../../env/.env",
        "../../../env/.env",
        
        # User home directory
        "~/.config/cwe-chatbot/.env",
    ]
    
    def __init__(self, search_paths: Optional[List[str]] = None) -> None:
        """
        Initialize environment loader.
        
        Args:
            search_paths: Custom search paths. If None, uses DEFAULT_ENV_PATHS.
        """
        self.search_paths = search_paths or self.DEFAULT_ENV_PATHS
        self._loaded_from: Optional[Path] = None
    
    def find_env_file(self) -> Optional[Path]:
        """
        Find the first available environment file.
        
        Returns:
            Path to environment file or None if not found.
        """
        # Check if explicit path is set via environment variable
        env_file_path = os.getenv("ENV_FILE_PATH")
        if env_file_path:
            path = Path(env_file_path).expanduser().resolve()
            if path.exists():
                return path
            else:
                logger.warning(f"ENV_FILE_PATH specified but file not found: {path}")
        
        # Search through default paths
        for path_str in self.search_paths:
            if path_str == "ENV_FILE_PATH":
                continue  # Already checked above
                
            path = Path(path_str).expanduser().resolve()
            if path.exists():
                return path
        
        return None
    
    def load_environment(self, override_existing: bool = False) -> bool:
        """
        Load environment variables from the first found env file.
        
        Args:
            override_existing: Whether to override existing environment variables.
            
        Returns:
            True if environment file was loaded, False otherwise.
        """
        env_file = self.find_env_file()
        if not env_file:
            logger.info("No environment file found in search paths")
            return False
        
        try:
            loaded_vars = 0
            with open(env_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse key=value pairs
                    if '=' not in line:
                        logger.warning(f"{env_file}:{line_num} - Invalid format: {line}")
                        continue
                    
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip("'\"")  # Remove quotes
                    
                    # Set environment variable
                    if override_existing or key not in os.environ:
                        os.environ[key] = value
                        loaded_vars += 1
            
            self._loaded_from = env_file
            logger.info(f"✅ Loaded {loaded_vars} environment variables from: {env_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load environment file {env_file}: {e}")
            return False
    
    def get_loaded_file(self) -> Optional[Path]:
        """Get the path of the environment file that was loaded."""
        return self._loaded_from
    
    def get_search_paths_info(self) -> Dict[str, Optional[bool]]:
        """Get information about search paths and which ones exist."""
        info = {}
        for path_str in self.search_paths:
            if path_str == "ENV_FILE_PATH":
                env_path = os.getenv("ENV_FILE_PATH")
                info[f"ENV_FILE_PATH={env_path}"] = env_path and Path(env_path).exists()
            else:
                path = Path(path_str).expanduser()
                info[str(path)] = path.exists()
        return info


# Global loader instance
_global_loader = EnvironmentLoader()


def load_env_auto() -> bool:
    """
    Automatically load environment using default search paths.
    Safe to call multiple times.
    
    Returns:
        True if environment was loaded, False otherwise.
    """
    return _global_loader.load_environment()


def get_env_info() -> Dict[str, Any]:
    """Get information about environment loading."""
    return {
        "loaded_from": str(_global_loader.get_loaded_file()) if _global_loader.get_loaded_file() else None,
        "search_paths": _global_loader.get_search_paths_info(),
        "important_vars_set": {
            "POSTGRES_PASSWORD": bool(os.getenv("POSTGRES_PASSWORD")),
            "OPENAI_API_KEY": bool(os.getenv("OPENAI_API_KEY")),
        }
    }


# Auto-load on module import (safe to call multiple times)
load_env_auto()