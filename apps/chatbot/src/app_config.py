"""
Application configuration for CWE ChatBot.
This module safely re-exports Config and config from the sibling module
`src/config.py` even though a package named `src.config` also exists.
"""

from importlib.util import spec_from_file_location, module_from_spec
from pathlib import Path

_root = Path(__file__).resolve().parent
_config_py = _root / "config.py"

if not _config_py.exists():  # pragma: no cover
    raise ImportError("config.py not found next to src package root")

_spec = spec_from_file_location("src._config_file", str(_config_py))
if _spec is None or _spec.loader is None:  # pragma: no cover
    raise ImportError("Unable to load src/config.py module spec")

_mod = module_from_spec(_spec)
# Ensure relative imports inside config.py resolve against the 'src' package
_mod.__package__ = "src"
_spec.loader.exec_module(_mod)  # type: ignore[call-arg]

# Re-export symbols
Config = getattr(_mod, "Config")  # type: ignore[assignment]
config = getattr(_mod, "config")  # type: ignore[assignment]
