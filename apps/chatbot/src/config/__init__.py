"""Configuration package for submodules (e.g., env_loader).

Intentionally minimal to avoid circular imports with the sibling module
`src/config.py` which uses relative imports like `.config.env_loader`.
"""

# Do not import from the sibling module here.
