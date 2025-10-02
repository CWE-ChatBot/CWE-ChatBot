# apps/cwe_ingestion/__main__.py
"""
Main entry point for running CWE ingestion as a module.
Usage: python -m apps.cwe_ingestion
"""
from .cli import cli

if __name__ == '__main__':
    cli()
