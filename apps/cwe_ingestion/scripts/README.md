# Scripts Directory

This directory contains utility and test scripts for the CWE ingestion pipeline.

## Test Scripts
- `test_*.py` - Various testing scripts for database connections, performance, and functionality validation
- `test_halfvec_performance.py` - Performance testing for halfvec optimization
- `test_retrieval_*.py` - Retrieval performance and functionality tests
- `test_db_connection.py` - Database connection validation
- `test_multi_db.py` - Multi-database configuration testing

## Utility Scripts
- `migrate_to_halfvec.py` - Migration script to add halfvec optimization for <200ms p95 performance
- `extract_embeddings_to_cache.py` - Extract and cache embeddings for reuse
- `production_iam_connection.py` - Production IAM authentication testing

## Usage
Run scripts from the parent directory using:
```bash
poetry run python scripts/script_name.py
```