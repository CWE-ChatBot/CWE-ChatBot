# CWE Ingestion Typing Fixes - October 8, 2025

## Objective

Re-enable strict mypy typing for the `apps/cwe_ingestion/cwe_ingestion` package and fix all type errors incrementally.

## Status

**Current**: 75 errors in 10 files
**Target**: 0 errors with full strict typing

## Configuration Change

Removed mypy overrides from `pyproject.toml`:
```toml
# BEFORE (permissive):
[[tool.mypy.overrides]]
module = "apps.cwe_ingestion.*"
disallow_untyped_defs = false
ignore_errors = true

[[tool.mypy.overrides]]
module = "apps.cwe_ingestion.cwe_ingestion.pg_chunk_store"
ignore_errors = true

# AFTER (strict):
# cwe_ingestion: Strict typing enabled - incremental fixes needed
# Removed ignore_errors overrides to enable full type checking
```

## Error Breakdown by File

### Priority 1: Core Database Stores (22 errors)

#### `pg_chunk_store.py` (16 errors)
**Issues**:
- Missing return type annotations (3): `_cursor`, `_get_connection`, `_ensure_schema`
- Unreachable code from numpy ndarray type checking (6 errors in `hybrid_search`, `query_hybrid`)
- Variable redefinition: `vec_param` defined twice
- Global function `query_hybrid` missing type annotations (2)

**Impact**: CRITICAL - Core retrieval functionality

#### `pg_vector_store.py` (6 errors)
**Issues**:
- Missing return type: `_ensure_schema` needs `-> None`
- Other type annotation issues

**Impact**: CRITICAL - Core storage functionality

### Priority 2: Pipeline Logic (28 errors)

#### `pipeline.py` (13 errors)
**Issues**:
- Multiple `no-redef` errors (7): Import statements being redefined
- Type incompatibility: `CWEEmbedder` vs `GeminiEmbedder`, `PostgresVectorStore` vs `PostgresChunkStore`
- Missing type annotations: `_run_single`, `_run_chunked`
- Method not found: `PostgresChunkStore.store_batch` (2)
- Returning `Any` from bool function (2)

**Impact**: HIGH - Core ingestion logic

#### `multi_db_pipeline.py` (15 errors)
**Issues**:
- Multiple `no-redef` errors (9): Import statements
- Type incompatibility: `CWEEmbedder` vs `GeminiEmbedder`
- Missing type annotations: `_generate_embeddings_once`, `_generate_single_row_embeddings`, `_generate_chunked_embeddings`
- Type mismatches in embeddings storage
- Method not found: `PostgresChunkStore.store_batch`

**Impact**: HIGH - Multi-database ingestion

### Priority 3: CLI Interface (19 errors)

#### `cli.py` (19 errors)
**Issues**:
- Multiple `no-redef` errors (3)
- Missing type annotations for all CLI functions (7+): `cli`, `ingest`, `query`, `stats`, `ingest_multi`, `policy_import`, etc.
- Unused `type: ignore` comment
- `set.add()` return value misuse
- Method not found: `PostgresChunkStore.query_similar`
- Type mismatch: ndarray vs list[float] in `query_hybrid`

**Impact**: MEDIUM - User interface, not core logic

### Priority 4: Supporting Modules (10 errors)

#### `gcp_db_helper.py` (4 errors)
- Missing return/type annotations: `cli`, `create_url`, `test_iam_auth`, `check_auth`

#### `parser.py` (2 errors)
- Missing return annotations: `__init__`, `_configure_secure_parser`

#### `embedding_cache.py` (3 errors)
- Missing return annotation: `_save_metadata`, `clear_cache`
- Returning Any: `load_embedding`

#### `embedder.py` (1 error)
- Unused `type: ignore` comment

#### `models.py` (1 error)
- Unused `type: ignore` comment

## Fix Strategy

### Phase 1: Quick Wins (Est. 30 min)
1. **Remove unused `type: ignore` comments** (3 errors)
   - `models.py:135`
   - `embedder.py:187`
   - `cli.py:25`

2. **Add missing `-> None` annotations** (10 errors)
   - All `__init__` methods
   - Helper methods that don't return values

### Phase 2: Import Cleanup (Est. 30 min)
3. **Fix `no-redef` errors** (19 errors)
   - Move imports to top of file or use `if TYPE_CHECKING:`
   - Consolidate duplicate imports

### Phase 3: Core Type Fixes (Est. 2-3 hours)
4. **Fix PostgresChunkStore/VectorStore confusion** (8 errors)
   - Clarify which store type is used where
   - Fix type annotations in pipeline classes
   - Add missing methods or fix method calls

5. **Fix numpy ndarray type checks** (6 errors)
   - Replace `isinstance(x, (list, np.ndarray))` checks
   - Use proper type narrowing or cast

6. **Add CLI function type annotations** (10 errors)
   - Annotate all Click command functions
   - Add return types

7. **Fix embedding type mismatches** (4 errors)
   - Ensure consistent use of `list[float]` vs `ndarray`
   - Add proper type conversions

## Testing Plan

After each phase:
```bash
# Check progress
poetry run mypy apps/cwe_ingestion/cwe_ingestion

# Run unit tests
poetry run pytest apps/cwe_ingestion/tests/unit/

# Run integration tests
poetry run pytest apps/cwe_ingestion/tests/integration/
```

## Blue-Green Deployment Strategy

**Context**: Need to keep existing Cloud Run service operational while testing fixes.

### Approach
1. **Current service**: `cwe-chatbot` (keep running)
2. **New service**: `cwe-chatbot-test` (deploy for testing)
3. **Traffic**: 0% to test service initially
4. **Testing**: Full unit, integration, e2e tests on test service
5. **Cutover**: Gradually shift traffic after validation

### Commands
```bash
# Deploy test service
gcloud run deploy cwe-chatbot-test \
  --image gcr.io/cwechatbot/cwe-chatbot:latest \
  --region us-central1 \
  --no-traffic

# Run tests against test service
TEST_SERVICE_URL=https://cwe-chatbot-test-<hash>-uc.a.run.app \
  poetry run pytest tests/

# Gradually shift traffic
gcloud run services update-traffic cwe-chatbot \
  --to-revisions=LATEST=10 \
  --region us-central1

# Full cutover after validation
gcloud run services update-traffic cwe-chatbot \
  --to-revisions=LATEST=100 \
  --region us-central1
```

## Progress Tracking

- [ ] Phase 1: Quick wins (unused ignores, missing -> None)
- [ ] Phase 2: Import cleanup (no-redef errors)
- [ ] Phase 3: Core type fixes
  - [ ] PostgresChunkStore/VectorStore types
  - [ ] Numpy ndarray handling
  - [ ] CLI function annotations
  - [ ] Embedding type mismatches
- [ ] All mypy errors resolved (0/75)
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Deploy to test service
- [ ] E2E tests pass on test service
- [ ] Production deployment

## Notes

- **Do NOT merge to main** until all tests pass on test service
- **Keep existing service running** throughout testing
- **Document any breaking changes** found during testing
- **Update type stubs** if third-party libraries cause issues
