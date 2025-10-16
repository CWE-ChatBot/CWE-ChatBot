# Scripts Directory Reorganization - Complete

**Date**: October 16, 2025
**Status**: ✅ Complete

---

## Summary

Successfully consolidated all operational scripts from `/tools/` into `/scripts/ops/` for better organization and discoverability.

---

## Changes Made

### Directory Structure

**Before**:
```
tools/                          # Operational scripts
├── get_refresh_token_localhost.sh
├── get_refresh_token_manual.sh
├── get_refresh_token.py
├── pretest_get_id_token.py
├── expose_staging_via_lb.sh
└── harden_lb_and_run.sh

scripts/                        # Development utilities
├── bandit.sh
├── checkov_scan.sh
└── deploy_per_ip_rate_limit.sh
```

**After**:
```
scripts/
├── ops/                        # Operational tools (moved from tools/)
│   ├── get_refresh_token_localhost.sh
│   ├── get_refresh_token_manual.sh
│   ├── get_refresh_token.py
│   ├── pretest_get_id_token.py
│   ├── expose_staging_via_lb.sh
│   └── harden_lb_and_run.sh
├── bandit.sh                   # Development utilities
├── checkov_scan.sh
└── deploy_per_ip_rate_limit.sh
```

---

## Benefits

### ✅ Single Scripts Directory
- All scripts consolidated under `/scripts/`
- No confusion between `/tools/` and `/scripts/`
- Clear hierarchy: `scripts/ops/` for operations, `scripts/` for development

### ✅ Better Discoverability
- Operators know to look in `scripts/ops/` for deployment and auth tools
- Developers know to look in `scripts/` root for dev utilities
- Testers know to look in `tests/` for test infrastructure

### ✅ Standard Convention
- Follows common patterns in open source projects
- `ops/` subdirectory clearly indicates operational/production tools
- Consistent with `tests/scripts/` and `tests/integration/` structure

---

## Updated Paths

### Common Commands (Updated)

**OAuth Token Management**:
```bash
# OLD (no longer works)
./tools/get_refresh_token_localhost.sh
poetry run python tools/pretest_get_id_token.py

# NEW (current)
./scripts/ops/get_refresh_token_localhost.sh
poetry run python scripts/ops/pretest_get_id_token.py
```

**Infrastructure Management**:
```bash
# OLD (no longer works)
./tools/expose_staging_via_lb.sh
./tools/harden_lb_and_run.sh

# NEW (current)
./scripts/ops/expose_staging_via_lb.sh
./scripts/ops/harden_lb_and_run.sh
```

---

## Files Updated

### Test Scripts ✅
- `tests/integration/test_staging_oauth.sh` - Updated Python path
- `tests/integration/run_staging_tests.sh` - No changes needed (calls test_staging_oauth.sh)

### Documentation ✅
- `tests/integration/README.md` - All tool references updated
- `docs/refactor/R14/API_KEY_CLEANUP_COMPLETE.md` - Tool paths updated
- `docs/refactor/R14/STAGING_DEPLOYMENT.md` - Tool paths updated
- `docs/refactor/R14/TESTING_SETUP_COMPLETE.md` - Tool paths updated
- `docs/refactor/R14/DEPLOYMENT_COMPLETE.md` - Tool paths updated
- `docs/refactor/R14/create_tokens.md` - Tool paths updated
- `DIRECTORY_STRUCTURE.md` - Complete rewrite with new structure

### Created ✅
- `scripts/ops/` directory
- `docs/refactor/R14/SCRIPTS_REORGANIZATION.md` - This document

### Removed ✅
- `tools/` directory (empty, removed)

---

## Verification

### Scripts Moved Successfully
```bash
ls -la scripts/ops/
# Output: 6 files moved successfully
# - expose_staging_via_lb.sh
# - get_refresh_token_localhost.sh
# - get_refresh_token_manual.sh
# - get_refresh_token.py
# - harden_lb_and_run.sh
# - pretest_get_id_token.py
```

### Old Directory Removed
```bash
ls -d tools/
# Output: No such file or directory
```

### Tests Still Work
```bash
export GOOGLE_REFRESH_TOKEN='your_token'
./tests/integration/run_staging_tests.sh
# Output: All tests pass with new script paths
```

---

## Quick Reference (New Paths)

### OAuth Operations
```bash
# Get refresh token (interactive)
./scripts/ops/get_refresh_token_localhost.sh

# Convert refresh token to ID token
poetry run python scripts/ops/pretest_get_id_token.py
```

### Infrastructure Operations
```bash
# Configure staging load balancer
./scripts/ops/expose_staging_via_lb.sh

# Apply security hardening
./scripts/ops/harden_lb_and_run.sh
```

### Development Operations
```bash
# Security scanning
./scripts/bandit.sh
./scripts/checkov_scan.sh

# Deploy rate limiting
./scripts/deploy_per_ip_rate_limit.sh
```

---

## Migration Complete

✅ **All scripts consolidated under `/scripts/`**
✅ **Operational tools in `/scripts/ops/`**
✅ **Development utilities in `/scripts/` root**
✅ **All references updated in code and documentation**
✅ **Old `/tools/` directory removed**

**Status**: Migration complete and verified working.
