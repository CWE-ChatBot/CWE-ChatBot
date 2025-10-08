#!/usr/bin/env bash
set -euo pipefail

# Semgrep scan helper for this monorepo.
# - Runs curated CI and broader security-audit rulesets
# - Excludes build/cache artifacts to reduce noise
# - Emits SARIF (semgrep.sarif) and JSON (semgrep.json)

ROOT_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
cd "$ROOT_DIR"

EXCLUDES=(
  "--exclude" "apps/cwe_ingestion/build"
  "--exclude" ".cache"
  "--exclude" ".pytest_cache"
  "--exclude" "htmlcov"
  "--exclude" "node_modules"
  "--exclude" "dist"
)

echo "Running Semgrep (p/ci + p/security-audit) ..."

# SARIF output
semgrep scan \
  --config p/ci \
  --config p/security-audit \
  --metrics=off \
  "${EXCLUDES[@]}" \
  --sarif --output semgrep.sarif || true

# JSON output (separate run because --output cannot be repeated)
semgrep scan \
  --config p/ci \
  --config p/security-audit \
  --metrics=off \
  "${EXCLUDES[@]}" \
  --json --output semgrep.json || true

echo "\nSemgrep completed. Outputs: semgrep.sarif, semgrep.json"
