#!/usr/bin/env bash
set -euo pipefail

echo "Running checkov scan (dockerfile, github_actions, kubernetes, helm)..."

# Output paths
JSON_OUT="checkov.json"
SARIF_OUT_DIR="checkov.sarif"

# Ensure SARIF output directory exists
mkdir -p "$SARIF_OUT_DIR"

# Prefer the first checkov in PATH (usually ~/.local/bin/checkov) and avoid Poetry venv
CHECKOV_BIN="$(which -a checkov | head -n1 || echo checkov)"
CHECKOV_ENV_PREFIX="env -u VIRTUAL_ENV"

# Run Checkov scans; do not fail the script on Checkov exit codes
$CHECKOV_ENV_PREFIX "$CHECKOV_BIN" -d . \
  --framework dockerfile,github_actions,kubernetes,helm \
  --skip-path .git,.venv,venv,node_modules,**/tests/** \
  -o json --output-file-path "$JSON_OUT" || true

$CHECKOV_ENV_PREFIX "$CHECKOV_BIN" -d . \
  --framework dockerfile,github_actions,kubernetes,helm \
  --skip-path .git,.venv,venv,node_modules,**/tests/** \
  -o sarif --output-file-path "$SARIF_OUT_DIR" || true

# Summarize results from JSON output
python - << 'PY'
import json, os, glob
base = 'checkov.json'
def summarize(reports):
    failed = sum(len(r.get('failed_checks') or []) for r in reports)
    passed = sum(len(r.get('passed_checks') or []) for r in reports)
    skipped = sum(len(r.get('skipped_checks') or []) for r in reports)
    print(f"Checkov summary: failed={failed}, passed={passed}, skipped={skipped}")

if os.path.isfile(base):
    try:
        data = json.load(open(base))
        reports = data if isinstance(data, list) else [data]
        summarize(reports)
    except Exception as e:
        print(f"Failed to parse {base}: {e}")
elif os.path.isdir(base):
    files = sorted(glob.glob(os.path.join(base, '*.json')))
    if not files:
        print('No JSON files found in checkov.json directory')
    else:
        reports = []
        for fp in files:
            try:
                data = json.load(open(fp))
                reports.extend(data if isinstance(data, list) else [data])
            except Exception as e:
                print(f"Failed to parse {fp}: {e}")
        if reports:
            summarize(reports)
        else:
            print('No valid JSON reports parsed')
else:
    print('No checkov.json produced')
PY

echo "Done. Outputs: ${JSON_OUT}, ${SARIF_OUT_DIR}/results_sarif.sarif"
