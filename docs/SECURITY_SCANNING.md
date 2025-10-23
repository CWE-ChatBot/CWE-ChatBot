# Security Scanning Guide

This document explains the security scanning infrastructure for the CWE ChatBot project, including local pre-commit hooks and CI/CD integration.

## Table of Contents

- [Overview](#overview)
- [Local Pre-Commit Security Scanning](#local-pre-commit-security-scanning)
- [CI/CD Security Pipeline](#cicd-security-pipeline)
- [Security Tools Reference](#security-tools-reference)
- [Developer Workflow](#developer-workflow)
- [Troubleshooting](#troubleshooting)

---

## Overview

This project uses a **defense-in-depth** security scanning approach:

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Scanning Layers                  │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  1. LOCAL (Pre-Commit Hooks)                                 │
│     ├─ Semgrep (security patterns)                           │
│     ├─ Bandit (Python security linter)                       │
│     ├─ pip-audit (dependency vulnerabilities)                │
│     ├─ Ruff (code quality + security)                        │
│     └─ Runs in: 5-10 seconds on git commit                   │
│                                                               │
│  2. CI/CD (GitHub Actions)                                   │
│     ├─ All local tools (enforced on every PR)                │
│     ├─ Pyright (advanced type checking)                      │
│     ├─ Pytest (unit tests with 85% coverage)                 │
│     ├─ Checkov (IaC security scanning)                       │
│     ├─ Vulture (dead code detection)                         │
│     └─ Runs in: 2-3 minutes on push/PR                       │
│                                                               │
│  3. AUTOMATED (Dependabot + Auto-Merge)                      │
│     ├─ Weekly dependency updates                             │
│     ├─ Auto-merge safe updates (patch/minor)                 │
│     ├─ Manual review for major updates                       │
│     └─ Continuous vulnerability monitoring                   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

**Philosophy**: Shift security left - catch issues during development, not in code review.

---

## Local Pre-Commit Security Scanning

Pre-commit hooks run automatically before every `git commit`, catching security issues immediately.

### Configuration File

All pre-commit hooks are configured in [`.pre-commit-config.yaml`](../.pre-commit-config.yaml)

### Installed Hooks

#### 1. Ruff (v0.14.1) - Fast Linter & Formatter

**Purpose**: Enforces code style and catches common bugs

**Files scanned**: `apps/**/*.py` (excludes tests, build, scripts)

**What it checks**:
- Unused imports and variables
- Undefined names
- F-string errors
- PEP 8 style violations
- Security issues (hardcoded passwords, eval usage)

**Auto-fixes**: Yes (with `--fix` flag)

**Example output**:
```
apps/chatbot/main.py:42:5: F401 'os' imported but unused
apps/chatbot/auth.py:15:1: E302 expected 2 blank lines, found 1
```

#### 2. Bandit (v1.8.6) - Python Security Linter

**Purpose**: Static analysis for common security issues in Python code

**Files scanned**: `./apps` (excludes tests, build, scripts)

**Severity**: Low-Low (`-ll` flag) - reports medium and high severity only

**What it detects**:
- Hardcoded passwords and secrets
- SQL injection vulnerabilities
- Shell injection risks
- Weak cryptography
- Insecure deserialization
- Path traversal vulnerabilities

**Example output**:
```
>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector
   Severity: Medium   Confidence: Low
   Location: apps/chatbot/database.py:45
   More Info: https://bandit.readthedocs.io/en/1.8.6/plugins/b608_hardcoded_sql_expressions.html
45      query = f"SELECT * FROM users WHERE id = {user_id}"
```

**Skipped checks**:
- `B608`: Hardcoded SQL expressions (we use parameterized queries)

#### 3. Semgrep (v1.89.0) - Advanced Security Scanning

**Purpose**: Pattern-based security analysis using community rulesets

**Rulesets**:
- `p/python` - Python-specific security rules (500+ patterns)
- `p/security-audit` - General security audit rules (1000+ patterns)

**Files scanned**: All Python code (excludes `**/tests/**`, `**/scripts/**`)

**What it detects**:
- SQL injection (even complex cases)
- Command injection
- XSS vulnerabilities
- Path traversal
- Insecure deserialization
- Hardcoded secrets and API keys
- Race conditions
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity) attacks

**Advantages over Bandit**:
- More comprehensive ruleset
- Lower false positive rate
- Community-maintained rules
- Regularly updated for new CVEs

**Example output**:
```
┌─────────────────┐
│ Findings Summary │
└─────────────────┘

  python.flask.security.injection.ssrf-requests.ssrf-requests
    Using user input in requests.get() can lead to SSRF
        apps/chatbot/api.py:78

  python.lang.security.audit.dangerous-system-call
    Using os.system() with user input can lead to command injection
        apps/chatbot/utils.py:42

Ran 523 rules on 42 files: 2 findings
```

**Configuration**:
```yaml
args: [
  '--config=p/python',
  '--config=p/security-audit',
  '--exclude=**/tests/**',
  '--exclude=**/scripts/**',
  '--error',  # Exit non-zero on findings
  '--skip-unknown-extensions'
]
```

#### 4. pip-audit (v2.9.0) - Dependency Vulnerability Scanner

**Purpose**: Scans Python dependencies for known security vulnerabilities

**Runs when**: `poetry.lock` file changes

**Process**:
1. Export Poetry dependencies to `/tmp/requirements.txt`
2. Run `pip-audit` against exported dependencies
3. Report vulnerabilities with CVE numbers

**Example output**:
```
Found 2 known vulnerabilities in 1 package

Name       Version  ID             Fix Versions
---------- -------- -------------- -------------
cryptography 38.0.0  PYSEC-2023-123 >=38.0.3
cryptography 38.0.0  GHSA-w7pp-m8wf-vj6r >=38.0.3
```

**Note**: Uses `|| true` to not block commits (just warns). CI will enforce.

#### 5. Standard Pre-Commit Hooks (v6.0.0)

**Basic file checks**:
- `trailing-whitespace` - Removes trailing spaces
- `end-of-file-fixer` - Ensures files end with newline
- `check-yaml` - Validates YAML syntax
- `check-added-large-files` - Blocks files >1MB
- `check-merge-conflict` - Detects merge conflict markers

### Installation

Pre-commit hooks are **already installed** if you ran `poetry install`. To reinstall:

```bash
poetry run pre-commit install
```

This creates `.git/hooks/pre-commit` that runs automatically on `git commit`.

### Running Hooks Manually

**Run all hooks on all files**:
```bash
poetry run pre-commit run --all-files
```

**Run all hooks on staged files** (same as commit):
```bash
poetry run pre-commit run
```

**Run specific hook**:
```bash
poetry run pre-commit run semgrep --all-files
poetry run pre-commit run bandit --all-files
poetry run pre-commit run ruff --all-files
```

**Update hooks to latest versions**:
```bash
poetry run pre-commit autoupdate
```

### Bypassing Hooks (Emergency Only)

If you absolutely must commit without running hooks:

```bash
git commit --no-verify -m "Emergency fix"
```

⚠️ **WARNING**: CI will still run all checks. Bypassing hooks just delays finding issues.

---

## CI/CD Security Pipeline

GitHub Actions runs comprehensive security scans on every push and pull request.

### Workflow File

All CI checks are defined in [`.github/workflows/quality.yml`](../.github/workflows/quality.yml)

### Jobs Overview

#### 1. lint-type-test
- Python 3.12
- Install Poetry dependencies
- Run all pre-commit hooks
- Execute pytest with coverage
- Enforce 85% minimum coverage

#### 2. pyright
- Advanced type checking
- Stricter than mypy
- Catches more type errors

#### 3. semgrep
- Same as local, but enforced
- Uploads SARIF to GitHub Code Scanning
- Results visible in Security tab

#### 4. pip-audit
- Same as local, but enforced
- **Fails build if vulnerabilities found**
- Uploads SARIF to GitHub Code Scanning

#### 5. bandit
- Same as local, but enforced
- Uploads JSON report as artifact
- Fails build if medium/high severity issues found

#### 6. vulture
- Dead code detection
- Helps reduce attack surface
- Uploads findings as artifact

#### 7. checkov
- Scans Dockerfiles, GitHub Actions, Kubernetes, Helm
- Detects IaC security misconfigurations
- Uploads SARIF to GitHub Code Scanning

### Viewing Results

**GitHub Code Scanning** (Security tab):
1. Go to repository → Security tab
2. Click "Code scanning" in left sidebar
3. View findings from:
   - Semgrep
   - pip-audit
   - Checkov

**Artifacts** (individual workflow runs):
1. Go to Actions tab
2. Click on workflow run
3. Scroll to "Artifacts" section
4. Download `bandit_report_no_tests.json` or `vulture.txt`

---

## Security Tools Reference

### Tool Comparison Matrix

| Tool | Type | Speed | Language | Strength | Use Case |
|------|------|-------|----------|----------|----------|
| **Ruff** | Linter | Very Fast | Python | Code quality | Style + basic security |
| **Bandit** | SAST | Fast | Python | Common bugs | Standard security issues |
| **Semgrep** | SAST | Medium | Multi-lang | Advanced patterns | Complex vulnerabilities |
| **pip-audit** | SCA | Fast | Python deps | CVE detection | Known vulnerabilities |
| **Checkov** | IaC | Fast | Multi-format | Misconfigurations | Infrastructure security |
| **Pyright** | Type checker | Medium | Python | Type safety | Prevent runtime errors |

**SAST** = Static Application Security Testing
**SCA** = Software Composition Analysis
**IaC** = Infrastructure as Code

### When Each Tool Catches What

**Ruff catches**:
```python
# Unused imports
import os  # ← F401: imported but unused

# Undefined variables
print(undefined_var)  # ← F821: undefined name

# Dangerous functions
eval(user_input)  # ← S307: use of eval is dangerous
```

**Bandit catches**:
```python
# Hardcoded passwords
password = "admin123"  # ← B105: hardcoded password

# Weak crypto
from Crypto.Cipher import DES  # ← B413: weak cipher

# SQL injection
query = f"SELECT * FROM users WHERE id = {user_id}"  # ← B608
```

**Semgrep catches**:
```python
# Command injection (complex)
import subprocess
cmd = f"ping {request.args.get('host')}"
subprocess.run(cmd, shell=True)  # ← Command injection via shell=True

# SSRF
import requests
url = request.args.get('url')
requests.get(url)  # ← SSRF: user controls URL

# Path traversal
filepath = os.path.join("/uploads", request.files['file'].filename)
# ← Path traversal if filename contains ../
```

**pip-audit catches**:
```
cryptography==38.0.0  ← CVE-2023-49083 (fix: >=38.0.3)
requests==2.25.0      ← GHSA-j8r2-6x86-q33q (fix: >=2.31.0)
```

**Checkov catches**:
```dockerfile
# Dockerfile runs as root
FROM python:3.11-slim
# Missing: USER nonroot  ← CKV_DOCKER_2

# GitHub Action uses outdated version
- uses: actions/checkout@v1  ← CKV_GHA_1 (use v4)
```

---

## Developer Workflow

### Recommended Daily Workflow

```bash
# 1. Start new feature
git checkout -b feature/new-auth

# 2. Write code
vim apps/chatbot/auth.py

# 3. Run hooks manually (optional - commit will run anyway)
poetry run pre-commit run --all-files

# 4. Fix any issues immediately
# (Easier to fix now than later!)

# 5. Commit (hooks run automatically)
git add apps/chatbot/auth.py
git commit -m "Add OAuth authentication"

# Pre-commit output:
# ruff.....................................................Passed
# ruff-format..............................................Passed
# bandit...................................................Passed
# semgrep..................................................Passed
# pip-audit................................................Passed
# trailing-whitespace......................................Passed
# end-of-file-fixer........................................Passed
# check-yaml...............................................Passed
# check-added-large-files..................................Passed
# check-merge-conflict.....................................Passed

# 6. Push to GitHub
git push origin feature/new-auth

# 7. Create PR
gh pr create --title "Add OAuth authentication"

# 8. Wait for CI (all pre-commit checks run again + extra checks)
# - If pre-commit passed locally, CI will likely pass too
# - CI adds: pyright, pytest, vulture, checkov

# 9. Merge after approval + green CI
```

### Fixing Pre-Commit Failures

#### Scenario 1: Ruff finds style issues

```bash
git commit -m "Add feature"

# Output:
# ruff.....................................................Failed
# - hook id: ruff
# - exit code: 1
#
# apps/chatbot/main.py:15:1: F401 'os' imported but unused

# Fix: Remove unused import
vim apps/chatbot/main.py  # Remove line 15

# Commit again
git add apps/chatbot/main.py
git commit -m "Add feature"
# ✅ Passes
```

#### Scenario 2: Bandit finds security issue

```bash
git commit -m "Add database query"

# Output:
# bandit...................................................Failed
# - hook id: bandit
# - exit code: 1
#
# >> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection
#    Severity: Medium
#    Location: apps/chatbot/database.py:45
# 45    query = f"SELECT * FROM users WHERE id = {user_id}"

# Fix: Use parameterized query
vim apps/chatbot/database.py
# Change to: query = "SELECT * FROM users WHERE id = %s"
# And: cursor.execute(query, (user_id,))

git add apps/chatbot/database.py
git commit -m "Add database query"
# ✅ Passes
```

#### Scenario 3: Semgrep finds command injection

```bash
git commit -m "Add file processing"

# Output:
# semgrep..................................................Failed
#
# python.lang.security.audit.dangerous-system-call
#   Using os.system() with user input can lead to command injection
#   apps/chatbot/processor.py:42

# Fix: Use subprocess.run() with list arguments
vim apps/chatbot/processor.py
# Change from: os.system(f"convert {filename} output.png")
# To: subprocess.run(["convert", filename, "output.png"], check=True)

git add apps/chatbot/processor.py
git commit -m "Add file processing"
# ✅ Passes
```

#### Scenario 4: pip-audit finds vulnerable dependency

```bash
poetry add requests

# Edit poetry.lock changed
git add poetry.lock pyproject.toml
git commit -m "Add requests dependency"

# Output:
# pip-audit................................................Failed
# Found 1 known vulnerability in 1 package
# Name      Version  ID             Fix Versions
# requests  2.25.0   GHSA-j8r2-...  >=2.31.0

# Fix: Update to safe version
poetry add "requests>=2.31.0"

git add poetry.lock pyproject.toml
git commit -m "Add requests dependency"
# ✅ Passes
```

---

## Troubleshooting

### Pre-commit hooks are slow on first run

**Cause**: Hooks download and install tools on first run

**Solution**: Be patient. After first run, hooks are cached and run fast (5-10s)

**First run**:
```
[INFO] Initializing environment for https://github.com/semgrep/semgrep.
[INFO] Installing environment for https://github.com/semgrep/semgrep.
[INFO] This may take a few minutes...
```

**Subsequent runs**:
```
semgrep..................................................Passed  (3.2s)
```

### Semgrep fails with "connection timeout"

**Cause**: Downloading rulesets from semgrep.dev

**Solution**: Check internet connection, or use `--offline` mode (local rules only)

### pip-audit fails even though dependencies are up to date

**Cause**: New CVE was just published

**Solution**:
1. Check vulnerability details: `poetry run pip-audit`
2. Update affected package: `poetry add "package>=fixed_version"`
3. If no fix available, check if vulnerability applies to your usage
4. Document decision in `docs/SECURITY.md`

### Pre-commit hooks fail but CI passes (or vice versa)

**Cause**: Different versions of tools or different configurations

**Solution**:
1. Update pre-commit hooks: `poetry run pre-commit autoupdate`
2. Clear pre-commit cache: `poetry run pre-commit clean`
3. Re-run: `poetry run pre-commit run --all-files`

### How to skip a specific hook temporarily

Edit `.pre-commit-config.yaml` and add to the hook:

```yaml
- id: semgrep
  args: ['--config=p/python']
  # stages: [manual]  # ← Add this to disable automatic running
```

Or use `SKIP` environment variable:

```bash
SKIP=semgrep git commit -m "Quick fix"
```

### CI job "semgrep" fails with "Path does not exist: semgrep.sarif"

**Status**: Fixed in current `quality.yml`

**Previous issue**: Used `sarif:` parameter which created nested directory

**Current fix**: Uses `sarif_output:` parameter for flat file output

---

## Adding New Security Rules

### Add Semgrep ruleset

Edit `.pre-commit-config.yaml`:

```yaml
- id: semgrep
  args: [
    '--config=p/python',
    '--config=p/security-audit',
    '--config=p/owasp-top-ten',  # ← Add new ruleset
    '--exclude=**/tests/**',
    '--exclude=**/scripts/**'
  ]
```

Edit `.github/workflows/quality.yml`:

```yaml
run: |
  semgrep scan \
    --config=p/python \
    --config=p/security-audit \
    --config=p/owasp-top-ten \  # ← Add same ruleset
    --exclude='**/tests/**' \
    --sarif --output=semgrep-results.sarif
```

Available rulesets: https://semgrep.dev/explore

### Add custom Semgrep rules

Create `.semgrep/rules.yaml`:

```yaml
rules:
  - id: no-debug-print
    pattern: print("DEBUG:", ...)
    message: Remove debug print statements before commit
    severity: WARNING
    languages: [python]
```

Update config to use custom rules:

```yaml
args: ['--config=.semgrep/rules.yaml', '--config=p/python']
```

### Adjust Bandit severity threshold

Edit `.pre-commit-config.yaml`:

```yaml
- id: bandit
  args: [
    -r, ./apps,
    -x, "./apps/**/tests/**",
    -lll,  # ← Change to -lll for only high severity
    --skip, B608
  ]
```

---

## Security Scanning Best Practices

### 1. Fix Issues Immediately

Don't accumulate security debt. When pre-commit hooks find an issue:
- ✅ **DO**: Fix it immediately before committing
- ❌ **DON'T**: Use `--no-verify` to bypass and "fix later"

### 2. Understand False Positives

Not every finding is a real vulnerability:
- **Verify the context** - Does this code path actually accept user input?
- **Check documentation** - Read the CVE or ruleset documentation
- **Make informed decisions** - Document why you're ignoring if appropriate

### 3. Keep Tools Updated

```bash
# Update pre-commit hooks monthly
poetry run pre-commit autoupdate

# Update dependencies weekly (automated by Dependabot)
poetry update
```

### 4. Layer Security Checks

- **Pre-commit**: Fast feedback during development
- **CI**: Enforce on all code
- **Dependabot**: Continuous monitoring
- **Manual reviews**: For complex security decisions

### 5. Monitor GitHub Security Tab

Check https://github.com/CWE-ChatBot/CWE-ChatBot/security/code-scanning weekly:
- Review new findings
- Dismiss false positives with documentation
- Track security trends over time

---

## Related Documentation

- [`.github/README.md`](../.github/README.md) - GitHub Actions workflows documentation
- [`.pre-commit-config.yaml`](../.pre-commit-config.yaml) - Pre-commit hook configuration
- [`pyproject.toml`](../pyproject.toml) - Poetry dependency management
- [`CLAUDE.md`](../CLAUDE.md) - Development workflow and testing guidelines

---

## Quick Reference

### Essential Commands

```bash
# Install pre-commit hooks
poetry run pre-commit install

# Run all hooks manually
poetry run pre-commit run --all-files

# Run specific hook
poetry run pre-commit run semgrep

# Update hooks to latest versions
poetry run pre-commit autoupdate

# Bypass hooks (emergency only)
git commit --no-verify

# Check for dependency vulnerabilities
poetry run pip-audit

# Run Semgrep manually with custom config
semgrep --config=p/python --config=p/security-audit apps/
```

### Tool Documentation

- **Ruff**: https://docs.astral.sh/ruff/
- **Bandit**: https://bandit.readthedocs.io/
- **Semgrep**: https://semgrep.dev/docs/
- **pip-audit**: https://pypi.org/project/pip-audit/
- **Checkov**: https://www.checkov.io/
- **Pre-commit**: https://pre-commit.com/
