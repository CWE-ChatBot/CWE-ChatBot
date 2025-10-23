# .github Directory Documentation

This directory contains GitHub-specific configurations for CI/CD, security scanning, and automated dependency management.

## Directory Structure

```
.github/
├── README.md                           # This file
├── dependabot.yml                      # Dependency update configuration
└── workflows/                          # GitHub Actions workflows
    ├── quality.yml                     # Security scanning and code quality checks
    ├── deploy-chatbot.yml              # Production deployment automation
    └── dependabot-auto-merge.yml       # Automated dependency update merging
```

## Files Overview

### `dependabot.yml` - Dependency Update Configuration

**Purpose**: Configures GitHub Dependabot to automatically check for and create PRs for dependency updates.

**What it does**:
- Monitors Docker base images in `/apps/chatbot` and `/apps/pdf_worker`
- Monitors GitHub Actions versions in workflows
- Monitors Python dependencies via Poetry (`pip` ecosystem)
- Runs weekly checks every Monday at 09:00 UTC
- Groups minor/patch updates together to reduce PR noise
- Separates major version updates for careful review

**Configuration breakdown**:

```yaml
# Docker monitoring - tracks base image updates
- package-ecosystem: "docker"
  directory: "/apps/chatbot"        # Monitors apps/chatbot/Dockerfile
  schedule:
    interval: "weekly"
    day: "monday"
    time: "09:00"
  cooldown:
    default-days: 5                 # Wait 5 days between update batches
  groups:
    minor-and-patch:                # Group safe updates together
      update-types: ["minor", "patch"]
    majors:                         # Separate major updates
      update-types: ["major"]
```

**Example PRs created**:
- `Bump python from 3.11-slim to 3.11.8-slim` (patch update)
- `Bump chainlit from 0.7.2 to 0.8.0` (minor update)
- `Bump langchain from 0.1.0 to 2.0.0` (major update - requires review)

**Related**: Works with `dependabot-auto-merge.yml` to automatically merge safe updates.

---

### `workflows/quality.yml` - Security Scanning & Code Quality

**Purpose**: Runs comprehensive security scanning and code quality checks on every push and pull request.

**Jobs breakdown**:

#### 1. `lint-type-test`
**What**: Python linting, type checking, and unit tests
**Runs on**: Python 3.12
**Steps**:
- Install Poetry dependencies
- Run pre-commit hooks (ruff, mypy, bandit)
- Execute pytest with coverage
- Enforce 85% minimum code coverage

**Tools**:
- **ruff**: Fast Python linter and formatter
- **mypy**: Static type checker
- **pytest**: Unit test framework
- **coverage**: Code coverage measurement

#### 2. `pyright`

- **What**: Advanced static type analysis
- **Runs on**: Python 3.12
- **Purpose**: Catches type errors that mypy might miss

#### 3. `semgrep`

- **What**: Advanced security scanning using Semgrep
- **Runs on**: Ubuntu Latest (uses `semgrep/semgrep:latest` container)
- **Rulesets**:
  - `p/python`: Python-specific security rules
  - `p/security-audit`: General security audit rules
- **Configuration**:
  ```yaml
  semgrep scan \
    --config=p/python \
    --config=p/security-audit \
    --exclude='**/tests/**' \          # Skip test code
    --exclude='**/scripts/**' \         # Skip utility scripts
    --sarif \                           # Output SARIF format
    --output=semgrep-results.sarif
  ```
- **Output**: Uploads results to GitHub Code Scanning tab
- **Detects**: SQL injection, command injection, XSS, hardcoded secrets, etc.

#### 4. `pip-audit`

- **What**: Scans Python dependencies for known vulnerabilities
- **Runs on**: Python 3.12
- **Process**:
  1. Export Poetry dependencies to `requirements.txt`
  2. Run `pip-audit` against exported dependencies
  3. Generate SARIF report
  4. Upload to GitHub Code Scanning
  5. **Fail build if vulnerabilities found**
- **Example findings**:
  - `cryptography 38.0.0 has known CVE-2023-12345` → Update required

#### 5. `bandit`

- **What**: Python security linter (static analysis)
- **Scans**: All Python code in `./apps` (excludes tests)
- **Configuration**:
  ```bash
  bandit -r ./apps \
    -x "./apps/**/tests/**,./apps/**/scripts/**" \
    -f json \
    -iii -l  # Show only medium and high severity
  ```
- **Output**: JSON report uploaded as artifact
- **Detects**: Hardcoded passwords, weak crypto, shell injection, etc.

#### 6. `vulture`

- **What**: Dead code detection
- **Purpose**: Find unused code to reduce attack surface
- **Configuration**: Minimum 70% confidence for findings
- **Output**: Text report uploaded as artifact

#### 7. `checkov`

- **What**: Infrastructure-as-Code (IaC) security scanner
- **Scans**:
  - Dockerfiles
  - GitHub Actions workflows
  - Kubernetes manifests
  - Helm charts
- **Example findings**:
  - "Dockerfile doesn't specify USER (runs as root)"
  - "GitHub Action uses outdated version with known vulnerability"
- **Output**: Uploads SARIF to GitHub Code Scanning

---

### `workflows/deploy-chatbot.yml` - Production Deployment

**Purpose**: Automates deployment of the CWE ChatBot application to Google Cloud Run.

**Trigger**: Manual workflow dispatch (button in GitHub Actions UI)

**Process**:
1. Checkout code
2. Authenticate with Google Cloud Platform
3. Build Docker image using Cloud Build
4. Deploy to Cloud Run with:
   - Region: `us-central1`
   - CPU allocation: Only during request processing
   - Min instances: 0 (scale to zero)
   - Max instances: 10
   - Environment variables from secrets

**Required secrets**:
- `GCP_PROJECT_ID`: Google Cloud project ID
- `GCP_SA_KEY`: Service account key for authentication
- Database credentials, API keys, etc.

**Safety**: Only deploys when manually triggered (no automatic deployments)

---

### `workflows/dependabot-auto-merge.yml` - Automated Dependency Updates

**Purpose**: Automatically merge safe dependency updates to reduce PR noise.

**Trigger**: When Dependabot opens/updates a PR

**Logic**:

```yaml
IF author == 'dependabot[bot]':
  IF update is patch (1.2.3 → 1.2.4) OR minor (1.2.0 → 1.3.0):
    → Auto-merge after CI passes
  IF update is major (1.0.0 → 2.0.0):
    → Add label 'needs-manual-review'
    → Wait for human approval
```

**Safety measures**:
- Only runs on Dependabot PRs
- Requires all CI checks to pass first
- Uses `--auto` merge (waits for status checks)
- Squash commits to keep history clean

**Examples**:

| Update Type | Example | Action |
|-------------|---------|--------|
| Patch | `requests 2.28.1 → 2.28.2` | Auto-merge ✅ |
| Minor | `langchain 0.1.0 → 0.2.0` | Auto-merge ✅ |
| Major | `pydantic 1.10.0 → 2.0.0` | Label for review 🏷️ |

---

## Integration with Pre-Commit Hooks

The `.github/workflows/quality.yml` CI checks mirror the **local pre-commit hooks** in [`.pre-commit-config.yaml`](../.pre-commit-config.yaml).

**Why both?**
- **Local pre-commit**: Fast feedback during development (5-10 seconds)
- **CI workflows**: Enforce checks on all PRs (no one can bypass)

**What's checked where**:

| Tool | Local Pre-Commit | CI (quality.yml) | Purpose |
|------|-----------------|------------------|---------|
| Ruff | ✅ | ✅ | Linting & formatting |
| Bandit | ✅ | ✅ | Security scanning |
| Semgrep | ✅ | ✅ | Advanced security |
| pip-audit | ✅ | ✅ | Dependency vulnerabilities |
| mypy | ❌ | ✅ | Type checking (slow locally) |
| pytest | ❌ | ✅ | Unit tests (slow locally) |

**Workflow**:
1. Developer writes code
2. `git commit` → Pre-commit runs (catches 80% of issues in <10s)
3. `git push` → CI runs (enforces all checks, including slow ones)
4. PR created → Full CI suite + security scans
5. Merge → Dependabot auto-merges safe updates

---

## Security Scanning Results

All security tools upload findings to: **GitHub Security Tab** → **Code Scanning**

**What you'll see**:
- Semgrep findings: SQL injection, XSS, hardcoded secrets
- Checkov findings: IaC security issues
- pip-audit findings: Vulnerable dependencies with CVE numbers

**Severity levels**:
- 🔴 **Critical/High**: Fix immediately before merge
- 🟡 **Medium**: Fix within sprint
- ⚪ **Low/Info**: Fix when convenient

**Filtering**:
- Tests and scripts are excluded from Semgrep (reduces noise)
- Only production application code findings are shown

---

## Troubleshooting

### Quality workflow fails with "Path does not exist: semgrep.sarif"
**Cause**: Semgrep action creates nested directory structure
**Fix**: Already fixed in current `quality.yml` - uses `sarif_output` parameter

### Pre-commit hooks are slow
**Cause**: Semgrep initialization on first run
**Solution**: Hooks cache after first run. Subsequent runs are fast (5-10s)

### Dependabot PRs not auto-merging
**Possible causes**:
1. CI checks haven't passed yet → Wait for quality.yml to finish
2. Major version update → Intentionally requires manual review
3. Workflow permissions → Check repo settings → Actions → General → Workflow permissions

### Too many Dependabot PRs at once
**Solution**: Already configured with cooldown (5 days between batches) and grouping

---

## Maintenance

### Update GitHub Actions versions
Dependabot monitors `uses:` statements in workflows and creates PRs automatically.

### Update pre-commit hook versions
```bash
poetry run pre-commit autoupdate
git add .pre-commit-config.yaml
git commit -m "Update pre-commit hooks"
```

### Update Semgrep rulesets
Currently using:
- `p/python` - Python-specific rules
- `p/security-audit` - General security rules

Add more rulesets by editing `quality.yml`:
```yaml
semgrep scan \
  --config=p/python \
  --config=p/security-audit \
  --config=p/owasp-top-ten \  # Add new ruleset
  --config=p/secrets            # Add secrets detection
```

Available rulesets: https://semgrep.dev/explore

### Adjust coverage threshold
Edit `quality.yml`:
```yaml
- name: Coverage gate
  uses: orgoro/coverage@v3
  with:
    coverageFile: ./coverage.xml
    minCoverage: 85  # Change this number (0-100)
```

---

## Related Documentation

- [Pre-commit hooks configuration](../.pre-commit-config.yaml)
- [Poetry dependency management](../pyproject.toml)
- [Security testing scripts](../tests/scripts/)
- [Project README](../README.md)

---

## Questions?

- **GitHub Actions**: https://docs.github.com/en/actions
- **Dependabot**: https://docs.github.com/en/code-security/dependabot
- **Semgrep**: https://semgrep.dev/docs
- **Pre-commit**: https://pre-commit.com/
