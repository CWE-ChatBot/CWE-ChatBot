# Ruff Security Checks Explained

**Date**: 2025-10-29
**Context**: Enabling Ruff S family and C90 complexity checks
**Configuration File**: `pyproject.toml`

---

## What We Just Enabled

### Before (No Security Checks)
```toml
[tool.ruff.lint]
select = ["E", "F", "I", "N", "W"]  # Only linting checks
ignore = ["E501"]
```

### After (Security + Complexity Checks)
```toml
[tool.ruff.lint]
select = [
    "E",   # pycodestyle errors
    "F",   # pyflakes
    "I",   # isort
    "N",   # pep8-naming
    "W",   # pycodestyle warnings
    "C90", # mccabe complexity (NEW)
    "S",   # flake8-bandit security checks (NEW)
]
ignore = ["E501"]
```

---

## What Each Rule Family Does

### E - Pycodestyle Errors
**Purpose**: Code style violations (PEP 8)
**Examples**:
- E101: Indentation contains mixed spaces and tabs
- E711: Comparison to None should be 'if cond is None:'
- E712: Comparison to True should be 'if cond is True:'

**Security Relevance**: LOW - Mostly style, but some prevent subtle bugs

---

### F - Pyflakes
**Purpose**: Logical errors in Python code
**Examples**:
- F401: Module imported but unused
- F811: Redefinition of unused variable
- F821: Undefined name
- F841: Local variable assigned but never used

**Security Relevance**: MEDIUM - Can catch bugs that lead to security issues

---

### I - Isort
**Purpose**: Import statement organization
**Examples**:
- I001: Import block is un-sorted or un-formatted

**Security Relevance**: LOW - Organizational only

---

### N - PEP8 Naming
**Purpose**: Naming convention enforcement
**Examples**:
- N801: Class name should use CapWords convention
- N802: Function name should be lowercase
- N806: Variable in function should be lowercase

**Security Relevance**: LOW - Consistency only

---

### W - Pycodestyle Warnings
**Purpose**: Code style warnings (less severe than E)
**Examples**:
- W291: Trailing whitespace
- W293: Blank line contains whitespace

**Security Relevance**: LOW - Style only

---

### **C90 - McCabe Complexity (NEWLY ENABLED)**

**Purpose**: Detect overly complex functions that are hard to test and maintain
**Rule**: C901 - Function is too complex

**What It Detects**: Functions with cyclomatic complexity > threshold (default 10)

**Cyclomatic Complexity Explained**:
```python
# Complexity = 1 (baseline)
def simple():
    return True

# Complexity = 2 (one decision point)
def with_if(x):
    if x > 0:  # +1
        return True
    return False

# Complexity = 4 (three decision points)
def complex_function(x, y, z):
    if x > 0:      # +1
        if y > 0:  # +1
            return True
    elif z > 0:    # +1
        return False
    return None
```

**Why It Matters for Security**:
1. **Hard to Test**: Complex functions have many code paths, making it easy to miss edge cases
2. **Hidden Bugs**: More complexity = more places for security bugs to hide
3. **Hard to Review**: Security reviewers can't audit 100-line functions effectively
4. **Maintenance Risk**: Future changes more likely to introduce vulnerabilities

**Example from CWE ChatBot**:
```python
# If a function has complexity > 10, C901 will flag it
# This forces you to refactor into smaller, testable functions
def process_query(query, context, user, session, flags, config):
    if query:
        if user:
            if session:
                if flags.validate:
                    if config.strict:
                        # ... 50 more lines
                        # Complexity = 15+ (TOO COMPLEX!)
```

**Remediation**: Break into smaller functions
```python
def process_query(query, context, user, session, flags, config):
    _validate_user_session(user, session)
    _apply_config(flags, config)
    return _execute_query(query, context)
# Each function: Complexity = 3-5 (GOOD!)
```

---

### **S - Flake8-Bandit Security Checks (NEWLY ENABLED)**

**Purpose**: Detect common security vulnerabilities in Python code
**Origin**: Port of Bandit security linter rules to Ruff

**Major Security Rules Enabled** (50+ total):

#### **Injection Vulnerabilities**

**S102**: Use of `exec()` - Allows arbitrary code execution
```python
# BAD - S102
exec(user_input)  # ❌ Ruff will flag this

# GOOD
# Don't use exec() with untrusted input
```

**S605**: Shell command with string (possible injection)
```python
# BAD - S605
os.system(f"ls {user_path}")  # ❌ Ruff will flag this

# GOOD - S603 (allowed)
subprocess.run(["ls", user_path], check=True)
```

**S608**: SQL string formatting (SQL injection risk)
```python
# BAD - S608
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # ❌

# GOOD
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

#### **Cryptography Issues**

**S105**: Hardcoded password string
```python
# BAD - S105
PASSWORD = "admin123"  # ❌ Ruff will flag this

# GOOD
PASSWORD = os.environ.get("DB_PASSWORD")
```

**S106**: Hardcoded password in function argument
```python
# BAD - S106
def connect(password="admin"):  # ❌ Ruff will flag this

# GOOD
def connect(password=None):
    if not password:
        password = os.environ.get("DB_PASSWORD")
```

**S107**: Hardcoded password in function call
```python
# BAD - S107
db.connect(password="secret")  # ❌ Ruff will flag this

# GOOD
db.connect(password=os.environ.get("DB_PASSWORD"))
```

**S324**: Insecure hash function (MD5, SHA1)
```python
# BAD - S324
import hashlib
hashlib.md5(data)  # ❌ Ruff will flag this (MD5 is broken)

# GOOD
hashlib.sha256(data)  # SHA-256 is secure
```

**S501-S505**: Weak cryptography
- S501: Using `assert` statements (removed in optimized Python)
- S502: SSL/TLS certificate verification disabled
- S503: Bad file permissions
- S504: SSL with insecure protocol version
- S505: Weak cryptographic key

#### **Dangerous Functions**

**S301-S302**: Pickle/Marshal (insecure deserialization)
```python
# BAD - S301
import pickle
data = pickle.loads(untrusted_data)  # ❌ Code execution risk

# GOOD
import json
data = json.loads(trusted_data)
```

**S303**: Insecure hash function for security purposes
```python
# BAD - S303
import hashlib
hashlib.md5()  # ❌ For passwords/signatures

# GOOD
from cryptography.hazmat.primitives import hashes
hashes.SHA256()
```

**S304-S310**: File handling security
- S304: `tempfile.mktemp` (race condition)
- S307: `eval()` usage
- S308: `mark_safe()` in templates
- S310: URL open (SSRF risk)

#### **Configuration Issues**

**S104**: Binding to all network interfaces
```python
# BAD - S104
app.run(host="0.0.0.0")  # ❌ Ruff will flag this

# GOOD
app.run(host="127.0.0.1")  # Localhost only
```

**S108**: Insecure temporary file
```python
# BAD - S108
temp = tempfile.mktemp()  # ❌ Race condition

# GOOD
with tempfile.NamedTemporaryFile() as temp:
    # Secure temporary file
```

**S113**: Request without timeout
```python
# BAD - S113
requests.get(url)  # ❌ Can hang forever

# GOOD
requests.get(url, timeout=10)
```

#### **Assert Statements (Production Risk)**

**S101**: Use of `assert` statement
```python
# BAD - S101 (in production code)
def authenticate(user):
    assert user.is_authenticated  # ❌ Removed with python -O

# GOOD
def authenticate(user):
    if not user.is_authenticated:
        raise AuthenticationError("User not authenticated")
```

---

## What Will Ruff Now Detect in CWE ChatBot?

### Security Issues Previously Missed

Based on the validation report, Ruff S family **MIGHT** now catch:

#### 1. **Hardcoded Secrets** (S105, S106, S107)
```python
# If we had something like:
API_KEY = "sk-1234567890abcdef"  # ❌ S105 would flag this
```

#### 2. **Insecure Hash Usage** (S324)
```python
# apps/cwe_ingestion/cwe_ingestion/embedding_cache.py:72
# Uses MD5 for cache keys (non-cryptographic use)
cache_key = hashlib.md5(text.encode()).hexdigest()
# Ruff will flag this, but it's a false positive (MD5 OK for cache keys)
```

#### 3. **Request Without Timeout** (S113)
```python
# If we had:
response = requests.get(jwks_url)  # ❌ S113 would flag this

# Fix:
response = requests.get(jwks_url, timeout=10)  # ✅
```

#### 4. **Assert in Production Code** (S101)
```python
# apps/chatbot/api.py:198
assert kid is not None  # ❌ S101 will flag this

# Fix:
if kid is None:
    raise HTTPException(status_code=401, detail="Missing key ID")
```

### Complexity Issues (C90)

Functions that might be flagged:
- Large handler functions with many conditionals
- Complex query processing logic
- Deep nested if/else chains

---

## Expected Impact

### What Ruff S + C90 Will NOT Catch

Based on validation analysis, Ruff will **STILL MISS**:
- ❌ Missing JWT key rotation (CRI-JWT-001)
- ❌ JWKS cache poisoning (HIGH-JWT-001)
- ❌ Missing JWT claim validation (MED-JWT-001)
- ❌ Algorithm pre-validation pattern (MED-JWT-002)
- ❌ PostgreSQL GUC SQL injection (INPUT-001) - unless we remove `--skip B608`
- ❌ ReDoS vulnerabilities (INPUT-002)

**Why**: These require domain knowledge, threat modeling, and architectural analysis.

### What Ruff S + C90 WILL Catch

- ✅ Hardcoded passwords/API keys
- ✅ Insecure hash functions (MD5/SHA1 for crypto)
- ✅ Insecure deserialization (pickle)
- ✅ Missing request timeouts
- ✅ Dangerous `assert` in production code
- ✅ Overly complex functions (testability issues)
- ✅ SSL/TLS configuration issues
- ✅ Shell injection patterns (basic)

**Estimated Additional Coverage**: 10-15% of vulnerabilities

---

## How to Run Ruff with New Rules

### Command Line
```bash
# Check all files
ruff check .

# Check specific directory
ruff check apps/chatbot/src

# Show only security issues (S family)
ruff check --select S apps/chatbot/src

# Show only complexity issues (C90)
ruff check --select C90 apps/chatbot/src

# Auto-fix safe issues
ruff check --fix apps/chatbot/src
```

### Pre-commit Hook
```bash
# Run pre-commit hooks (includes ruff)
pre-commit run --all-files

# Run only ruff hook
pre-commit run ruff --all-files
```

### CI/CD Pipeline
Already configured in `.github/workflows/quality.yml`:
```yaml
- name: Run Ruff (Lint)
  run: poetry run ruff check .
```

---

## Configuring Complexity Threshold

### Default: Complexity > 10 is flagged

### Custom Configuration
```toml
[tool.ruff.lint.mccabe]
max-complexity = 10  # Default

# More strict (recommended for security-critical code)
max-complexity = 7

# More lenient (not recommended)
max-complexity = 15
```

### Per-File Overrides
```toml
[tool.ruff.lint.per-file-ignores]
# Allow higher complexity in test files
"tests/**/*.py" = ["C901"]

# Allow higher complexity in legacy code (temporary)
"apps/legacy/**/*.py" = ["C901"]
```

---

## Handling False Positives

### Inline Ignores
```python
# Ignore specific rule on specific line
cache_key = hashlib.md5(text.encode()).hexdigest()  # noqa: S324

# Ignore multiple rules
data = pickle.loads(trusted_internal_data)  # noqa: S301, S403

# Ignore with explanation (recommended)
# MD5 used for cache key generation only, not cryptographic security
cache_key = hashlib.md5(text.encode()).hexdigest()  # noqa: S324
```

### File-Level Ignores
```python
# At top of file
# ruff: noqa: S324

# Or for specific rules
# ruff: noqa: S324, S301
```

### Project-Level Ignores
```toml
[tool.ruff.lint]
ignore = [
    "E501",  # Line too long
    "S324",  # MD5 usage (if we accept the risk)
]
```

---

## Next Steps

### 1. Run Ruff and Review Findings
```bash
# See what new issues are detected
poetry run ruff check apps/chatbot/src apps/cwe_ingestion/cwe_ingestion
```

### 2. Triage Each Finding
- **True Positive**: Fix the security issue
- **False Positive**: Add `# noqa` with explanation
- **Low Priority**: Add to backlog

### 3. Update Pre-commit Config
The `.pre-commit-config.yaml` already includes ruff, so new rules will run automatically on commit.

### 4. Monitor CI/CD
The GitHub Actions workflow will now catch more issues in PRs.

---

## Summary

**Before**: Ruff only checked code style and basic errors (0% security coverage)

**After**: Ruff now checks:
- 50+ security patterns (S family - Bandit equivalent)
- Function complexity (C90 - McCabe)
- Combined with existing style checks (E, F, I, N, W)

**Expected Impact**:
- Catch 10-15% more vulnerabilities automatically
- Enforce complexity limits (improves testability)
- Faster feedback loop (pre-commit + CI/CD)
- **Still need manual analysis for remaining 85-90%**

**Bottom Line**: This is a good improvement to automated tooling, but **does not replace comprehensive security analysis**. It catches common mistakes, but misses architectural issues, domain-specific vulnerabilities, and business logic flaws.

---

**Configuration File**: `/home/chris/work/CyberSecAI/cwe_chatbot_bmad/pyproject.toml:79-89`
**Documentation**: https://docs.astral.sh/ruff/rules/
**Related Report**: `VALIDATED_AUTO_VS_MANUAL_ANALYSIS.md`
