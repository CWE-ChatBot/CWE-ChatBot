# Development Toolchain

This document describes the complete development toolchain used in the CWE ChatBot project, including Python tools, browser debugging tools, and security testing tools.

## Overview

The project uses a modern development toolchain optimized for code quality, type safety, security, and developer productivity:

### Development Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.12.3 | Runtime and development |
| Poetry | 1.8.2 | Dependency management and packaging |
| pip | 24.0 | Package installer (used by Poetry) |
| Ruff | 0.6.9 | Fast linting and code formatting (Rust-based) |
| Black | 23.12.1 | Opinionated code formatter |
| Mypy | 1.17.1 | Static type checking |
| Pydantic | 2.11.7 | Data validation and settings management |
| Semgrep | Latest | Security-focused static analysis |

### GitHub Advanced Security

The project leverages **GitHub Advanced Security** for comprehensive security protection:

| Tool | Purpose | Status |
|------|---------|--------|
| **Dependabot** | Automated dependency updates and vulnerability alerts | ✅ Enabled |
| **CodeQL** | Automated code scanning for security vulnerabilities | ✅ Enabled |
| **Secret Scanning** | Detect secrets, tokens, and credentials in code | ✅ Enabled |
| **Push Protection** | Block commits containing secrets before they reach repository | ✅ Enabled |

**Key Benefits**:
- **Dependabot**: Automatically creates PRs to update vulnerable dependencies
- **CodeQL**: Scans for 200+ security vulnerability patterns (SQL injection, XSS, etc.)
- **Secret Scanning**: Prevents credential leaks (API keys, tokens, passwords)
- **Push Protection**: Real-time blocking of secret commits (prevents incidents before they happen)

## Tool Purposes

### Python 3.12.3
**Purpose**: Language runtime and standard library

**Key Features Used**:
- Type hints with generics (PEP 585)
- Structural pattern matching
- Dataclasses for configuration
- AsyncIO for concurrent operations
- Context managers for resource management

**Installation**:
```bash
# Ubuntu/Debian
sudo apt install python3.12 python3.12-venv python3.12-dev

# Verify
python3 --version
```

### Poetry 1.8.2
**Purpose**: Dependency management, virtual environment management, and packaging

**Why Poetry**:
- Deterministic builds with poetry.lock
- Simpler dependency resolution than pip
- Built-in virtual environment management
- pyproject.toml standard configuration
- Workspace support for monorepos

**Installation**:
```bash
curl -sSL https://install.python-poetry.org | python3 -

# Verify
poetry --version
```

**Key Commands**:
```bash
# Install dependencies
poetry install

# Run command in virtual environment
poetry run python script.py
poetry run pytest
poetry run chainlit run apps/chatbot/main.py

# Add dependency
poetry add package-name

# Update dependencies
poetry update

# Show installed packages
poetry show --tree
```

**Configuration** (pyproject.toml):
```toml
[tool.poetry]
name = "cwe-chatbot"
version = "1.0.0"
description = "AI-powered CWE analysis chatbot"
python = "^3.10"

[tool.poetry.dependencies]
python = "^3.10"
pydantic = "^2.11.7"
# ... other dependencies

[tool.poetry.group.dev.dependencies]
ruff = "^0.6.9"
black = "^23.12.1"
mypy = "^1.17.1"
pytest = "^7.4.4"
```

### Ruff 0.6.9
**Purpose**: Extremely fast Python linter and code formatter (Rust-based)

**Why Ruff**:
- 10-100x faster than other Python linters
- Replaces Flake8, isort, pydocstyle, and more
- Built-in auto-fix for many rules
- Can also format code (alternative to Black)
- Native type-aware linting

**Key Features**:
- Linting: Enforces code style rules
- Formatting: Fast code formatter (Black-compatible)
- Import sorting: Organizes imports
- Error codes: Pyflakes (F), pycodestyle (E/W), isort (I), etc.

**Usage**:
```bash
# Lint code
poetry run ruff check .

# Auto-fix issues
poetry run ruff check --fix .

# Format code (alternative to Black)
poetry run ruff format .

# Check specific directory
poetry run ruff check apps/chatbot/src/
```

**Configuration** (pyproject.toml or ruff.toml):
```toml
[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = [
    "E",   # pycodestyle errors
    "W",   # pycodestyle warnings
    "F",   # pyflakes
    "I",   # isort
    "B",   # flake8-bugbear
    "S",   # flake8-bandit (security)
    "C4",  # flake8-comprehensions
]
ignore = [
    "E501",  # line too long (handled by formatter)
]

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S101"]  # Allow assert in tests
```

### Black 23.12.1
**Purpose**: Opinionated code formatter ("The Uncompromising Code Formatter")

**Why Black**:
- Zero configuration philosophy
- Consistent formatting across projects
- Eliminates formatting debates
- Fast and deterministic
- Industry standard

**Key Features**:
- Formats code to consistent style
- Line length: 88 characters (default)
- PEP 8 compliant with some opinions
- Preserves AST (code semantics unchanged)

**Usage**:
```bash
# Format code
poetry run black .

# Check without modifying
poetry run black --check .

# Format specific files
poetry run black apps/chatbot/src/
```

**Configuration** (pyproject.toml):
```toml
[tool.black]
line-length = 88
target-version = ['py312']
include = '\.pyi?$'
extend-exclude = '''
/(
  # Exclude directories
  \.git
  | \.venv
  | build
  | dist
)/
'''
```

**Note**: Ruff's formatter can replace Black. Choose one:
- **Black**: More mature, zero config philosophy
- **Ruff format**: Faster, Black-compatible, integrated with linting

### Mypy 1.17.1
**Purpose**: Static type checker for Python

**Why Mypy**:
- Catches type errors before runtime
- Improves code documentation via types
- Better IDE autocomplete and refactoring
- Industry standard for Python type checking
- Gradual typing (can adopt incrementally)

**Key Features**:
- Static analysis of type hints
- Detects type mismatches
- Validates function signatures
- Checks generic types
- Plugin system (e.g., Pydantic plugin)

**Usage**:
```bash
# Type check entire project
poetry run mypy .

# Check specific files
poetry run mypy apps/chatbot/src/

# Generate HTML report
poetry run mypy --html-report mypy-report .
```

**Configuration** (pyproject.toml or mypy.ini):
```toml
[tool.mypy]
python_version = "3.12"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_any_unimported = false
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_no_return = true
check_untyped_defs = true
plugins = ["pydantic.mypy"]

[[tool.mypy.overrides]]
module = "tests.*"
disallow_untyped_defs = false
```

### Pydantic 2.11.7
**Purpose**: Data validation and settings management using Python type hints

**Why Pydantic**:
- Runtime validation of data structures
- Type-safe configuration management
- JSON Schema generation
- Fast performance (Rust core)
- Excellent error messages

**Key Features**:
- BaseModel for data classes with validation
- Settings management from environment variables
- Automatic type coercion
- Custom validators
- JSON serialization/deserialization

**Usage Example**:
```python
from pydantic import BaseModel, Field, validator

class Config(BaseModel):
    """Application configuration."""

    pg_host: str = Field(default="localhost")
    pg_port: int = Field(default=5432, ge=1, le=65535)
    max_instances: int = Field(default=10, ge=1)

    @validator('pg_host')
    def validate_host(cls, v):
        if not v:
            raise ValueError('Host cannot be empty')
        return v

# Usage
config = Config(pg_host="10.43.0.3", pg_port=5432)
print(config.pg_host)  # Type-safe access
```

**Settings Management**:
```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """Load settings from environment variables."""

    postgres_host: str
    postgres_port: int = 5432
    gemini_api_key: str

    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()  # Loads from .env automatically
```

## Tool Integration Workflow

### 1. Three-Tool Approach (Recommended)

Use all three tools for maximum code quality:

```bash
# 1. Format code (Black)
poetry run black .

# 2. Lint and auto-fix (Ruff)
poetry run ruff check --fix .

# 3. Type check (Mypy)
poetry run mypy .
```

**Why all three?**
- **Ruff**: Fast linting, catches common code issues, import sorting
- **Black**: Consistent formatting (or use `ruff format` instead)
- **Mypy**: Type safety, catches type-related bugs

### 2. Alternative: Ruff-Only Formatting

Use Ruff for both linting and formatting:

```bash
# 1. Format code (Ruff)
poetry run ruff format .

# 2. Lint and auto-fix (Ruff)
poetry run ruff check --fix .

# 3. Type check (Mypy)
poetry run mypy .
```

**Advantage**: One less tool, slightly faster

### 3. Pre-commit Hook Integration

Automate quality checks with git hooks:

```bash
# .git/hooks/pre-commit
#!/bin/bash
set -e

echo "Running code quality checks..."

# Format
poetry run black . || exit 1

# Lint
poetry run ruff check --fix . || exit 1

# Type check
poetry run mypy . || exit 1

echo "✓ All checks passed"
```

Make executable:
```bash
chmod +x .git/hooks/pre-commit
```

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Code Quality

on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'

      - name: Install Poetry
        run: curl -sSL https://install.python-poetry.org | python3 -

      - name: Install dependencies
        run: poetry install

      - name: Check formatting (Black)
        run: poetry run black --check .

      - name: Lint (Ruff)
        run: poetry run ruff check .

      - name: Type check (Mypy)
        run: poetry run mypy .

      - name: Run tests
        run: poetry run pytest
```

## Development Workflow

### Daily Development
```bash
# 1. Make code changes
vim apps/chatbot/src/secrets.py

# 2. Format
poetry run black apps/chatbot/src/secrets.py

# 3. Lint
poetry run ruff check --fix apps/chatbot/src/secrets.py

# 4. Type check
poetry run mypy apps/chatbot/src/secrets.py

# 5. Test
poetry run pytest apps/chatbot/tests/unit/test_secrets.py

# 6. Commit
git add apps/chatbot/src/secrets.py
git commit -m "Add Secret Manager integration"
```

### IDE Integration

**VS Code** (settings.json):
```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.ruffEnabled": true,
  "python.linting.mypyEnabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  }
}
```

**PyCharm**:
- Settings → Tools → Black → Enable
- Settings → Tools → External Tools → Add Ruff
- Settings → Python Integrated Tools → Type Checker: Mypy

## Upgrade Strategy

### Check for Updates
```bash
# Show outdated packages
poetry show --outdated

# Check specific tool
poetry show ruff
```

### Upgrade Tools
```bash
# Upgrade specific tool
poetry update ruff

# Upgrade all dev dependencies
poetry update --only dev

# Upgrade Poetry itself
poetry self update
```

### Breaking Changes to Watch

**Ruff 1.0** (upcoming):
- API changes in configuration format
- New default rules

**Pydantic 2.x** (current):
- Different from Pydantic 1.x API
- Rust core for performance
- Settings moved to pydantic-settings package

**Mypy**:
- Stricter type checking in newer versions
- May require additional type annotations

## Troubleshooting

### Common Issues

**Poetry not found**:
```bash
# Add Poetry to PATH
export PATH="$HOME/.local/bin:$PATH"
```

**Ruff/Black conflict**:
```bash
# Ensure line-length matches
[tool.ruff]
line-length = 88  # Match Black's default

[tool.black]
line-length = 88
```

**Mypy cache issues**:
```bash
# Clear cache
poetry run mypy --clear-cache .
```

**Type stub missing**:
```bash
# Install type stubs
poetry add --group dev types-requests
```

## Best Practices

1. **Run tools in order**: Format → Lint → Type check
2. **Fix type errors immediately**: Don't accumulate technical debt
3. **Use strict mode**: Enable strict Mypy checking for new code
4. **Review Ruff output**: Don't blindly accept auto-fixes
5. **Keep tools updated**: Check monthly for updates
6. **Configure in pyproject.toml**: Single source of configuration
7. **Document deviations**: If you ignore a rule, comment why

## Resources

- **Python**: https://docs.python.org/3.12/
- **Poetry**: https://python-poetry.org/docs/
- **Ruff**: https://docs.astral.sh/ruff/
- **Black**: https://black.readthedocs.io/
- **Mypy**: https://mypy.readthedocs.io/
- **Pydantic**: https://docs.pydantic.dev/

## Project-Specific Notes

### Current Setup
- No pyproject.toml in project root (yet)
- Tools installed via Poetry in virtual environment
- Configuration currently implicit (using defaults)

### TODO
- [ ] Create pyproject.toml with tool configurations
- [ ] Add pre-commit hooks
- [ ] Configure CI/CD pipeline with quality checks
- [ ] Document project-specific Ruff/Mypy rules

---

## Browser Development Tools

### Chrome DevTools

**Purpose**: Browser-based debugging, performance analysis, and security testing

**Why Chrome DevTools**:
- Built into Chrome/Chromium browsers
- Real-time debugging of web applications
- Performance profiling and optimization
- Security issue detection (CSP, HTTPS, etc.)
- Network traffic analysis
- Industry-standard for web development

**Key Features**:

#### 1. **Console**
- JavaScript errors and warnings
- Console.log() output
- Interactive JavaScript REPL
- Filter by log level (error, warning, info, debug)

**Usage**:
```
Open DevTools: F12 or Ctrl+Shift+I (Windows/Linux), Cmd+Option+I (Mac)
Navigate to: Console tab
```

**Common Use Cases**:
- Debug JavaScript errors in Chainlit UI
- Test JavaScript snippets interactively
- Monitor API call responses
- Check for authentication errors

---

#### 2. **Network Tab**

**Purpose**: Monitor all HTTP/HTTPS network requests, responses, and timing

**Key Information**:
- Request/response headers
- Request payload and response body
- HTTP status codes (200, 404, 500, etc.)
- Request timing (TTFB, download time, total time)
- Resource size and compression
- WebSocket connections

**Usage**:
```
Open DevTools → Network tab
Reload page to capture requests
Click any request to see details:
  - Headers (request/response)
  - Preview (formatted response)
  - Response (raw response body)
  - Timing (waterfall chart)
```

**Common Debugging Scenarios**:

**CSP (Content Security Policy) Violations**:
```
Symptom: Resources fail to load (fonts, stylesheets, scripts)
Network Tab: Shows failed requests (status 0 or blocked)
Console: Shows CSP violation errors

Example Error:
"Refused to load the stylesheet 'https://fonts.googleapis.com/css2?family=Inter'
because it violates the following Content Security Policy directive:
"style-src 'self'"

Fix: Update CSP middleware to allow external sources:
style-src 'self' https://fonts.googleapis.com https://cdn.jsdelivr.net;
```

**CORS (Cross-Origin Resource Sharing) Errors**:
```
Symptom: API calls fail from browser
Network Tab: Request shows (failed) or (blocked)
Console: "CORS policy: No 'Access-Control-Allow-Origin' header"

Fix: Update backend to include CORS headers:
Access-Control-Allow-Origin: https://cwe.crashedmind.com
```

**Authentication Failures**:
```
Symptom: 401 Unauthorized or 403 Forbidden responses
Network Tab: Check request headers for Authorization/Cookie
Response tab: Check error message body

Fix: Verify OAuth token is being sent, check session expiry
```

**Slow Requests**:
```
Network Tab → Timing column: Shows request duration
Click request → Timing tab: See breakdown:
  - Queueing: Time waiting for available connection
  - DNS Lookup: Domain resolution time
  - Initial connection: TCP handshake + TLS
  - Waiting (TTFB): Server processing time ← Often the bottleneck
  - Content Download: Transfer time

Optimization targets:
- TTFB > 1s: Optimize backend processing
- Content Download > 1s: Enable compression, reduce payload size
```

**Filter Options**:
- Type: XHR, JS, CSS, Img, Media, Font, Doc, WS (WebSocket), etc.
- Domain: Filter by specific domain
- Status: Filter by HTTP status code

---

#### 3. **Application Tab**

**Purpose**: Inspect storage, cookies, cache, and service workers

**Key Features**:
- **Cookies**: View, edit, delete cookies
- **Local Storage**: Key-value storage
- **Session Storage**: Session-scoped storage
- **Cache Storage**: Service worker caches
- **IndexedDB**: Client-side database

**Usage**:
```
Open DevTools → Application tab
Expand "Cookies" → Select domain
View/edit/delete cookies
Check Storage quota and usage
```

**Common Use Cases**:
- Verify OAuth session cookies are set
- Check token expiration timestamps
- Clear storage to test fresh session
- Inspect cached resources

---

#### 4. **Security Tab**

**Purpose**: Verify HTTPS configuration and certificate validity

**Key Information**:
- Certificate details (issuer, expiry, validity)
- HTTPS connection security
- Mixed content warnings
- Certificate transparency logs

**Usage**:
```
Open DevTools → Security tab
Click "View certificate" for details
Check for mixed content warnings
```

**Common Issues**:
- **Mixed Content**: HTTPS page loading HTTP resources (blocked by browser)
- **Invalid Certificate**: Self-signed or expired cert
- **Weak Cipher**: Outdated TLS protocol or cipher suite

---

#### 5. **Lighthouse**

**Purpose**: Automated auditing for performance, accessibility, SEO, and best practices

**Categories**:
1. **Performance**: Page load speed, metrics (FCP, LCP, TBT, CLS)
2. **Accessibility**: ARIA roles, color contrast, keyboard navigation
3. **Best Practices**: HTTPS, CSP, console errors, deprecated APIs
4. **SEO**: Meta tags, viewport, crawlability
5. **Progressive Web App (PWA)**: Manifest, service worker, offline support

**Usage**:
```
Open DevTools → Lighthouse tab
Select categories to audit:
  ☑ Performance
  ☑ Accessibility
  ☑ Best Practices
  ☑ SEO
Select device: Mobile or Desktop
Click "Analyze page load"
```

**Key Metrics**:

**Performance Metrics**:
- **FCP (First Contentful Paint)**: Time to first text/image (Target: <1.8s)
- **LCP (Largest Contentful Paint)**: Time to largest element (Target: <2.5s)
- **TBT (Total Blocking Time)**: Main thread blocking time (Target: <200ms)
- **CLS (Cumulative Layout Shift)**: Visual stability (Target: <0.1)
- **Speed Index**: How quickly content is visually populated (Target: <3.4s)

**Best Practices Checks**:
- ✅ Uses HTTPS
- ✅ No browser errors logged to console
- ✅ Images have explicit width and height
- ✅ Links to cross-origin destinations are safe
- ✅ Avoids deprecated APIs
- ⚠️ Content Security Policy (CSP) configured
- ⚠️ No mixed content warnings

**Accessibility Checks**:
- ✅ All images have alt text
- ✅ Color contrast meets WCAG AA standards
- ✅ Form elements have associated labels
- ✅ ARIA roles used correctly
- ✅ Keyboard navigation works

**CSP Validation in Lighthouse**:
```
Best Practices → Security section:
- "Content Security Policy" check
- Shows if CSP header is missing or too permissive
- Recommends strict CSP for XSS prevention

Example Recommendation:
"No CSP found in enforcement mode"
Fix: Add CSP header via middleware or meta tag
```

**Using Lighthouse for Debugging**:

**Scenario: Slow Page Load**
```
Lighthouse → Performance audit
Check diagnostics:
  - "Avoid enormous network payloads" → Reduce bundle size
  - "Serve images in next-gen formats" → Use WebP instead of PNG
  - "Reduce unused JavaScript" → Code splitting
  - "Minimize main-thread work" → Optimize JavaScript execution
```

**Scenario: CSP Blocking Resources**
```
Lighthouse → Best Practices → Security
Check: "Content Security Policy"
If failing:
  1. Open Console tab for specific violation errors
  2. Open Network tab to see blocked requests
  3. Update CSP directives to allow legitimate sources
```

**Scenario: Accessibility Issues**
```
Lighthouse → Accessibility audit
Shows specific violations:
  - "Image elements do not have [alt] attributes"
  - "Background and foreground colors do not have sufficient contrast"
Click each issue for:
  - Failing elements
  - How to fix
  - Learn more link (WCAG guidelines)
```

**Lighthouse CLI (Automated Testing)**:
```bash
# Install Lighthouse CLI
npm install -g lighthouse

# Run audit and generate HTML report
lighthouse https://cwe.crashedmind.com \
  --output html \
  --output-path ./lighthouse-report.html \
  --chrome-flags="--headless"

# Run specific categories
lighthouse https://cwe.crashedmind.com \
  --only-categories=performance,accessibility \
  --output json \
  --output-path ./lighthouse.json

# CI/CD integration
lighthouse https://staging-cwe.crashedmind.com \
  --preset=desktop \
  --quiet \
  --chrome-flags="--headless" \
  | grep "Performance score" # Fail if score < 90
```

**Lighthouse in CI/CD**:
```yaml
# .github/workflows/lighthouse.yml
name: Lighthouse Audit

on: [pull_request]

jobs:
  lighthouse:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Lighthouse
        uses: treosh/lighthouse-ci-action@v9
        with:
          urls: |
            https://staging-cwe.crashedmind.com
          uploadArtifacts: true
          temporaryPublicStorage: true
```

---

#### 6. **Sources Tab** (Debugging JavaScript)

**Purpose**: Set breakpoints, step through code, inspect variables

**Usage**:
```
Open DevTools → Sources tab
Navigate to JavaScript file
Click line number to set breakpoint
Reload page, code will pause at breakpoint
Use controls:
  - Step over: Execute current line
  - Step into: Enter function call
  - Step out: Exit current function
  - Resume: Continue execution
```

**Common Use Cases**:
- Debug Chainlit frontend JavaScript
- Inspect WebSocket message handling
- Track OAuth redirect flow
- Debug form validation logic

---

### Chrome DevTools Best Practices for CWE ChatBot

1. **Always check Network tab first** when debugging production issues
2. **Use Lighthouse** before major releases to catch regressions
3. **Monitor Console** for CSP violations and JavaScript errors
4. **Verify CSP headers** in Network → Response Headers
5. **Test on mobile** using Device Toolbar (Ctrl+Shift+M)
6. **Use "Preserve log"** in Network tab to keep requests across page navigations
7. **Enable "Disable cache"** when debugging to avoid stale resources

### Common Production Debugging Workflow

```
1. User reports: "Page not loading" or "Feature broken"

2. Open Chrome DevTools (F12)

3. Check Console tab:
   - Any red errors? → JavaScript exception
   - CSP violations? → Update CSP middleware
   - Network errors? → Proceed to Network tab

4. Check Network tab:
   - Any failed requests (red)? → Check status code
   - 401/403? → Authentication issue
   - 500/502/503? → Backend error
   - 0 or (blocked)? → CSP or CORS issue
   - Slow requests (>2s)? → Performance issue

5. Check specific request details:
   - Headers tab: Verify correct CSP, CORS, cookies sent
   - Preview/Response: See actual response body
   - Timing: Identify bottleneck (TTFB vs download)

6. Check Application tab:
   - Cookies: Verify session cookie present and valid
   - Storage: Check if data persists correctly

7. Run Lighthouse audit:
   - Identify performance regressions
   - Check accessibility issues
   - Verify security best practices

8. Fix issue, deploy, verify in Network/Console tabs
```

### Chrome DevTools Resources

- **Official Documentation**: https://developer.chrome.com/docs/devtools/
- **Network Tab Guide**: https://developer.chrome.com/docs/devtools/network/
- **Lighthouse Documentation**: https://developer.chrome.com/docs/lighthouse/
- **CSP Reference**: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- **Performance Metrics**: https://web.dev/metrics/

---

## Security Testing Tools

### Semgrep (Static Analysis)

Already documented in Development Tools section above. Key for security-focused code scanning.

### OWASP ZAP (Dynamic Analysis)

**Purpose**: Web application security scanner for finding vulnerabilities

**Key Features**:
- Automated vulnerability scanning
- Active and passive scanning modes
- API security testing
- Authentication testing
- OWASP Top 10 coverage

**Usage**:
```bash
# Run ZAP baseline scan (passive)
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://cwe.crashedmind.com \
  -r zap-report.html

# Run full scan (active)
docker run -t owasp/zap2docker-stable zap-full-scan.py \
  -t https://staging-cwe.crashedmind.com \
  -r zap-full-report.html
```

### Browser Security Headers Checker

Use Chrome DevTools Network tab to verify security headers:
- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security: max-age=31536000`
- `Referrer-Policy: strict-origin-when-cross-origin`
