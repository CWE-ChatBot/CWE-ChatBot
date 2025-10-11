# Debug Issue D1: CSP Blocking Chainlit External CSS

**Date**: 2025-10-10 (Initial fix) → 2025-10-11 (Complete fix)
**Status**: ✅ FULLY RESOLVED
**Related**: Story S-12 (CSP Implementation)
**Final Deployment**: cwe-chatbot-00183-jfc (2025-10-11 08:34 UTC)

## Problem Observed

Browser console (Chrome DevTools) showed CSS resources blocked by Content Security Policy:

```
(blocked:csp)
Request URL: https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&display=swap
Referrer Policy: no-referrer

(blocked:csp)
Request URL: https://cdn.jsdelivr.net/npm/katex@0.16.22/dist/katex.min.css
Referrer Policy: no-referrer
```

**Symptoms:**
- Chainlit UI rendering without proper fonts (Inter font family missing)
- Math rendering (KaTeX) CSS not loading
- Visual appearance degraded

## Root Cause Analysis

The CSP implemented in Story S-12 had overly restrictive `style-src` and `font-src` directives:

**Original CSP (apps/chatbot/src/security/middleware.py):**
```python
"style-src 'self' 'unsafe-inline'; "
"font-src 'self' data:; "
```

**Issue:** Only allowed CSS from same origin + inline styles. Blocked external CSS from:
- `fonts.googleapis.com` - Google Fonts (Inter font family used by Chainlit)
- `cdn.jsdelivr.net` - KaTeX CSS for math rendering
- `fonts.gstatic.com` - Google Fonts static assets

## Solution Implemented

Updated CSP to allow trusted external CSS/font sources AND restore required Chainlit directives:

### Phase 1: Initial Fix (2025-10-10)
**Commit:** `575adc9` - Fix CSP to allow Chainlit external CSS and fonts

```python
"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
"font-src 'self' data: https://fonts.gstatic.com; "
```

### Phase 2: Additional Issues Found (2025-10-11)

After deployment, discovered two additional CSP issues:

1. **KaTeX Fonts Still Blocked** (commit `f6b9246`)
   - KaTeX fonts (.woff2, .ttf) also served from `cdn.jsdelivr.net`
   - Need `cdn.jsdelivr.net` in BOTH `style-src` AND `font-src`

2. **Inline Scripts Blocked** (commit `fa46221`)
   - S-12 removed `'unsafe-inline'` from `script-src` for security
   - But Chainlit 2.8.0 uses inline scripts that can't be externalized
   - Had to restore `'unsafe-inline'` for Chainlit compatibility

### Final CSP (Compatibility+ Mode)
**File Changed:** `apps/chatbot/src/security/middleware.py`

```python
"script-src 'self' 'unsafe-inline' 'unsafe-eval'; "  # Chainlit requires both
"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "  # Google Fonts + KaTeX CSS
"font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; "  # Google Fonts + KaTeX fonts
```

**Key Changes:**
- ✅ Added `https://cdn.jsdelivr.net` to `font-src` (for KaTeX fonts)
- ✅ Restored `'unsafe-inline'` to `script-src` (for Chainlit inline scripts)
- ✅ Kept all external CDN sources (Google Fonts, KaTeX)

## Security Analysis

### External CDN Sources ✅ Safe to Allow
All sources are trusted and HTTPS-only:
- **fonts.googleapis.com** - Google's official font service
- **cdn.jsdelivr.net** - Popular open-source CDN with automated security scanning
- **fonts.gstatic.com** - Google's font asset delivery

**No new attack surface:**
- Only CSS and font files allowed (no scripts from CDN)
- HTTPS-only sources (no downgrade attacks)
- Required for Chainlit UI to function properly
- Standard practice for modern web applications

### Unsafe Inline Directives ⚠️ Required Trade-off

**Security Impact of `'unsafe-inline'` in `script-src`:**
- ❌ **Reduces XSS protection**: Allows inline `<script>` tags
- ❌ **Not ideal**: More vulnerable to script injection
- ✅ **Necessary for Chainlit 2.8.0**: Framework uses inline scripts that can't be externalized
- ✅ **Compatibility mode**: This is documented as "Compatibility+ CSP" (not strict)

**Trade-off Decision:**
- **Priority:** Application functionality (Chainlit compatibility)
- **Mitigation:** Other CSP directives still provide protection
- **Alternative:** Use `CSP_MODE=strict` (will break Chainlit)

### Defense-in-Depth Maintained ✅
- ✅ `frame-ancestors 'none'` - Prevents clickjacking
- ✅ `object-src 'none'` - Blocks plugins/embeds
- ✅ `form-action 'self'` - Restricts form submissions
- ✅ `base-uri 'self'` - Prevents base tag injection
- ✅ WebSocket origin pinning - Validates WS connections
- ✅ HSTS, X-Frame-Options, other security headers active

## Testing

### Local Testing
```bash
poetry run chainlit run apps/chatbot/main.py
```

**Verification steps:**
1. Open browser DevTools console
2. Check Network tab for CSS requests
3. Verify no `(blocked:csp)` errors for fonts.googleapis.com or cdn.jsdelivr.net
4. Verify UI renders with proper Inter font
5. Test math rendering (if KaTeX is used)

### Production Testing
After deployment:
```bash
# Deploy
gcloud builds submit --config=apps/chatbot/cloudbuild.yaml

# Verify
curl -I https://cwe.crashedmind.com/ | grep -i "content-security-policy"
```

**Expected CSP header:**
```
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' https://cwe.crashedmind.com wss://cwe.crashedmind.com; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'
```

## Observations

1. **CSP Evolution**: S-12 initially implemented strict CSP without accounting for Chainlit's external dependencies
2. **Compatibility vs Security**: Need to balance security strictness with framework requirements
3. **CDN Trust**: Modern web apps commonly trust well-established CDNs (Google, jsDelivr)
4. **HTTPS Requirement**: All external sources must use HTTPS to maintain security

## Resolution Status

✅ **All Issues Fixed and Deployed**

### Deployment History
1. **2025-10-10**: Initial fix (commit `575adc9`) - Google Fonts + KaTeX CSS
2. **2025-10-11**: KaTeX fonts fix (commit `f6b9246`) - Added `cdn.jsdelivr.net` to `font-src`
3. **2025-10-11**: Inline scripts fix (commit `fa46221`) - Restored `'unsafe-inline'` to `script-src`
4. **2025-10-11**: Final deployment - cwe-chatbot-00183-jfc

### Verification Complete ✅
```bash
# CSP Header Check
curl -I https://cwe.crashedmind.com/ | grep -i "content-security-policy"

# Result: All directives present and correct
script-src 'self' 'unsafe-inline' 'unsafe-eval';
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net;
font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net;
```

### Browser Console Verification ✅
After hard refresh (Ctrl+Shift+R):
- ✅ No `blocked:csp` errors for Google Fonts
- ✅ No `blocked:csp` errors for KaTeX CSS
- ✅ No `blocked:csp` errors for KaTeX fonts (30+ files)
- ✅ No `blocked:csp` errors for inline scripts
- ✅ UI renders with proper Inter font
- ✅ Math rendering works with KaTeX

### Related Fixes
- **D4 Issue #2**: /logo 404 errors also fixed (see [CSP-AND-LOGO-FIXES-2025-10-11.md](../CSP-AND-LOGO-FIXES-2025-10-11.md))

## Lessons Learned

1. **CSP requires iterative refinement**: Initial fix wasn't complete
2. **Test in actual browser**: DevTools reveals CSP issues not visible in server logs
3. **Font loading is separate from CSS**: `style-src` ≠ `font-src`
4. **Framework constraints**: Chainlit 2.8.0 requires `'unsafe-inline'` - trade-off accepted
5. **Document security decisions**: Clear justification for each `'unsafe-*'` directive
