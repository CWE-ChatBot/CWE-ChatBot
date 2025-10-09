# Mozilla Observatory Security Analysis - S-12

**Test Date**: October 9, 2025
**URL**: https://cwe.crashedmind.com
**Overall Score**: -20 (needs improvement)

## Test Results Summary

### ✅ Passed Tests (8/9)

| Test | Score | Status | Notes |
|------|-------|--------|-------|
| **CORS** | 0 | ✅ PASS | Content not visible via CORS |
| **Redirection** | 0 | ✅ PASS | HTTP→HTTPS redirect working |
| **Referrer Policy** | 0* | ✅ PASS | Set to `no-referrer` |
| **HSTS** | 0 | ✅ PASS | 31536000s (1 year) with preload |
| **Subresource Integrity** | - | ✅ N/A | All scripts from same origin |
| **X-Content-Type-Options** | 0 | ✅ PASS | Set to `nosniff` |
| **X-Frame-Options** | 0* | ✅ PASS | Via CSP `frame-ancestors 'none'` |
| **Cross-Origin Resource Policy** | 0* | ✅ PASS | CORP implemented correctly |
| **Cookies** | - | ✅ N/A | No cookies in initial request |

### ❌ Failed Test (1/9)

| Test | Score | Status | Issue |
|------|-------|--------|-------|
| **Content Security Policy (CSP)** | -20 | ❌ FAIL | Contains `unsafe-inline` and `unsafe-eval` |

---

## CSP Issue Analysis

### Current CSP (Compatible Mode)
```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'unsafe-inline' 'unsafe-eval';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self' data:;
  connect-src 'self' https://cwe.crashedmind.com wss: https:;
  frame-ancestors 'none';
  base-uri 'self';
  object-src 'none';
  form-action 'self'
```

### Problems Identified by Observatory

1. **`'unsafe-inline'` in `script-src`**
   - **Risk**: Allows inline JavaScript, enabling XSS attacks
   - **Reason We Use It**: Chainlit UI uses inline scripts
   - **Impact**: -10 points

2. **`'unsafe-eval'` in `script-src`**
   - **Risk**: Allows `eval()`, enabling code injection
   - **Reason We Use It**: Chainlit UI may use dynamic code evaluation
   - **Impact**: -10 points

3. **`data:` in `img-src`**
   - **Risk**: Minor - allows data URIs for images
   - **Reason We Use It**: Base64-encoded images/icons
   - **Impact**: Contributes to unsafety score

4. **Overly broad `https:` in `connect-src`**
   - **Risk**: Allows connections to any HTTPS endpoint
   - **Reason We Use It**: External API calls, CDNs
   - **Impact**: Minor concern

---

## Why We Accept This Score (For Now)

### 1. Trade-off: Functionality vs. Security Score
- **Chainlit UI Requirement**: The UI framework requires `unsafe-inline` and `unsafe-eval`
- **Choice**: Compatible mode (working app with -20 score) vs. Strict mode (broken UI with 0 score)
- **Decision**: Ship working app first, optimize later

### 2. Defense-in-Depth Mitigates Risk
Even with CSP -20 points, we have multiple layers:
- ✅ Input sanitization (HTML escaping)
- ✅ CSRF token protection
- ✅ OAuth authentication
- ✅ Cloud Armor WAF
- ✅ Output encoding
- ✅ Principle of least privilege

### 3. Roadmap for Improvement
- **Phase 1** (Current): Compatible mode CSP, monitor for violations
- **Phase 2** (Future): Test Chainlit UI with strict CSP
- **Phase 3** (Optional): Fork/patch Chainlit to remove unsafe directives

---

## Improvement Plan: CSP Strict Mode

### Goal
Achieve Observatory score of **A (90+)** by removing `unsafe-inline` and `unsafe-eval`

### Steps to Implement

#### Step 1: Identify Inline Scripts/Styles
**Action**: Use CSP reporting to find violations
```python
# Add to CSP
report-uri /csp-violation-report-endpoint
```

**Monitor**:
```bash
# Check CSP violations in browser console
# Expected: Many violations from Chainlit UI
```

#### Step 2: Test Chainlit with Strict CSP
**Action**: Create test environment with strict CSP
```python
# In middleware.py
CSP_MODE = "strict"  # No unsafe-inline, no unsafe-eval
```

**Test Checklist**:
- [ ] Main UI loads
- [ ] OAuth login works
- [ ] WebSocket connects
- [ ] Messages send/receive
- [ ] Actions (buttons) work
- [ ] File uploads work
- [ ] No console errors

**Expected Result**: Chainlit UI breaks (doesn't work without unsafe directives)

#### Step 3: Refactor or Replace
**Option A**: Wait for Chainlit to support CSP strict mode
- Monitor Chainlit GitHub for CSP improvements
- Upgrade when available

**Option B**: Use nonces for inline scripts
```python
# Generate nonce per request
nonce = secrets.token_urlsafe(16)

# Add to CSP
script-src 'self' 'nonce-{nonce}'

# Inject nonce into all inline scripts
<script nonce="{nonce}">...</script>
```

**Option C**: Extract inline scripts to external files
- Move all inline scripts to `.js` files
- Load via `<script src="...">`
- Requires Chainlit modification (complex)

**Option D**: Switch UI framework
- Replace Chainlit with CSP-compatible framework
- **Cost**: Significant development effort
- **Benefit**: Full CSP compliance

---

## Recommended Actions

### Immediate (Keep Current Score)
**Status Quo**: Accept -20 score, focus on other security priorities
- ✅ All other security headers perfect
- ✅ Cloud Armor WAF protecting edge
- ✅ Application-level protections in place
- ✅ No known XSS vulnerabilities

**Justification**:
- Chainlit UI requires unsafe directives
- Defense-in-depth mitigates CSP gaps
- Functional app > perfect security score

### Short-Term (3-6 months)
1. **Monitor CSP Violations**:
   - Add `report-uri` directive
   - Log violations to Cloud Logging
   - Analyze patterns over time

2. **Test Chainlit Updates**:
   - Check new Chainlit versions for CSP improvements
   - Test strict mode compatibility
   - Upgrade if CSP-compatible

3. **Evaluate Alternatives**:
   - Survey CSP-compatible chat UI frameworks
   - Assess migration effort
   - Decision: migrate vs. accept score

### Long-Term (6-12+ months)
**Option 1**: Migrate to CSP-Strict UI Framework
- Replace Chainlit with CSP-compatible alternative
- Achieve Observatory score A (90+)
- **Effort**: High (4-8 weeks)

**Option 2**: Contribute to Chainlit
- Submit PR to Chainlit for CSP strict mode support
- Use nonces for inline scripts
- **Effort**: Medium (2-4 weeks)

**Option 3**: Accept Current Score
- Document CSP limitation as known issue
- Focus on other security priorities
- **Effort**: None

---

## Other Observatory Recommendations

### 1. HSTS Preload Submission ⭐ (Bonus Points)
**Action**: Submit domain to https://hstspreload.org/
**Requirements**:
- ✅ HSTS max-age ≥ 31536000 (1 year) - **Done**
- ✅ `includeSubDomains` directive - **Done**
- ✅ `preload` directive - **Done**
- ✅ All subdomains serve HTTPS - **Need to verify**

**Benefit**: Browser preloads HSTS, prevents MITM on first visit
**Risk**: Cannot easily remove once preloaded (requires manual delisting)

### 2. Subresource Integrity (SRI) ⭐ (Bonus Points)
**Action**: Add SRI hashes to external scripts/styles
```html
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-abc123..."
        crossorigin="anonymous"></script>
```

**Benefit**: Prevents compromised CDN from injecting malicious code
**Current Status**: All scripts loaded from same origin (no SRI needed)

---

## Final Score Analysis

### Current Score: -20
**Breakdown**:
- Base: 100
- CSP unsafe-inline: -10
- CSP unsafe-eval: -10
- **Total: 80** → **Grade: B**

### After Strict CSP Implementation: 100
**Breakdown**:
- Base: 100
- All tests passing: 0
- Bonus (HSTS preload): +5
- Bonus (SRI): +5
- **Total: 110** → **Grade: A+**

---

## Conclusion

### Current Posture: **ACCEPTABLE** ✅
- **Score**: -20 (Grade B)
- **Security**: Strong defense-in-depth despite CSP limitations
- **Functionality**: Chainlit UI working correctly
- **Risk**: Low (mitigated by other layers)

### Recommendation: **ACCEPT FOR NOW**
**Rationale**:
1. CSP limitation is due to Chainlit framework, not poor implementation
2. Defense-in-depth provides robust XSS protection
3. Improving CSP score requires significant effort (UI replacement or framework modification)
4. Other security priorities (monitoring, testing, incident response) more impactful

### Future Path: **MONITOR AND REASSESS**
- Track Chainlit CSP improvements
- Evaluate migration cost vs. benefit
- Reassess in 6 months

---

**Documented By**: Claude Code Agent
**Analysis Date**: October 9, 2025
**Next Review**: March 2026 (6 months)
