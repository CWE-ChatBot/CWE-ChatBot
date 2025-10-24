# Accepted Security Risks

This document tracks security vulnerabilities that have been reviewed and explicitly accepted as risks for this project.

## Active Accepted Risks

### GHSA-wj6h-64fc-37mp: ecdsa Minerva Timing Attack

**Vulnerability Details:**
- **Package**: `ecdsa` version 0.19.1 (transitive dependency via `python-jose`)
- **Severity**: Not formally rated (timing attack)
- **CVE**: None assigned
- **GitHub Advisory**: [GHSA-wj6h-64fc-37mp](https://github.com/advisories/GHSA-wj6h-64fc-37mp)

**Description:**
Python-ecdsa is subject to a Minerva timing attack on the P-256 curve. Using `ecdsa.SigningKey.sign_digest()` and timing signatures, an attacker can leak the internal nonce which may allow for private key discovery.

**Impact Scope:**
- ECDSA signatures (signing operations)
- Key generation
- ECDH operations

**NOT Affected:**
- ECDSA signature verification ✓

**Project Maintainer Position:**
The python-ecdsa project considers side-channel attacks out of scope for the project. **There is no planned fix.**

**Why Risk is Accepted:**

1. **Limited Attack Surface**:
   - We use `python-jose` only for **JWT token verification**, not signing
   - The vulnerable signing operations are never exposed in our application
   - Timing attacks require local access to observe signing operation timing

2. **No Fix Available**:
   - Upstream maintainers will not fix (out of scope)
   - No secure alternative version exists
   - Switching libraries would require significant refactoring

3. **Mitigation in Place**:
   - JWT tokens are signed by OAuth providers (Google, GitHub)
   - Our application only verifies signatures, never generates them
   - No user-controlled data flows through the vulnerable code path

4. **Risk Assessment**:
   - **Likelihood**: Very Low (requires local timing attack access to signing operations we don't expose)
   - **Impact**: None (we don't perform signing operations)
   - **Overall Risk**: Minimal

**Expiration Date**: 2026-01-01

**Review Required**: Annual review or when:
- python-jose changes dependencies
- We add JWT signing functionality
- A fix becomes available upstream

**Documented**: 2025-01-XX
**Last Reviewed**: 2025-01-XX
**Next Review**: 2026-01-01

---

### NUCLEI-SRI-001: Missing Subresource Integrity on Chainlit CDN Resources

**Finding Details:**
- **Source**: Nuclei DAST scan (template: `missing-sri.yaml`)
- **Severity**: INFO
- **Classification**: CWE-345 (Insufficient Verification of Data Authenticity)
- **Affected Resources**:
  - Google Fonts: `https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&display=swap`
  - KaTeX: `https://cdn.jsdelivr.net/npm/katex@0.16.22/dist/katex.min.css`

**Description:**
External CSS resources loaded from CDNs lack Subresource Integrity (SRI) attributes. If a CDN is compromised, malicious CSS could be injected into the application.

**Root Cause:**
Chainlit 2.8.0 framework hardcodes CDN links in server-generated HTML before any application code executes. The framework provides no configuration option to:
- Disable CDN resource injection
- Add SRI attributes to injected links
- Use local font hosting instead

**Investigation Performed:**
1. Attempted local font hosting (1.8MB font files in `/public/fonts/`)
2. Deployed to staging and verified with Nuclei scan
3. Confirmed Chainlit injects CDN links regardless of local resources
4. Reviewed Chainlit 2.8.0 configuration options (none available)
5. Assessed alternative solutions (fork framework, strict CSP blocking)

**Why Risk is Accepted:**

1. **Framework Limitation**:
   - Chainlit hardcodes CDN links in server-side HTML generation
   - No configuration option to disable or customize
   - Cannot override without forking framework (high maintenance burden)

2. **Reputable CDN Sources**:
   - Google Fonts: Industry-leading CDN with strong security practices
   - jsDelivr (KaTeX): Well-monitored CDN with SRI support available
   - Both CDNs support SRI hashes (Chainlit simply doesn't use them)

3. **Low Severity**:
   - INFO-level finding (not exploitable vulnerability)
   - Requires CDN compromise (low likelihood)
   - Impact limited to CSS injection (no JavaScript execution)

4. **Ineffective Mitigations**:
   - Local font hosting: Doesn't prevent Chainlit's CDN injection
   - Strict CSP blocking: Breaks application functionality
   - Framework fork: Unsustainable maintenance burden

5. **Risk Assessment**:
   - **Likelihood**: Very Low (requires compromise of Google/jsDelivr infrastructure)
   - **Impact**: Low (CSS-only, no JS execution)
   - **Overall Risk**: Minimal

**Mitigation in Place:**
- Content Security Policy (CSP) restricts other external resources
- Regular dependency updates to track Chainlit releases
- Monitoring for Chainlit feature additions (HTML template customization)

**Expiration Date**: 2026-10-24

**Review Required**: Annual review or when:
- Chainlit adds HTML template customization
- Major version upgrade of Chainlit framework
- CDN compromise reported for Google Fonts or jsDelivr

**Documented**: 2025-10-24
**Last Reviewed**: 2025-10-24
**Next Review**: 2026-10-24

**References**:
- Nuclei scan results: `tests/nuclei/results.md`
- Investigation notes: `apps/chatbot/public/custom.css` (comments)
- OWASP SRI guidance: https://owasp.org/www-community/controls/Subresource_Integrity

---

## Process for Accepting New Risks

1. **Document the vulnerability** with full details (CVE, GHSA, severity)
2. **Assess actual impact** to this specific application
3. **Identify mitigations** currently in place
4. **Justify acceptance** with clear reasoning
5. **Set expiration date** for mandatory re-review
6. **Add to pip-audit ignore list** in `.github/workflows/quality.yml` and `.pre-commit-config.yaml`
7. **Get approval** from security reviewer
8. **Update this document** with all details
