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

## Process for Accepting New Risks

1. **Document the vulnerability** with full details (CVE, GHSA, severity)
2. **Assess actual impact** to this specific application
3. **Identify mitigations** currently in place
4. **Justify acceptance** with clear reasoning
5. **Set expiration date** for mandatory re-review
6. **Add to pip-audit ignore list** in `.github/workflows/quality.yml` and `.pre-commit-config.yaml`
7. **Get approval** from security reviewer
8. **Update this document** with all details
