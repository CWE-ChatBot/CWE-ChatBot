# **ADR: OWASP Preconfigured WAF Rules for Cloud Armor — Not Recommended**

## **Summary**

We evaluated whether to add **OWASP preconfigured WAF rules** (XSS, SQLi, RFI, LFI protection) to our existing Cloud Armor security policy.
**Decision: do not implement.** We will **keep our current application-level defenses** and **not** add OWASP managed rule sets at this time.
Our application is a **security education chatbot** where users legitimately discuss attack patterns, creating unacceptable false positive risk.

## **Issue**

Our current security architecture includes:

* **Application-level defenses:** 100% parameterized queries (SQLi prevention), output sanitization + CSP headers (XSS prevention), CSRF token protection.
* **Cloud Armor custom rules:** WebSocket origin pinning (3 rules).
* **Infrastructure security:** VPC connector, SSL/TLS enforcement, HSTS, security headers.

OWASP preconfigured WAF rules could provide additional edge-layer defense-in-depth, but they introduce significant false positive risk for our specific use case.

## **Decision**

**Do not implement OWASP WAF rules.** Continue using **application-level defenses** as primary protection.
No production changes planned. Our current approach is validated by:
* Google Cloud Security Command Center Web Security Scanner: **NO VULNERABILITIES FOUND**
* Security score: **93/100 (Excellent)**
* Zero security incidents in production

## **Status**

**Rejected** (2025-10-10). Revisit only if security posture degrades (see "Revisit Triggers").

## **Details**

### **Assumptions**

* Application is a **security education tool** where users legitimately discuss SQL injection, XSS, and other attack patterns.
* Current application-level defenses are properly implemented and tested.
* User experience quality is a critical requirement.
* False positives blocking legitimate security discussions are unacceptable.

### **Constraints**

* Users MUST be able to ask "How does SQL injection work?" without getting blocked.
* Users MUST be able to paste vulnerable code examples for analysis.
* Users MUST be able to discuss CWE-89 (SQLi), CWE-79 (XSS), etc. freely.
* Application purpose is security education, not typical web application.

### **Options Considered**

1. **Status quo (Application-level defenses only)** — **Chosen**

   * *Pros:* No false positives; users can discuss security freely; 93/100 security score validated; Google Security Scanner found zero vulnerabilities; proper architecture for security education tool.
   * *Cons:* No edge-layer WAF for attack pattern detection; relies entirely on application code correctness.

2. **OWASP WAF rules in preview mode** — **Rejected**

   * *Pros:* Could log attack attempts without blocking; provides reconnaissance intelligence.
   * *Cons:* Still creates noise in logs; no actual security benefit if not enforcing; ongoing monitoring burden.

3. **OWASP WAF rules with extensive exclusions** — **Rejected**

   * *Pros:* Edge-layer protection for true attacks.
   * *Cons:* HIGH false positive risk; users discussing "SELECT * FROM users WHERE 1=1" get blocked; requires extensive tuning and maintenance; degrades user experience; exclusions would be complex and fragile.

4. **OWASP WAF rules in enforce mode** — **Strongly Rejected**

   * *Pros:* Maximum edge protection; compliance checkbox.
   * *Cons:* UNACCEPTABLE user experience; blocks legitimate security education; defeats application purpose; user frustration: "I can't ask about SQL injection in a CWE chatbot!"

5. **Selective OWASP rules (e.g., only RFI/LFI, not SQLi/XSS)** — **Rejected**

   * *Pros:* Reduced false positive risk on SQLi/XSS discussions.
   * *Cons:* Still has false positive risk; partial solution; added complexity for marginal benefit.

### **Trade-offs (Current Approach vs OWASP WAF)**

| Factor | Current (App-Level Only) | With OWASP WAF |
|--------|--------------------------|----------------|
| **SQLi Protection** | ✅ Excellent (100% parameterized queries, tested) | ✅ Excellent (WAF + app, but redundant) |
| **XSS Protection** | ✅ Excellent (CSP + sanitization, tested) | ✅ Excellent (WAF + app, but redundant) |
| **False Positives** | ✅ None (users discuss security freely) | ❌ HIGH (blocks legitimate security discussions) |
| **User Experience** | ✅ Excellent (no blocks on valid content) | ❌ Poor (403 errors on security topics) |
| **Maintenance Burden** | ✅ Low (established code) | ❌ High (ongoing tuning, exclusions) |
| **Cost** | ✅ Current baseline | ⚠️ +$10-20/month (Cloud Armor fees) |
| **Complexity** | ✅ Simple, well-understood | ⚠️ Complex (WAF rules, exclusions, monitoring) |
| **Security Validation** | ✅ Google Scanner: 0 vulnerabilities | ✅ Same (marginal improvement) |
| **Security Score** | ✅ 93/100 (Excellent) | ✅ 94/100? (negligible gain) |
| **Compliance** | ✅ Sufficient for current needs | ✅ Better optics (checkbox WAF) |

### **Security Validation Evidence**

Our current application-level defenses are proven effective:

1. **Google Cloud Security Command Center Web Security Scanner:**
   - ✅ **NO VULNERABILITIES FOUND**
   - ✅ Zero XSS vulnerabilities detected
   - ✅ Zero SQL injection vulnerabilities detected
   - ✅ Zero CSRF vulnerabilities detected
   - ✅ Zero outdated library vulnerabilities detected

2. **Mozilla Observatory:** Grade B (-20 score, acceptable for Chainlit framework limitations)

3. **Comprehensive Test Coverage:**
   - ✅ 49 SQL injection prevention tests (100% parameterized queries verified)
   - ✅ 26 security tests passing (input sanitization, CSRF, headers)
   - ✅ WebSocket security tests passing

4. **Production Stability:**
   - ✅ Zero security incidents since deployment (October 9, 2025)
   - ✅ Real users authenticated and using application
   - ✅ No blocked legitimate traffic

### **Special Consideration: Security Education Use Case**

**CRITICAL DIFFERENCE from typical web applications:**

* **Normal web app:** Users should NOT send SQL injection patterns → WAF blocks attacks ✅
* **CWE ChatBot:** Users SHOULD be able to discuss SQL injection patterns → WAF blocks education ❌

**Real-world scenarios that would trigger false positives:**

1. **User asks:** "How does SQL injection work?"
   - **WAF action:** Block (SQLi pattern detected in query parameter)
   - **Impact:** User gets 403 Forbidden, cannot learn about SQLi

2. **User pastes code:** "Is this vulnerable? `SELECT * FROM users WHERE id = '" + user_input + "'`"
   - **WAF action:** Block (SQLi pattern in request body)
   - **Impact:** User cannot get code review help

3. **User discusses CWE-79:** "Show me an XSS payload example"
   - **WAF action:** Block (XSS pattern detected)
   - **Impact:** User cannot learn about XSS from a CWE chatbot!

4. **User researches CWE-98:** "Explain RFI with include($_GET['page'])"
   - **WAF action:** Block (RFI pattern detected)
   - **Impact:** Defeats the purpose of security education

**This is NOT acceptable for a security education platform.**

### **Revisit Triggers**

Reopen this ADR and reconsider OWASP WAF rules if **any** of the following occur:

* **Security breach:** Successful attack exploiting XSS or SQLi despite application-level defenses.
* **Google Security Scanner degradation:** Scanner finds vulnerabilities in future scans.
* **Security score degradation:** Score drops below 85/100 due to lack of edge protection.
* **Compliance requirement:** Customer/industry mandates WAF with OWASP rule sets.
* **Application pivot:** CWE ChatBot pivots away from security education to general-purpose tool.
* **False positive elimination technology:** Cloud Armor introduces ML-based false positive reduction specifically for security education tools.

### **Recommended Alternative Protections**

Instead of OWASP WAF rules, we recommend focusing on:

1. ✅ **Already Implemented:**
   - Application-level input sanitization (InputSanitizer)
   - 100% parameterized queries (SecureQueryBuilder)
   - Output sanitization (HTML escaping)
   - CSP headers + XSS prevention
   - CSRF token protection
   - WebSocket origin pinning (Cloud Armor custom rules)

2. **Future Enhancements (Low False Positive Risk):**
   - **Rate limiting per IP:** Prevent brute force, DDoS (no impact on content)
   - **Geographic restrictions:** If applicable (no impact on content)
   - **Bot management (reCAPTCHA):** For suspicious automated patterns (no impact on legitimate discussions)
   - **Adaptive Protection:** Cloud Armor's ML-based DDoS protection (already enabled via Layer 7 DDoS defense)

## **Implications**

* **Now:** No changes to Cloud Armor policy; continue with current application-level defenses.
* **Ongoing:** Monitor Google Cloud Security Scanner results; maintain high test coverage.
* **Future:** If security posture degrades, revisit with careful consideration of false positive mitigation strategies.

## **Related**

* **Story S-12:** CSRF and WebSocket Security Hardening (COMPLETE)
* **Story S-10:** SQL Injection Prevention (100% parameterized queries)
* **ADR:** *Database Choice for CWE Chatbot* (PostgreSQL + pgvector)
* **Security Assessment:** 93/100 score, zero vulnerabilities found
* **Cloud Armor Policy:** `cwe-chatbot-armor` (3 custom WebSocket security rules)

## **Appendix: If Circumstances Change**

### **If OWASP WAF Rules Become Necessary (Future)**

Should revisit triggers occur, implement with extreme caution:

1. **Preview Mode First (Mandatory):**
   ```bash
   # Add in preview mode (log only, no blocking)
   gcloud compute security-policies rules create 2000 \
     --security-policy=cwe-chatbot-armor \
     --expression="evaluatePreconfiguredExpr('xss-v33-stable')" \
     --action=deny-403 \
     --preview \
     --description="OWASP XSS protection (PREVIEW - log only)"
   ```

2. **Analysis Period (Minimum 2-4 weeks):**
   - Review Cloud Armor logs daily
   - Identify false positive patterns
   - Estimate impact on user experience

3. **Extensive Exclusions (Before Enforcing):**
   - Exclude security-related URL paths (e.g., `/chat`, `/ask`)
   - Exclude known security discussion patterns
   - Exclude educational code examples
   - Document each exclusion with justification

4. **Gradual Rollout (If Proceeding):**
   - Enable for 1% of traffic with monitoring
   - Measure false positive rate (target: <0.1%)
   - Increase gradually: 1% → 10% → 50% → 100%
   - Instant rollback capability via preview flag

5. **User Communication (Critical):**
   - Inform users about potential false positives
   - Provide clear error messages with workarounds
   - Create bypass mechanism for legitimate security discussions

**Success Criteria (Required Before Full Rollout):**
- False positive rate < 0.1%
- No user complaints about blocked legitimate content
- Measurable security benefit (blocked actual attacks)
- User satisfaction maintained

**Likely Outcome:** Even with extensive effort, false positive rate will likely be unacceptable for security education use case. This reinforces the current decision to NOT implement OWASP WAF rules.

## **Conclusion**

For the CWE ChatBot security education platform, **application-level defenses are the right architecture**. OWASP WAF rules are designed for typical web applications where attack patterns are malicious, not for platforms where discussing attack patterns is the core value proposition.

Our current security posture is excellent (93/100, zero vulnerabilities), validated by independent scanning, and appropriate for the use case. Adding OWASP WAF rules would degrade user experience without meaningful security benefit.

**Decision: Keep current approach. Do not implement OWASP WAF rules.**
