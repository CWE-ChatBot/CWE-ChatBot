# CWE Chatbot Volunteer Testing Guide (Early Access)

**Welcome!** Thank you for helping improve the CWE Chatbot. This guide will help you provide the most valuable feedback.

---

## Quick Start (5 minutes)

1. **Access the chatbot**: [Your deployment URL here]
2. **Log in** using Google or GitHub OAuth
3. **Try 3-5 real-world tasks** from your daily work
4. **Complete feedback form**: [Form URL here]
5. **Estimated time**: 15-20 minutes

---

## Before You Start

### ⚠️ **Important: Centrally-Hosted Evaluation Only**

**This evaluation uses a centrally-hosted (cloud) deployment**:
- All volunteers test the same shared instance
- Self-hosted deployment is NOT available for this evaluation
- Bring Your Own LLM (BYOLLM) is NOT available for this evaluation
- The form asks about deployment PREFERENCES to gauge future interest

### ⚠️ **Data Privacy Notice**

- **Avoid confidential data**: Anonymize code snippets, vulnerability descriptions, and internal info
- **Cloud logging**: Assume all interactions are logged in Google Cloud
- **No secrets**: Never paste API keys, passwords, or credentials in prompts

### ✅ **What to Test**

The chatbot is designed for **5 key user roles** (per PRD user scenarios). Pick tasks matching **your real-world workflow**:

| Your Role | Suggested Tasks |
|-----------|-----------------|
| **PSIRT Member** | Map bug reports to CWEs, create advisory language, assess impact, prioritize vulnerabilities |
| **Developer** | Analyze code snippets, find CWE for vulnerability, get remediation steps, fix bugs |
| **Academic Researcher** | Explore CWE relationships, analyze vulnerability trends, compare weaknesses, research detection methods |
| **Bug Bounty Hunter** | Map exploits to CWEs, validate vulnerability classification, improve reporting accuracy |
| **Product Manager** | Identify common CWE patterns, strategic weakness analysis, resource allocation, prevention strategies |
| **Security Architect** | Design secure systems, evaluate controls, crosswalk to standards (ASVS, NIST) |

---

## Testing Checklist (Complete 3-5 Tasks)

### Task Ideas by Feature

#### 1. **CWE Lookup**
- ✅ "Tell me about CWE-79"
- ✅ "What is Cross-Site Scripting and how is it different from CWE-116?"
- ✅ "List all injection-related CWEs"

#### 2. **CVE → CWE Mapping**
- ✅ Paste a CVE advisory: "Map this CVE to CWEs: [paste CVE description]"
- ✅ "What CWE does CVE-2024-1234 map to?" (use real CVE)

#### 3. **Code Analysis**
- ✅ Paste code snippet: "What CWE does this code violate? [paste anonymized code]"
- ✅ "Find CWE for this SQL injection vulnerability: [paste code]"
- ✅ "Does this code have any CWE weaknesses? [paste code]"

#### 4. **Crosswalks & Controls**
- ✅ "Map CWE-79 to ASVS controls"
- ✅ "What NIST controls address CWE-89?"
- ✅ "How does CWE-502 relate to OWASP Top 10?"

#### 5. **Mitigation Guidance**
- ✅ "How do I fix CWE-79 in Django?"
- ✅ "Give me a remediation checklist for SQL injection"
- ✅ "What's the secure coding pattern to prevent CWE-22?"

#### 6. **Training Content**
- ✅ "Explain CWE-89 to a junior developer"
- ✅ "Write a 2-paragraph training blurb on CSRF for developers"
- ✅ "What's the difference between authentication and authorization? (CWE context)"

#### 7. **Export or Share**
- ✅ "Export this conversation as Markdown"
- ✅ "Share this CWE mapping as JSON"

---

## What to Look For

### ✅ **Good Signs**
- Accurate CWE IDs (check against https://cwe.mitre.org)
- Citations to official CWE entries
- Confidence scores on suggestions (if shown)
- Graceful handling when you provide incomplete info
- Context remembered across follow-up questions
- Response time under 3 seconds

### 🚩 **Red Flags (Please Report!)**
- **Hallucinations**: Made-up CWE IDs, incorrect names, false relationships
- **Wrong mappings**: CVE mapped to unrelated CWE
- **Missing context**: Chatbot forgets previous questions
- **Slow responses**: Over 5 seconds for simple queries
- **Errors/crashes**: Timeouts, 500 errors, blank responses
- **Security concerns**: Data leakage, unauthorized access

---

## Feedback Form Tips

### Section 1: About You
- **Deployment preference**: This asks what you would PREFER (centrally-hosted vs. self-hosted) for future use
  - Note: This evaluation only offers centrally-hosted deployment
  - Choose "Prefer self-hosted" if you would want to run on your own infrastructure
  - Explain why if you prefer self-hosted (e.g., data residency, compliance, control)

### Section 2: Core Tasks
- **ALL OPTIONAL**: Fill out 3-5 tasks (quality over quantity)
- **Exact prompts**: Copy-paste your actual queries (anonymize as needed)
- **Confidence scores**: Look for numbers/percentages next to CWE suggestions
- **Incomplete info handling**: Note if chatbot said "not enough information" or asked clarifying questions

### Section 3: Performance
- **Latency**: Choose time bucket based on typical response (not fastest/slowest)
- **Stability**: Report "Some issues" even for 1-2 errors (we want to know!)

### Section 4: Hallucinations
**CRITICAL**: If you find wrong answers, please log with this template:
- **(a) Your prompt**: [exact question]
- **(b) Expected source**: [link to official CWE entry or authoritative source]
- **(c) Model output**: [what chatbot said]
- **(d) Impact**: Low (minor error) / Med (misleading) / High (dangerous misinfo)

**Example**:
```
(a) "What is CWE-79?"
(b) https://cwe.mitre.org/data/definitions/79.html (Improper Neutralization of Input During Web Page Generation)
(c) Chatbot said "CWE-79 is SQL Injection"
(d) Impact: HIGH (completely wrong weakness type)
```

### Section 5: Prioritization
- **P0 = Blocker**: Must fix before General Availability
- **P1 = High**: Important, needed soon
- **P2 = Medium**: Nice to have
- **P3 = Low**: Future enhancement

Focus on **2-3 items max** (quality over quantity). If you have many suggestions, use "If limited to 3 improvements" question instead.

---

## Common Scenarios

### Scenario 1: "I don't know what CWE to test"
**Try these**:
- CWE-79 (XSS) — Very common
- CWE-89 (SQL Injection) — High impact
- CWE-22 (Path Traversal) — Good for code analysis
- CWE-502 (Deserialization) — Complex topic
- CWE-862 (Missing Authorization) — Real-world scenario

### Scenario 2: "Chatbot gave me 10 CWE suggestions"
**What to check**:
- Are they prioritized (numbered 1-10)?
- Do they have confidence scores (e.g., "85% confidence")?
- Are top 3 more relevant than bottom 3?

### Scenario 3: "I provided incomplete code snippet"
**What to expect**:
- Chatbot should say something like "I need more context" or "Not enough information to determine CWE"
- It might ask clarifying questions
- It should NOT guess with high confidence

### Scenario 4: "Response is too technical for me"
**Try asking**:
- "Explain this in simpler terms"
- "I'm a novice, can you rephrase?"
- Then report if chatbot adapted explanation in the form

---

## Technical Issues?

### Authentication Problems
- **OAuth error**: Check redirect URIs in Google/GitHub console
- **Session timeout**: Report in "Authentication issues" field
- **Can't log in**: Email [support contact]

### Performance Problems
- **Slow responses (>5 sec)**: Note specific query in form
- **Timeouts**: Report in "Stability" section
- **Errors**: Copy full error message to "Details on stability issues"

### Data Privacy Concerns
- **Worried about confidentiality**: Anonymize all sensitive data before testing; this evaluation uses cloud logging
- **GDPR/compliance questions**: Indicate in "deployment preference" if self-hosted is required for your use case
- **Found data leakage**: Report immediately to [security contact]

---

## After Submitting Feedback

### What Happens Next?
1. **Triage (within 1 week)**: We review P0/P1 items
2. **Follow-up (if needed)**: We may email for clarification on critical issues
3. **Mid-November**: Results summary shared with volunteers
4. **GA Release (Q4 2025)**: Incorporating your feedback

### Want to Help More?
- **Participate in 15-30 min interview**: Provide your email in the feedback form and we'll reach out
- **Join beta testing**: Email [beta program contact]
- **Contribute to open source**: [GitHub repo link]

---

## Questions or Problems?

- **Form issues**: Email [form admin contact]
- **Chatbot bugs**: Report via "Hallucinations or wrong answers" field
- **General questions**: [Project contact]

---

## Thank You!

Your feedback will directly influence the CWE Chatbot's development priorities. Every hallucination report, feature suggestion, and performance note helps us build a better tool for the cybersecurity community.

**Target**: 20-30 volunteer responses by mid-November 2025

---

## Quick Reference: Form Sections

1. **About You** (8 questions, 4 required) — 2 min
2. **Expectations** (6 questions, 3 required) — 2 min
3. **Core Tasks** (up to 5 tasks, all optional) — 8-10 min
4. **Usability** (1 grid, required) — 1 min
5. **Accuracy** (3 questions, all optional) — 1 min
6. **Performance** (6 questions, 3 required) — 2 min
7. **Features** (7 questions, 1 required) — 2 min
8. **Value** (6 questions, 2 required) — 2 min
9. **Prioritization** (up to 5 items, all optional) — 2 min

**Total**: ~15-20 minutes (complete 3-5 core tasks for best results)
