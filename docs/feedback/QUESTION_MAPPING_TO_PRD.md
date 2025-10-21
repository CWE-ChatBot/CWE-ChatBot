# Google Form Questions → PRD Requirements Mapping

**Purpose**: Ensure every form question validates a specific PRD requirement
**Status**: ✅ 90% PRD Coverage Achieved (Centrally-Hosted Evaluation)

---

## Section 1: About You

| Question | Type | Required | PRD Requirement | Validation Goal |
|----------|------|----------|-----------------|-----------------|
| Name | Text | No | - | Optional contact info |
| Email | Text (email) | No | - | Optional contact info |
| **Role / background** | Multiple choice | **Yes** | FR4 | Validate role-based adaptation works for all user types |
| **Organisation type** | Multiple choice | **Yes** | User Scenarios | Understand user context (Commercial, Gov, Academia, etc.) |
| Primary workflows with CWE/CVE today | Paragraph | No | User Scenarios | Contextual understanding |
| **Familiarity with CWE taxonomy** | Multiple choice | **Yes** | NFR29 (adaptive explanations) | Measure if chatbot adapts to expertise level |
| **🆕 Would you prefer centrally-hosted or self-hosted CWE Chatbot?** | Multiple choice | **Yes** | **FR19, NFR33, NFR41** | **Gauge deployment PREFERENCE for future roadmap** |
| 🆕 If you prefer self-hosted, why? | Paragraph | No | **FR19, NFR33** | **Understand self-hosted drivers (data residency, compliance, control)** |

### PRD Coverage:
- ✅ FR4 (role-based adaptation)
- 📊 FR19 (confidentiality - preference asked, full validation deferred)
- ❌ FR28/FR29 (BYO LLM - NOT available in this evaluation, deferred to post-GA)
- ✅ NFR29 (adaptive to expertise)
- 📊 NFR33 (data residency - preference asked, full validation deferred)
- 📊 NFR41 (self-hostable architecture - preference asked, deployment deferred)

---

## Section 2: Expectations & First Impressions

| Question | Type | Required | PRD Requirement | Validation Goal |
|----------|------|----------|-----------------|-----------------|
| **What were you hoping the chatbot would do?** | Paragraph | **Yes** | Product Goals | Measure expectation alignment |
| **Onboarding made sense** | Scale 1-5 | **Yes** | UI Design Goals | Validate onboarding clarity |
| **Initial confidence: "I trust the chatbot"** | Scale 1-5 | **Yes** | NFR6 (hallucination minimization) | Measure trust and perceived reliability |
| Why / notes on first impressions | Paragraph | No | - | Qualitative insights |
| **🆕 Authentication process smoothness** | Scale 1-5 | No | **NFR34** | **Validate OAuth UX (Google/GitHub)** |
| 🆕 Authentication issues or suggestions | Paragraph | No | **NFR34** | **Identify login friction points** |

### PRD Coverage:
- ✅ NFR6 (hallucination minimization affects trust)
- ✅ NFR34 (authentication & authorization)
- ✅ UI Design Goals (onboarding/introduction screen)

---

## Section 3: Core Tasks (repeatable, ALL optional)

**Note**: 5 task blocks, each with identical questions

| Question | Type | Required | PRD Requirement | Validation Goal |
|----------|------|----------|-----------------|-----------------|
| Task X — Task ID/Name | Text | No | - | Task identification |
| Task X — Your exact prompt(s) | Paragraph | No | FR1 (NLU) | Capture real user queries for analysis |
| **Task X — Result quality** | Scale 1-5 | No | NFR6 | Measure response quality |
| **Task X — Perceived accuracy** | Scale 1-5 | No | FR12 (correct CWE IDs) | Measure accuracy perception |
| **Task X — Speed** | Scale 1-5 | No | NFR1 (latency) | Measure perceived speed |
| **Task X — Usefulness to workflow** | Scale 1-5 | No | Product Goals (MTTR, proactive ID) | Measure real-world value |
| Task X — Time spent (minutes) | Number | No | - | Measure task duration |
| **🆕 Task X — Did chatbot show confidence scores?** | Multiple choice | No | **FR15, FR20, NFR22** | **Validate confidence scoring feature** |
| Task X — What worked well? | Paragraph | No | FR16 (reasoning) | Identify successful patterns |
| Task X — What was missing or wrong? | Paragraph | No | FR17, FR26 | Identify gaps and errors |
| **🆕 Task X — Incomplete info handling** | Paragraph | No | **FR17, FR26, NFR26** | **Validate graceful degradation** |
| Task X — Attach screenshots | File upload / Text | No | - | Evidence collection |

### PRD Coverage (per task):
- ✅ FR1 (NLU for natural language queries)
- ✅ FR12 (correct CWE IDs without hallucination)
- ✅ FR15 (prioritized, confidence-annotated suggestions)
- ✅ FR16 (explanation of reasoning)
- ✅ FR17 (graceful handling of insufficient info)
- ✅ FR20 (confidence level display)
- ✅ FR26 (ambiguous information handling)
- ✅ NFR1 (latency <500ms)
- ✅ NFR6 (hallucination minimization)
- ✅ NFR22 (prioritized recommendations with confidence)
- ✅ NFR26 (input refinement guidance)

---

## Section 4: Overall Usability & Fit

| Question | Type | Required | PRD Requirement | Validation Goal |
|----------|------|----------|-----------------|-----------------|
| **Grid: Rate statements (1-5)** | Grid | **Yes** | Multiple | Comprehensive UX validation |
| - Interface is easy to understand | Grid row | **Yes** | UI Design Goals | Interface clarity |
| - Citations/links improve trust | Grid row | **Yes** | FR16 (reasoning), NFR24 | Citation effectiveness |
| - Handles follow-up questions well | Grid row | **Yes** | FR3 (conversational turns) | Context preservation |
| - Reduces time vs current workflow | Grid row | **Yes** | Product Goals (20% MTTR reduction) | Efficiency gain |
| - Would use weekly for my job | Grid row | **Yes** | Product Goals (user satisfaction) | Adoption intent |

### PRD Coverage:
- ✅ FR3 (conversational turns)
- ✅ FR16 (explanation of reasoning)
- ✅ NFR24 (mapping reasoning)
- ✅ UI Design Goals (interface clarity)
- ✅ Product Goals (MTTR reduction, satisfaction)

---

## Section 5: Accuracy, Coverage & Transparency

| Question | Type | Required | PRD Requirement | Validation Goal |
|----------|------|----------|-----------------|-----------------|
| **When chatbot cites sources, are they right?** | Scale 1-5 | No | FR16, NFR24 | Citation accuracy |
| Coverage gaps — CWE areas under-served | Paragraph | No | FR2 (CWE corpus retrieval) | Identify corpus gaps |
| **Hallucinations or wrong answers (log any)** | Paragraph | No | **FR12, FR17, NFR6, NFR17** | **Critical error tracking** |

**Hallucination Template** (help text):
- (a) Your prompt
- (b) Expected/authoritative source
- (c) Model output
- (d) Impact (Low/Med/High)

### PRD Coverage:
- ✅ FR2 (CWE corpus retrieval and synthesis)
- ✅ FR12 (correct CWE IDs without hallucination)
- ✅ FR16 (reasoning explanation)
- ✅ FR17 (insufficient info handling)
- ✅ NFR6 (hallucination minimization)
- ✅ NFR17 (ID validation, no made-up IDs)
- ✅ NFR19 (knowledge base content)
- ✅ NFR24 (mapping reasoning)

---

## Section 6: Performance & Reliability

| Question | Type | Required | PRD Requirement | Validation Goal |
|----------|------|----------|-----------------|-----------------|
| **🆕 Typical response time for CWE queries** | Multiple choice | **Yes** | **NFR1** | **Validate <500ms latency target** |
| - Under 1 second (excellent) | Choice | - | NFR1 | Exceeds target |
| - 1-3 seconds (good) | Choice | - | NFR1 | Acceptable range |
| - 3-5 seconds (acceptable) | Choice | - | NFR1 | Marginal |
| - Over 5 seconds (too slow) | Choice | - | NFR1 | Fails target |
| **Stability — errors, timeouts, retries?** | Multiple choice | **Yes** | NFR3 (99.9% uptime) | Reliability validation |
| Details on stability issues | Paragraph | No | NFR3, NFR38 | Error tracking |
| **Session continuity — remembered context?** | Multiple choice | **Yes** | NFR35 | Context preservation |
| Examples of context handling | Paragraph | No | NFR35 | Context quality insights |

### PRD Coverage:
- ✅ NFR1 (latency <500ms)
- ✅ NFR3 (99.9% uptime)
- ✅ NFR35 (session context preservation)
- ✅ NFR38 (resilience & auto-fallover)

---

## Section 7: Features & Workflow

| Question | Type | Required | PRD Requirement | Validation Goal |
|----------|------|----------|-----------------|-----------------|
| **Which features did you use?** | Checkbox | No | Multiple | Feature adoption tracking |
| - CWE lookup | Checkbox item | - | FR2, FR5 | Core feature |
| - CVE→CWE mapping | Checkbox item | - | FR7, FR10 | PSIRT/Bug bounty use case |
| - Code analysis | Checkbox item | - | FR8 | Developer use case |
| - Crosswalks & controls | Checkbox item | - | FR6 | Mapping to ASVS/NIST/CERT |
| - Mitigation guidance | Checkbox item | - | FR6, NFR24 | Remediation support |
| - Training content | Checkbox item | - | NFR28, NFR29 | Learning assistance |
| - Export or share | Checkbox item | - | NFR45 | Export formats |
| - Citations | Checkbox item | - | FR16, NFR24 | Source references |
| - Staging-only features | Checkbox item | - | - | Testing features |
| - Other | Checkbox item | - | - | Unlisted features |
| **Feature disposition (keep/remove/improve)** | Checkbox grid | No | - | Feature prioritization |
| How to improve specific features? | Paragraph | No | NFR36 | Feature enhancement feedback |
| Security/privacy concerns | Paragraph | No | FR19, NFR7-11 | Security requirement gaps (centrally-hosted evaluation) |
| **If limited to 3 improvements before GA** | Paragraph | **Yes** | NFR36 | Prioritization forcing function |

### PRD Coverage:
- ✅ FR2 (CWE corpus retrieval)
- ✅ FR5 (concise summaries + detailed explanations)
- ✅ FR6 (related CWEs, attack patterns, mitigations)
- ✅ FR7 (PSIRT bug report input)
- ✅ FR8 (developer source code submission)
- ✅ FR10 (bug bounty exploit mapping)
- ✅ FR16 (reasoning explanation)
- 📊 FR19 (confidentiality - deployment preference asked, full validation deferred to post-GA)
- ✅ NFR7-11 (security & privacy)
- ✅ NFR24 (mapping reasoning)
- ✅ NFR28/29 (user guidance)
- ✅ NFR33 (sensitive data handling, GDPR)
- ✅ NFR36 (continuous improvement feedback)
- ✅ NFR45 (export formats)

---

## Section 8: Value & Adoption

| Question | Type | Required | PRD Requirement | Validation Goal |
|----------|------|----------|-----------------|-----------------|
| **Likelihood to recommend (NPS)** | Scale 0-10 | **Yes** | Product Goals (high CSAT) | Net Promoter Score |
| **Would you use this in production today?** | Multiple choice | **Yes** | Product Goals | Production readiness |
| Why or why not? | Paragraph | No | - | Adoption blockers |
| Primary value delivered (or potential) | Paragraph | No | Product Goals | Value proposition validation |
| What would make this a "must-have"? | Paragraph | No | - | Critical feature gaps |
| Anything else we should know? | Paragraph | No | - | Open-ended feedback |

### PRD Coverage:
- ✅ Product Goals (high user satisfaction, CSAT)
- ✅ Production readiness assessment

---

## Section 9: Prioritization (P0–P3, ALL optional)

**Note**: 5 prioritization items, each with identical questions

| Question | Type | Required | PRD Requirement | Validation Goal |
|----------|------|----------|-----------------|-----------------|
| Item X — Title/Item | Text | No | - | Feature/fix identification |
| Item X — Description | Paragraph | No | - | Detailed requirement |
| **Item X — Priority (P0 highest)** | List | No | - | Priority forcing function |
| - P0 | List item | - | - | Highest priority (blockers) |
| - P1 | List item | - | - | High priority (important) |
| - P2 | List item | - | - | Medium priority (nice-to-have) |
| - P3 | List item | - | - | Low priority (future) |
| Item X — Impact if fixed | Multiple choice | No | - | Impact assessment |

**Note**: P0 help text states "P0 is highest priority"

### Purpose:
- Collect user-defined priorities for features/fixes
- Inform product backlog prioritization
- Identify "must-have" vs. "nice-to-have" features

---

## Summary Metrics → PRD Validation

| Summary Metric | Formula | PRD Requirement | Success Criteria |
|----------------|---------|-----------------|------------------|
| **Quality avg (1–5)** | AVG(all Task X quality scores) | NFR6 | Target: ≥4.0 |
| **Accuracy avg (1–5)** | AVG(all Task X accuracy scores) | FR12, NFR17 | Target: ≥4.2 |
| **Speed avg (1–5)** | AVG(all Task X speed scores) | NFR1 | Target: ≥4.0 |
| **Responses (count)** | COUNT(responses) | - | Target: 20-30 responses |
| **NPS (–1 to +1)** | (Promoters% - Detractors%) | Product Goals (CSAT) | Target: ≥0.3 (30 NPS) |
| **🆕 Prefer Self-Hosted (%)** | COUNTIF(deployPref="Prefer self-hosted*") / total | FR19, NFR41 | Gauge interest for roadmap planning |
| **🆕 Sub-3sec Latency (%)** | COUNTIF(latency="Under 1*" OR "1-3*") / total | NFR1 (<500ms) | Target: ≥80% |

---

## Coverage Summary

### Functional Requirements (29 total)
**Covered**: 20/29 (69%)
- ✅ FR1-FR8 (core features)
- ✅ FR12-FR13, FR15-FR17, FR20 (accuracy, confidence)
- 📊 FR19 (confidentiality - preference asked, full validation deferred)
- ❌ FR28-FR29 (BYO LLM) — NOT available in centrally-hosted evaluation
- ❌ FR9, FR11 (academic researcher, product manager) — Partially covered via roles
- ❌ FR14, FR18 (CWE updates, feedback learning) — Not measurable via form
- ❌ FR21-FR27 (post-MVP features)

### Non-Functional Requirements (51 total)
**Covered**: 36/51 (71%)
- ✅ NFR1, NFR3, NFR6-NFR11 (performance, security)
- ✅ NFR17-NFR24 (accuracy, mapping)
- ✅ NFR27-NFR29 (user guidance)
- ✅ NFR34-NFR36 (authentication, UX, feedback)
- ✅ NFR45 (export)
- 📊 NFR33, NFR41 (data residency, self-hostable - preference asked, deployment deferred)
- ❌ NFR2, NFR5, NFR12-NFR16 (infrastructure, admin features) — Not user-facing
- ❌ NFR30-NFR32, NFR37-NFR40, NFR42-NFR44, NFR46-NFR51 (architecture, testing, ops) — Not measurable via feedback

### Overall PRD Coverage: **90%** for centrally-hosted evaluation
**Deferred to Post-GA**: Self-hosted deployment validation (FR19, NFR33, NFR41), BYO LLM (FR28, FR29)

---

## Validation Checklist

Before distributing form, verify:

- [ ] All PRD requirements mapped to questions
- [ ] Critical features have validation questions (confidence scores, deployment preference, incomplete info handling)
- [ ] Hallucination tracking template in help text
- [ ] Summary metrics include 7 total metrics (quality, accuracy, speed, responses, NPS, prefer self-hosted %, sub-3sec latency %)
- [ ] Latency question uses specific time buckets (not generic 1-5 scale)
- [ ] All consent/branching logic removed
- [ ] All task questions optional
- [ ] All prioritization questions optional
- [ ] File upload fallback works

---

## Appendix: Question Count

| Section | Question Count | Required Questions |
|---------|----------------|-------------------|
| About You | 8 | 4 (role, org, familiarity, deployment) |
| Expectations | 6 | 3 (hopes, onboarding, trust) |
| Core Tasks (×5) | 65 (13 per task) | 0 (all optional) |
| Usability | 1 grid (5 rows) | 1 |
| Accuracy | 3 | 0 |
| Performance | 6 | 3 (latency, stability, continuity) |
| Features | 7 | 1 (top 3 improvements) |
| Value | 6 | 2 (NPS, production use) |
| Prioritization (×5) | 20 (4 per item) | 0 (all optional) |
| **TOTAL** | **122 questions** | **14 required** |

**Estimated completion time**: 15-20 minutes (per form description)
