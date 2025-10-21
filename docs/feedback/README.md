# CWE Chatbot Volunteer Feedback - Documentation Package

**Status**: ✅ **Ready for Deployment**
**Product Owner**: Sarah
**Date**: October 21, 2025
**PRD Version**: 1.8

## ⚠️ **Evaluation Scope: Centrally-Hosted Only**

**This volunteer evaluation tests CENTRALLY-HOSTED deployment only**:
- All volunteers access the same cloud-hosted instance
- Self-hosted deployment is NOT available for this evaluation
- Bring Your Own LLM (BYO LLM) is NOT available for this evaluation
- Form asks about deployment PREFERENCES to gauge future interest

---

## 📦 Package Contents

| File | Purpose | Audience |
|------|---------|----------|
| **google_form_script_REVISED.gs** | ✅ **USE THIS** - Final Google Apps Script | Form admin |
| google_form_script.gs | ❌ **DO NOT USE** - Original version (outdated) | Archive only |
| REVISION_SUMMARY.md | Executive summary of changes and PRD alignment | Product Owner, stakeholders |
| QUESTION_MAPPING_TO_PRD.md | Detailed question-to-requirement mapping (95% coverage) | Product Owner, QA |
| VOLUNTEER_TESTING_GUIDE.md | Instructions for volunteers (what to test, how to report) | Volunteers |
| README.md | This file - navigation and quick start | Everyone |

---

## 🚀 Quick Start (Form Administrator)

### Step 1: Deploy Form (30 minutes)
1. Open Google Apps Script: https://script.google.com
2. Create new project: "CWE Chatbot Feedback Form"
3. Copy contents of `google_form_script_REVISED.gs`
4. Run function: `createForm()`
5. Check execution log for form URLs

**Expected output**:
```
Form created: https://docs.google.com/forms/d/.../edit
Response URL: https://docs.google.com/forms/d/.../viewform
Spreadsheet: https://docs.google.com/spreadsheets/d/.../edit
```

### Step 2: Test Form (15 minutes)
1. Open form response URL
2. Complete form as test user (use "Test User" name)
3. Submit response
4. Open spreadsheet → "Form Responses 1" tab → verify 1 row
5. Run custom menu: **CWE Feedback → Build/Refresh Summary**
6. Verify "Summary" tab shows 7 metrics

**Expected metrics**:
- Quality avg (1–5)
- Accuracy avg (1–5)
- Speed avg (1–5)
- Responses (count) = 1
- NPS (–1 to +1)
- Prefer Self-Hosted (%)
- Sub-3sec Latency (%)

### Step 3: Share with Volunteers (5 minutes)
1. Copy form response URL
2. Email volunteers with:
   - Form URL
   - `VOLUNTEER_TESTING_GUIDE.md` (as PDF or Google Doc)
   - Deadline: Mid-November 2025
   - Target: 20-30 responses

---

## 📊 What Changed (Product Owner Review)

### ✅ Requested Removals (Original Specification)
- ❌ Consent to participate section (no branching)
- ❌ Integrations/exports question
- ❌ Estimated effort field
- ❌ Consent for follow-up section
- ✅ Core tasks: ALL optional
- ✅ Prioritization: ALL optional

### ➕ Critical Additions (PRD Alignment)
- ✅ Deployment PREFERENCE question (gauges interest in self-hosting vs. centrally-hosted)
- ✅ Confidence score validation — **FR15, NFR22**
- ✅ Authentication experience — **NFR34**
- ✅ Specific latency buckets (replaced generic 1-5 scale) — **NFR1**
- ✅ Incomplete information handling — **FR17, NFR26**
- ✅ Enhanced Summary metrics (7 total metrics: quality, accuracy, speed, responses, NPS, prefer self-hosted %, sub-3sec latency %)

**Note**: This evaluation uses **centrally-hosted deployment only**. Self-hosted and BYO LLM are NOT available for testing.

### Result: **90% PRD Coverage** (up from 70%) for centrally-hosted evaluation

Full details: See `REVISION_SUMMARY.md`

---

## 🎯 Key Metrics to Track

After collecting responses, monitor these in the Summary tab:

| Metric | Success Criteria | Action if Below Target |
|--------|------------------|------------------------|
| **Quality avg** | ≥4.0/5 | Review hallucination reports; improve RAG retrieval |
| **Accuracy avg** | ≥4.2/5 | Fix hallucinations; validate CWE ID correctness |
| **Speed avg** | ≥4.0/5 | Optimize response latency |
| **NPS** | ≥0.3 (30 NPS) | Triage P0 items; address top pain points |
| **Sub-3sec Latency** | ≥80% | Performance tuning; check infrastructure |
| **Prefer Self-Hosted** | Track % | Inform future deployment roadmap; if >50%, prioritize self-hosted capability |

---

## 📋 PRD Validation Checklist

Use this checklist to validate form covers all critical requirements:

### Functional Requirements
- [x] FR1: NLU for natural language queries (Task prompts)
- [x] FR2: CWE corpus retrieval (Core tasks)
- [x] FR3: Conversational turns (Usability grid - follow-up questions)
- [x] FR4: Role-based adaptation (Role/background question)
- [x] FR5: Concise + detailed explanations (Core tasks)
- [x] FR6: Related CWEs, mitigations (Feature usage)
- [x] FR7-FR11: User scenario coverage (Roles, features)
- [x] FR12: Correct CWE IDs (Hallucination tracking, accuracy)
- [x] FR15-FR17: Confidence, reasoning, insufficient info (New questions)
- [x] FR19: Confidentiality (Deployment preference, security concerns)
- [x] FR20: Confidence display (New confidence score question)

### Non-Functional Requirements (High Priority)
- [x] NFR1: Latency <500ms (Specific latency buckets)
- [x] NFR3: 99.9% uptime (Stability question)
- [x] NFR6: Hallucination minimization (Hallucination tracking)
- [x] NFR7-NFR11: Security & privacy (Security concerns, data residency)
- [x] NFR17: ID validation (Hallucination tracking)
- [x] NFR22: Prioritized confidence scores (Confidence score question)
- [x] NFR24: Mapping reasoning (Citations appropriateness)
- [x] NFR26: Input refinement guidance (Incomplete info handling)
- [x] NFR33-NFR34: Security, authentication (Auth experience, data residency)
- [x] NFR35: Context preservation (Session continuity)
- [x] NFR36: Continuous improvement (Feedback mechanisms)
- [x] NFR41: Self-hostable (Deployment model)
- [x] NFR45: Export formats (Feature usage)

**Total Coverage**: 90% of user-facing requirements for centrally-hosted evaluation (deferred: self-hosted validation, BYO LLM)

Full mapping: See `QUESTION_MAPPING_TO_PRD.md`

---

## 🔍 Common Issues & Troubleshooting

### Issue 1: "File upload not available" error
**Cause**: Google Workspace account disabled file uploads
**Fix**: Script automatically falls back to text field for links
**Verify**: Check if text field appears instead of file upload

### Issue 2: Summary tab shows "No matching columns yet"
**Cause**: No responses submitted, or header names don't match regex
**Fix**:
1. Submit 1 test response
2. Run "CWE Feedback → Build/Refresh Summary"
3. Verify header names exactly match script expectations

### Issue 3: NPS calculation shows blank
**Cause**: NPS column not found
**Fix**: Check "Likelihood to recommend (NPS)" question exists
**Verify**: Column header matches regex `/^Likelihood to recommend \(NPS\)$/i`

### Issue 4: Deployment preference metric shows "question not found"
**Cause**: Using old script version
**Fix**: Use `google_form_script_REVISED.gs` (not original)
**Verify**: Check for deployment preference question in "About You" section

---

## 📅 Timeline

| Phase | Date | Activities |
|-------|------|------------|
| **Form Deployment** | Week of Oct 21 | Deploy script, test form, verify metrics |
| **Volunteer Distribution** | Early November | Share form + testing guide with 30+ volunteers |
| **Collection Period** | November 1-15 | Monitor responses, answer questions |
| **Analysis & Triage** | November 16-22 | Review hallucinations, prioritize P0/P1 items |
| **Results Sharing** | November 25 | Summary report to stakeholders |
| **GA Release** | Q4 2025 | Incorporate feedback into production |

---

## 📧 Contacts

| Role | Contact | Purpose |
|------|---------|---------|
| **Form Admin** | [TBD] | Technical issues with form/script |
| **Product Owner** | Sarah | Prioritization, requirements questions |
| **Security Lead** | [TBD] | Hallucination reports, data privacy |
| **Project Manager** | [TBD] | Timeline, volunteer coordination |

---

## 🎓 Volunteer Instructions

### What to Send Volunteers
1. **Form URL**: [Your deployed form URL]
2. **Testing Guide**: `VOLUNTEER_TESTING_GUIDE.md` (convert to PDF or Google Doc)
3. **Access Info**: Chatbot URL, login instructions
4. **Deadline**: Mid-November 2025
5. **Support Contact**: [Your contact email]

### Sample Email Template
```
Subject: CWE Chatbot Early Access - We Need Your Feedback!

Hi [Name],

Thank you for volunteering to test the CWE Chatbot! We need your expertise to help us build a better tool for the cybersecurity community.

What you'll do:
- Access the chatbot: [URL]
- Try 3-5 real-world tasks (15-20 minutes)
- Complete feedback form: [Form URL]

Testing guide: [Attach VOLUNTEER_TESTING_GUIDE.pdf]

Deadline: November 15, 2025

Questions? Reply to this email or contact [support email].

Thank you!
[Your Name]
CWE Chatbot Team
```

---

## 📈 Success Criteria

### Quantitative Goals
- ✅ **20-30 responses** (minimum 20 for statistical significance)
- ✅ **NPS ≥30** (0.3 on –1 to +1 scale)
- ✅ **Quality avg ≥4.0/5**
- ✅ **Accuracy avg ≥4.2/5**
- ✅ **Sub-3sec latency ≥80%**

### Qualitative Goals
- ✅ Identify top 3-5 hallucination patterns
- ✅ Gauge self-hosted deployment interest for future roadmap
- ✅ Prioritize P0 features for GA release
- ✅ Understand authentication pain points
- ✅ Assess confidence score helpfulness

---

## 🔒 Data Privacy & Security

### Form Data Handling
- **Email collection**: Disabled by default (optional Name/Email fields)
- **PII**: Name and Email only if volunteers choose to provide
- **Storage**: Google Sheets, encrypted at rest
- **Access**: Limited to form admin and product owner
- **Retention**: Delete after analysis (per GDPR)

### Volunteer Data Handling
- **Anonymize examples**: Volunteers instructed to remove confidential data
- **Centrally-hosted evaluation**: All volunteers use cloud-hosted instance
- **Hallucination reports**: May contain sensitive prompts (handle carefully)

**Compliance**: GDPR-ready, delete responses upon request

---

## 📚 Additional Resources

### PRD & Requirements
- `docs/prd.md` - Full Product Requirements Document
- `docs/prd/user-stories.md` - Detailed user stories
- `docs/architecture.md` - Technical architecture

### Testing & QA
- `tests/integration/` - Integration test suite
- `tests/e2e/` - End-to-end test scenarios

### Deployment
- `apps/chatbot/deploy.sh` - Production deployment script
- `apps/chatbot/deploy_staging.sh` - Staging deployment

---

## ✅ Pre-Distribution Checklist

Before sharing form with volunteers, verify:

- [ ] Deployed script using `google_form_script_REVISED.gs`
- [ ] Tested form end-to-end (submitted test response)
- [ ] Verified Summary tab shows 7 metrics
- [ ] Deleted test response (clean slate for volunteers)
- [ ] Converted `VOLUNTEER_TESTING_GUIDE.md` to PDF or Google Doc
- [ ] Prepared volunteer email with form URL and testing guide
- [ ] Set up support email/contact for volunteer questions
- [ ] Verified chatbot is accessible and working
- [ ] Reviewed data privacy and GDPR compliance
- [ ] Obtained stakeholder approval (if required)

---

## 🎉 You're Ready!

This package provides everything needed to:
1. ✅ Deploy a PRD-aligned feedback form
2. ✅ Collect high-quality volunteer feedback
3. ✅ Track critical success metrics
4. ✅ Validate product-market fit
5. ✅ Prioritize GA release features

**Next Step**: Deploy the form and share with volunteers!

Questions? Contact Product Owner (Sarah) or project team.

---

**Version**: 1.0 (October 2025)
**Last Updated**: October 21, 2025
**Status**: ✅ Ready for Production
