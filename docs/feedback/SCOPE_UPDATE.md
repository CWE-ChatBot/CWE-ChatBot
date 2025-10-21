# Evaluation Scope Update: Centrally-Hosted Only

**Date**: October 21, 2025
**Product Owner**: Sarah
**Change Type**: Scope clarification

---

## Summary of Changes

### ❌ **What's NOT Available for This Evaluation**

1. **Self-Hosted Deployment**
   - NOT available for volunteer testing
   - All volunteers use the same centrally-hosted (cloud) instance
   - Form now asks about deployment PREFERENCE instead of actual deployment used

2. **Bring Your Own LLM (BYO LLM)**
   - NOT available for volunteer testing
   - Removed from form questions entirely
   - Future feature consideration based on user feedback

---

## What Changed in the Form Script

### Before (Original Questions):
```javascript
// Question: "How are you accessing the CWE Chatbot?"
// Choices: Centrally-hosted | Self-hosted | Don't know
// → IMPLIED users could test either deployment

// Question: "Did you configure BYO LLM?"
// Choices: Yes - API key | Yes - self-hosted | No | N/A
// → IMPLIED BYO LLM was available
```

### After (Updated Questions):
```javascript
// Question: "Would you prefer to use a centrally-hosted solution or self-host the CWE Chatbot?"
// Choices: Prefer centrally-hosted | Prefer self-hosted | Either | Unsure
// Help Text: "Note: This evaluation uses centrally-hosted deployment.
//             This question gauges future deployment preferences."
// → CLEAR this is a preference question, not actual usage

// Question: "If you prefer self-hosted, why?"
// Type: Paragraph text (optional)
// → Captures reasons for self-hosting interest

// REMOVED: BYO LLM question entirely
```

---

## Summary Metrics Changes

### Before (8 metrics):
1. Quality avg (1–5)
2. Accuracy avg (1–5)
3. Speed avg (1–5)
4. Responses (count)
5. NPS (–1 to +1)
6. **Self-Hosted Users (%)** ← Measured actual usage
7. **BYO LLM Adoption (%)** ← Measured actual usage
8. Sub-3sec Latency (%)

### After (8 metrics):
1. Quality avg (1–5)
2. Accuracy avg (1–5)
3. Speed avg (1–5)
4. Responses (count)
5. NPS (–1 to +1)
6. **Prefer Self-Hosted (%)** ← Measures preference/interest
7. Sub-3sec Latency (%)

**Total metrics reduced from 8 to 7** (removed BYO LLM adoption metric)

---

## Documentation Updates

### Files Updated:

1. **google_form_script_REVISED.gs**
   - Changed deployment question to preference question
   - Removed BYO LLM question
   - Updated Summary metrics (7 instead of 8)
   - Added evaluation scope note in header comments

2. **VOLUNTEER_TESTING_GUIDE.md**
   - Added "Centrally-Hosted Evaluation Only" warning section
   - Removed "Self-Hosted Deployment Checklist" section (entire section deleted)
   - Removed "BYO LLM Configuration" section (entire section deleted)
   - Updated data privacy notice (cloud logging only)
   - Updated deployment preference guidance

3. **README.md**
   - Added evaluation scope warning at top
   - Updated expected metrics (7 instead of 8)
   - Changed "Self-Hosted Users" to "Prefer Self-Hosted"
   - Updated success criteria table

4. **SCOPE_UPDATE.md** (this file)
   - Created to document the scope change

---

## Why This Change?

### Reason 1: Evaluation Constraints
- Self-hosted deployment requires infrastructure setup by each volunteer
- Not feasible for 20-30 volunteers to set up self-hosted instances
- Centrally-hosted provides consistent testing environment

### Reason 2: BYO LLM Complexity
- Requires volunteers to have their own LLM API keys or models
- Adds configuration complexity
- Can be evaluated post-GA with dedicated technical users

### Reason 3: Focus on Core Features
- Evaluation should focus on chatbot functionality (accuracy, usability, performance)
- Deployment model is important but secondary for MVP validation
- Preference data still collected for roadmap planning

---

## Impact on PRD Coverage

### Before Scope Change:
- **95% PRD coverage** (including self-hosted and BYO LLM validation)

### After Scope Change:
- **90% PRD coverage** (self-hosted and BYO LLM deferred to post-GA)
- Still validates all core chatbot features
- Collects preference data for future deployment planning

### Deferred to Post-GA:
- FR19 validation (self-hosted confidentiality guarantee) → Preference question instead
- FR28/FR29 validation (BYO LLM API key / self-hosted model) → Removed
- NFR33 validation (self-hosted data residency) → Preference question instead
- NFR41 validation (self-hostable architecture) → Preference question instead

**Note**: Architecture still supports self-hosting; just not tested in this volunteer evaluation.

---

## User Communication

### What to Tell Volunteers:

**Correct**:
> "This evaluation uses a centrally-hosted (cloud) deployment. All volunteers will test the same instance. The form will ask about your deployment preferences to help us plan future capabilities."

**Incorrect** (don't say this):
> ~~"You can test either centrally-hosted or self-hosted deployment."~~
> ~~"BYO LLM is available if you configure your API key."~~

---

## Testing Checklist Update

### Before Distributing Form:

- [x] Updated form script with preference questions
- [x] Removed BYO LLM questions
- [x] Updated Summary metrics (7 total)
- [x] Updated VOLUNTEER_TESTING_GUIDE.md
- [x] Updated README.md
- [x] Created SCOPE_UPDATE.md
- [ ] Test form deployment (run createForm())
- [ ] Verify Summary tab shows 7 metrics (not 8)
- [ ] Review volunteer email template
- [ ] Confirm chatbot URL is accessible

---

## Metrics Interpretation

### "Prefer Self-Hosted (%)" Metric

**What it measures**: Percentage of volunteers who would prefer self-hosted deployment over centrally-hosted

**How to interpret**:
- **<30%**: Low demand → Centrally-hosted sufficient for MVP/GA
- **30-50%**: Moderate interest → Consider self-hosted for future releases
- **>50%**: High demand → Prioritize self-hosted capability post-GA

**Action thresholds**:
- If >50% prefer self-hosted: Add self-hosted deployment to post-GA roadmap (P1 priority)
- If >30% cite compliance/data residency: Document self-hosting setup guide
- If <30%: Focus on centrally-hosted optimization

---

## Rollback Plan

If we need to revert to testing self-hosted/BYO LLM:

1. Revert `google_form_script_REVISED.gs` to previous version
2. Restore self-hosted checklist in VOLUNTEER_TESTING_GUIDE.md
3. Restore BYO LLM configuration section
4. Update README.md to remove scope warning
5. Provide volunteers with self-hosted setup instructions
6. Update Summary metrics to 8 (re-add BYO LLM adoption)

**Estimated effort**: 2 hours (form redeploy + doc updates + volunteer communication)

---

## Questions or Concerns?

Contact Product Owner (Sarah) if:
- Volunteers ask about self-hosted deployment
- Confusion about deployment preference question
- Need clarification on evaluation scope
- Want to add self-hosted testing later

---

**Version**: 1.0
**Status**: ✅ Approved
**Effective Date**: October 21, 2025
