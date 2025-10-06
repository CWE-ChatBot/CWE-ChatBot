# S-2 Reality Check: Model Armor Cannot Be Applied (Gemini API vs Vertex AI)

**Date:** 2025-10-06
**Status:** ❌ BLOCKED - App uses Gemini API SDK, not Vertex AI
**Impact:** Model Armor setup scripts are NOT applicable to current implementation

## Critical Finding

**The CWE ChatBot uses `google.generativeai` (Gemini API SDK), NOT Vertex AI.**

### Evidence

From [apps/chatbot/src/llm_provider.py](../../apps/chatbot/src/llm_provider.py#L32-L35):
```python
import google.generativeai as genai  # type: ignore
self._genai.configure(api_key=api_key)
self._model = genai.GenerativeModel(model_name)
```

From [apps/chatbot/src/app_config.py](../../apps/chatbot/src/app_config.py#L56):
```python
llm_provider: str = os.getenv("LLM_PROVIDER", "google")  # "google" = Gemini API SDK
```

### Why This Matters

**Model Armor ONLY works with Vertex AI endpoints**, not the Gemini API SDK:

| Feature | Gemini API SDK (Current) | Vertex AI (Required for Model Armor) |
|---------|--------------------------|---------------------------------------|
| Endpoint | `generativelanguage.googleapis.com` | `{region}-aiplatform.googleapis.com` |
| Authentication | API Key | OAuth2 / Service Account |
| Model Armor Support | ❌ **NO** | ✅ YES |
| SafetySetting Support | ✅ YES (app-level) | ✅ YES (app-level) |
| Pricing | Pay-per-use | Enterprise pricing |

## What Actually Works Today

### Current Guardrails (App-Level Only)

1. **SafetySetting** - ✅ ACTIVE
   - `BLOCK_NONE` for all categories (intentional for security content)
   - Configured in [apps/chatbot/src/llm_provider.py](../../apps/chatbot/src/llm_provider.py#L47-L51)
   - Documented in [docs/runbooks/S-2-safety-settings.md](../runbooks/S-2-safety-settings.md)

2. **Input Sanitization** - ✅ ACTIVE
   - `InputSanitizer` class in [apps/chatbot/src/input_security.py](../../apps/chatbot/src/input_security.py)
   - Removes control characters, limits length
   - SQL injection prevention via `SecureQueryBuilder`

3. **RAG Grounding** - ✅ ACTIVE
   - Responses constrained to CWE corpus (7,913 chunks)
   - Vector search with pgvector + halfvec
   - Source citations for all claims

4. **OAuth Authentication** - ✅ ACTIVE (when enabled)
   - Google + GitHub providers
   - Email whitelist authorization

### What Does NOT Work

1. **Model Armor** - ❌ NOT APPLICABLE
   - Requires Vertex AI endpoint (not Gemini API SDK)
   - Setup scripts created but cannot be used
   - Prompt injection/jailbreak detection NOT available

2. **Platform-Level DLP** - ❌ NOT APPLICABLE
   - Requires Vertex AI integration
   - Model Armor DLP shield NOT available

3. **Vertex AI Logging** - ❌ NOT APPLICABLE
   - Gemini API SDK uses different logging
   - Observability setup script targets Vertex AI logs

## S-2 Acceptance Criteria Re-Assessment

| AC | Original Status | Reality Check | Notes |
|----|-----------------|---------------|-------|
| AC-1 | ✅ READY | ❌ **BLOCKED** | Model Armor requires Vertex AI (app uses Gemini API) |
| AC-2 | ✅ COMPLETE | ✅ **ACCURATE** | SafetySetting works with Gemini API SDK |
| AC-3 | ⚠️ DEFERRED | ⚠️ **ACCURATE** | Deferred correctly |
| AC-4 | 🟡 PARTIAL | ❌ **BLOCKED** | Model Armor DLP requires Vertex AI |
| AC-5 | ✅ READY | 🟡 **PARTIAL** | App logs work, Vertex AI logs don't apply |
| AC-6 | ✅ COMPLETE | ✅ **ACCURATE** | RAG grounding works independently |
| AC-7 | ✅ COMPLETE | 🟡 **PARTIAL** | Runbooks reference Vertex AI features that don't exist |

**Revised Summary:** 2/7 complete, 1 partial, 4 blocked by architecture mismatch

## Security Posture Reality

### What We Actually Have (3 Layers)

1. **Application Security Layer**
   - Input sanitization and validation
   - SQL injection prevention
   - OAuth2 authentication
   - Email whitelist authorization

2. **RAG Grounding Layer**
   - Responses constrained to CWE corpus
   - Source citations
   - No free-form generation

3. **SafetySetting Layer** (Permissive)
   - BLOCK_NONE for security content
   - Last-resort protection only

### What We DON'T Have

1. ❌ **Platform-level prompt injection detection** (requires Vertex AI + Model Armor)
2. ❌ **Platform-level jailbreak detection** (requires Vertex AI + Model Armor)
3. ❌ **Platform-level data loss prevention** (requires Vertex AI + Model Armor)
4. ❌ **Platform-level malicious URL detection** (requires Vertex AI + Model Armor)

### Attack Vectors Still Present

1. **Prompt Injection** - Only app-level protection (input sanitization)
2. **Jailbreak Attempts** - Only SafetySetting (BLOCK_NONE = minimal protection)
3. **Data Exfiltration** - Input validation helps, but no platform-level DLP
4. **System Prompt Extraction** - No platform-level shields

**Risk Level:** MEDIUM-HIGH - Relying on app-level defenses only, no platform-level protection

## Options Going Forward

### Option 1: Migrate to Vertex AI (RECOMMENDED)

**Effort:** Medium (app code changes required)

**Changes needed:**
```python
# Replace:
import google.generativeai as genai
genai.configure(api_key=api_key)
model = genai.GenerativeModel(model_name)

# With:
import vertexai
from vertexai.generative_models import GenerativeModel
vertexai.init(project=project_id, location=location)
model = GenerativeModel(model_name)
```

**Benefits:**
- ✅ Model Armor support (prompt injection, jailbreak, DLP)
- ✅ Enterprise-grade security
- ✅ Better observability (Vertex AI audit logs)
- ✅ Consistent with GCP ecosystem

**Drawbacks:**
- ⚠️ Requires app code changes (violates S-2 "no-code-change" constraint)
- ⚠️ Different authentication (service account vs API key)
- ⚠️ Potentially higher cost (enterprise pricing)

### Option 2: Accept Current State (App-Level Only)

**Effort:** Zero (document reality and move on)

**What we have:**
- SafetySetting (permissive for security content)
- Input sanitization and validation
- RAG grounding (prevents hallucination)
- OAuth authentication

**What we don't have:**
- Platform-level prompt injection/jailbreak detection
- Platform-level DLP
- Model Armor shields

**Risk acceptance:**
- Document that app relies on 3 layers of defense (not 4)
- Accept medium-high risk for prompt injection attacks
- Rely on input validation and RAG grounding

### Option 3: Add App-Level Prompt Injection Detection

**Effort:** Medium (add detection library or custom logic)

**Implementation:**
```python
# Add to InputSanitizer
def detect_prompt_injection(self, text: str) -> bool:
    """Detect common prompt injection patterns."""
    injection_patterns = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"ignore\s+above",
        r"developer\s+mode",
        r"DAN\s+mode",
        r"reveal.*system\s+prompt",
        r"print.*API\s+key",
    ]
    for pattern in injection_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False
```

**Benefits:**
- ✅ Adds prompt injection detection without Vertex AI
- ✅ Can be tuned for CWE ChatBot use case
- ✅ Works with current Gemini API SDK

**Drawbacks:**
- ⚠️ App code changes required
- ⚠️ Maintenance burden (keeping patterns updated)
- ⚠️ Less robust than Model Armor (platform-level)

## Recommendation

**Short-term (Immediate):**
1. **Accept Option 2** - Document current state honestly
2. Update S-2 story status to reflect reality
3. Mark Model Armor AC items as "BLOCKED - Requires Vertex AI migration"
4. Keep SafetySetting documentation (accurate and useful)
5. Archive Model Armor scripts with note "For future Vertex AI migration"

**Medium-term (Next Sprint):**
1. **Implement Option 3** - Add app-level prompt injection detection
2. Create new story: "S-2B: App-Level Prompt Injection Detection"
3. Use regex patterns + heuristics for common attacks
4. Add comprehensive testing with known attack payloads

**Long-term (Future Epic):**
1. **Implement Option 1** - Migrate to Vertex AI
2. Create epic: "Vertex AI Migration"
3. Stories: Update LLM provider, Update auth, Deploy Model Armor, Migrate to service account
4. Full Model Armor support becomes available

## What to Do with S-2 Deliverables

### Keep (Still Valuable)

1. ✅ [docs/runbooks/S-2-safety-settings.md](../runbooks/S-2-safety-settings.md)
   - Documents actual SafetySetting configuration
   - Explains BLOCK_NONE rationale
   - Useful for current implementation

2. ✅ [scripts/s2_smoke_test.py](../../scripts/s2_smoke_test.py)
   - Can still test app-level defenses
   - Validates input sanitization
   - Useful for regression testing

### Archive (Future Use)

1. 📦 [scripts/s2_setup_model_armor.sh](../../scripts/s2_setup_model_armor.sh)
   - Move to `docs/future/vertex-ai-migration/`
   - Keep for future Vertex AI migration
   - Add note "Requires Vertex AI migration first"

2. 📦 [scripts/s2_setup_observability.sh](../../scripts/s2_setup_observability.sh)
   - Move to `docs/future/vertex-ai-migration/`
   - Vertex AI specific logging/metrics
   - Add note "Requires Vertex AI migration first"

3. 📦 [docs/runbooks/S-2-guardrails-runbook.md](../runbooks/S-2-guardrails-runbook.md)
   - Move to `docs/future/vertex-ai-migration/`
   - Model Armor specific operations
   - Add note "Requires Vertex AI migration first"

### Update (Reflect Reality)

1. ✏️ [docs/stories/S-2.LLM-Input-Output-Guardrails.md](S-2.LLM-Input-Output-Guardrails.md)
   - Update status to "PARTIALLY COMPLETE (blocked by Gemini API SDK)"
   - Mark Model Armor items as "BLOCKED - Requires Vertex AI"
   - Document what actually works (SafetySetting, input sanitization, RAG)

## Lessons Learned

### What Went Wrong

1. **❌ Didn't verify actual LLM provider before planning** - Assumed Vertex AI without checking
2. **❌ Plan document assumed Vertex AI integration** - No validation of current state
3. **❌ "No code changes" constraint conflicted with requirements** - Model Armor requires Vertex AI, which requires code changes

### Following CLAUDE.md Principles

Per CLAUDE.md:
> "NO THEATER": If something doesn't work, say it immediately - don't pretend with elaborate non-functional code

**This document follows that principle** - The Model Armor scripts were created but cannot work with current architecture.

> "REALITY CHECK": Before implementing anything, verify the actual integration points exist and work

**This check came too late** - Should have verified Vertex AI vs Gemini API before creating scripts.

> **Test first. Make it work. Make it right. Make it fast.**

**It doesn't work** - Scripts cannot be deployed because app uses wrong API.

### How to Prevent This

1. **✅ Always check actual dependencies first** - Read code before planning infrastructure
2. **✅ Test assumptions early** - "The app uses Vertex AI" should have been verified
3. **✅ Don't create elaborate solutions for wrong problem** - Should have stopped when mismatch found

## Next Steps

1. Update S-2 story status to reflect reality
2. Archive Vertex AI specific scripts to `docs/future/vertex-ai-migration/`
3. Keep SafetySetting documentation (accurate and useful)
4. Create follow-up story for app-level prompt injection detection (Option 3)
5. Add Vertex AI migration to long-term roadmap (Option 1)

---

**Bottom Line:** Story S-2 discovered an architecture mismatch. Model Armor requires Vertex AI; app uses Gemini API SDK. SafetySetting documentation and smoke test are valuable. Model Armor setup scripts are premature and cannot be deployed without migrating to Vertex AI first.

**Honest Assessment:** 2/7 acceptance criteria met (SafetySetting, Grounding), 4/7 blocked by architecture, 1/7 deferred.
