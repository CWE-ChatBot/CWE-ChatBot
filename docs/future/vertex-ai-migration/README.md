# Vertex AI Migration Materials

**Status:** Archived - Requires Vertex AI migration before use
**Source:** Story S-2 LLM Input/Output Guardrails
**Date Archived:** 2025-10-06

## Why These Files Are Archived

The CWE ChatBot currently uses `google.generativeai` (Gemini API SDK), which calls `generativelanguage.googleapis.com` endpoints.

**Model Armor and Vertex AI-specific features only work with Vertex AI endpoints** (`{region}-aiplatform.googleapis.com`), not the Gemini API SDK.

These files were created for Story S-2 but cannot be deployed until the app migrates to Vertex AI.

## Archived Files

### Setup Scripts

1. **[s2_setup_model_armor.sh](s2_setup_model_armor.sh)**
   - Creates Model Armor template with prompt injection, jailbreak, data loss, and URL detection shields
   - Configures HIGH confidence thresholds for CWE security content
   - **Requires:** Vertex AI endpoints (app currently uses Gemini API SDK)

2. **[s2_setup_observability.sh](s2_setup_observability.sh)**
   - Creates log-based metric for guardrail blocks
   - Sets up email alerts for CRITICAL security events
   - **Requires:** Vertex AI audit logs (not available with Gemini API SDK)

### Documentation

3. **[S-2-guardrails-runbook.md](S-2-guardrails-runbook.md)**
   - Operations runbook for Model Armor incident response
   - Alert triage procedures
   - Model Armor tuning and rollback procedures
   - **Requires:** Model Armor integration (not available with Gemini API SDK)

## What You Need to Migrate

### Code Changes Required

**Current implementation (Gemini API SDK):**
```python
# apps/chatbot/src/llm_provider.py
import google.generativeai as genai
genai.configure(api_key=api_key)
model = genai.GenerativeModel(model_name)
```

**Required for Model Armor (Vertex AI SDK):**
```python
# apps/chatbot/src/llm_provider.py
import vertexai
from vertexai.generative_models import GenerativeModel
vertexai.init(project=project_id, location=location)
model = GenerativeModel(model_name)
```

### Additional Changes

1. **Authentication:** Change from API key to service account or OAuth2
2. **Environment variables:** Add `GCP_PROJECT_ID` and `GCP_LOCATION`
3. **Deployment:** Update Cloud Run service account permissions for Vertex AI
4. **Testing:** Update all tests to use Vertex AI endpoints

### Migration Checklist

When you're ready to migrate to Vertex AI:

- [ ] Create migration epic and stories
- [ ] Update `LLMProvider` class to use `vertexai` SDK
- [ ] Update authentication from API key to service account
- [ ] Update environment configuration (add PROJECT_ID, LOCATION)
- [ ] Update Cloud Run deployment (service account permissions)
- [ ] Run integration tests with Vertex AI endpoints
- [ ] Deploy scripts from this directory:
  - [ ] Run `s2_setup_model_armor.sh`
  - [ ] Bind Model Armor template via Console
  - [ ] Run `s2_setup_observability.sh`
  - [ ] Verify alerts and logging
- [ ] Import operations runbook to `docs/runbooks/`
- [ ] Train ops team on Model Armor incident response

## Comparison: Gemini API SDK vs Vertex AI

| Feature | Gemini API SDK (Current) | Vertex AI (Required for Migration) |
|---------|--------------------------|-------------------------------------|
| Endpoint | `generativelanguage.googleapis.com` | `{region}-aiplatform.googleapis.com` |
| Authentication | API Key | Service Account / OAuth2 |
| Model Armor Support | ❌ NO | ✅ YES |
| Prompt Injection Detection | ❌ NO | ✅ YES (via Model Armor) |
| Jailbreak Detection | ❌ NO | ✅ YES (via Model Armor) |
| Data Loss Prevention | ❌ NO | ✅ YES (via Model Armor) |
| Platform-level Logging | ❌ Limited | ✅ Full Vertex AI audit logs |
| SafetySetting Support | ✅ YES | ✅ YES |
| Pricing | Pay-per-use (lower cost) | Enterprise pricing (higher cost) |

## Related Documentation

- **Architecture Mismatch Analysis:** [docs/stories/S-2-REALITY-CHECK.md](../../stories/S-2-REALITY-CHECK.md)
- **Story S-2 Status:** [docs/stories/S-2.LLM-Input-Output-Guardrails.md](../../stories/S-2.LLM-Input-Output-Guardrails.md)
- **SafetySetting Documentation (still valid):** [docs/runbooks/S-2-safety-settings.md](../../runbooks/S-2-safety-settings.md)

## When to Use These Files

**Deploy these files when:**
1. ✅ App has been migrated to Vertex AI SDK
2. ✅ Service account authentication is configured
3. ✅ Vertex AI API is enabled for the project
4. ✅ Integration tests pass with Vertex AI endpoints

**Do NOT deploy these files if:**
1. ❌ App still uses `google.generativeai` SDK
2. ❌ App authenticates with API key only
3. ❌ You haven't completed Vertex AI migration testing

## Questions?

See [S-2-REALITY-CHECK.md](../../stories/S-2-REALITY-CHECK.md) for detailed analysis of the architecture mismatch and migration options.
