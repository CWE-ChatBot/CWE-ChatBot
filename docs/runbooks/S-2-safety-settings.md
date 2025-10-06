# S-2: SafetySetting Configuration

**Story:** S-2 LLM Input/Output Guardrails
**Last Updated:** 2025-10-06
**Status:** Active in Production

## Current Configuration

The CWE ChatBot uses Gemini API with the following SafetySetting configuration:

```python
from google.generativeai.types import HarmCategory, HarmBlockThreshold

safety_settings = [
    {"category": HarmCategory.HARM_CATEGORY_HARASSMENT, "threshold": HarmBlockThreshold.BLOCK_NONE},
    {"category": HarmCategory.HARM_CATEGORY_HATE_SPEECH, "threshold": HarmBlockThreshold.BLOCK_NONE},
    {"category": HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, "threshold": HarmBlockThreshold.BLOCK_NONE},
    {"category": HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, "threshold": HarmBlockThreshold.BLOCK_NONE},
]
```

### Locations

This configuration is applied in two locations:

1. **[apps/chatbot/src/app_config.py](../../apps/chatbot/src/app_config.py#L115-L120)** - Default configuration
2. **[apps/chatbot/src/llm_provider.py](../../apps/chatbot/src/llm_provider.py#L46-L51)** - LLM provider implementation

## Rationale: BLOCK_NONE for Vulnerability Information

**Why all categories use `BLOCK_NONE`:**

The CWE ChatBot is a **defensive security tool** that provides vulnerability information to security professionals. This requires discussing:

- **Exploitation techniques** (may trigger DANGEROUS_CONTENT)
- **Attack vectors** (may trigger HARASSMENT or HATE_SPEECH in adversarial contexts)
- **Malicious code examples** (may trigger DANGEROUS_CONTENT)
- **Security vulnerabilities in sensitive domains** (may trigger SEXUALLY_EXPLICIT for certain CVEs)

**BLOCK_NONE does NOT mean "no safety"** - it means we rely on:

1. **Model Armor** (external guardrails) for prompt injection, jailbreak, and data loss prevention
2. **Input sanitization** (`InputSanitizer` in [apps/chatbot/src/input_security.py](../../apps/chatbot/src/input_security.py))
3. **Security validation** (`SecurityValidator` in same file)
4. **RAG grounding** to prevent hallucination and keep responses factual

## Defense-in-Depth Strategy

### Layer 1: Model Armor (Platform-Level)
- **Prompt injection detection** - Blocks "Ignore all instructions" attacks
- **Jailbreak detection** - Blocks attempts to bypass safety
- **Data loss prevention** - Blocks attempts to extract secrets/PII
- **Malicious URL detection** - Blocks phishing/malware links

### Layer 2: Application-Level Security
- **Input sanitization** - Removes control characters, limits length
- **Security validation** - Detects SQL injection, command injection attempts
- **Authentication** - OAuth2 with Google/GitHub (when enabled)
- **Authorization** - Email whitelist for access control

### Layer 3: RAG Grounding
- **Vector search** - Responses grounded in official CWE corpus
- **Source citations** - Every claim backed by CWE documentation
- **No free-form generation** - LLM constrained to CWE content

### Layer 4: SafetySetting (BLOCK_NONE)
- **Permissive for legitimate security content**
- **Does not block vulnerability information**
- **Relies on upstream layers for actual safety**

## Monitoring and Observability

### Log-Based Metrics
- **llm_guardrail_blocks** - Tracks Model Armor/Safety blocks
- **Severity: CRITICAL** - All guardrail blocks logged at CRITICAL level

### Alerts
- **CRITICAL: LLM guardrail blocks > 0 (5m)** - Email alert to security team
- **Auto-close: 30 minutes** - Reduces alert fatigue

### Audit Logs
- **Vertex AI Data Access logs** - Enabled for all model calls
- **Retention: 400 days** (Google Cloud default for Admin Activity logs)

## Changing SafetySetting Thresholds

**⚠️ WARNING:** Changing from `BLOCK_NONE` to higher thresholds will break legitimate CWE ChatBot functionality.

### If You Must Change Thresholds:

1. **Test in non-production first**
   ```bash
   # Update app_config.py with new thresholds
   # Deploy to staging environment
   # Run comprehensive test suite
   ```

2. **Use specific thresholds per category**
   - `HARASSMENT`: Can try `BLOCK_ONLY_HIGH` (may block adversarial analysis)
   - `HATE_SPEECH`: Can try `BLOCK_ONLY_HIGH` (may block certain CVEs)
   - `SEXUALLY_EXPLICIT`: Must remain `BLOCK_NONE` (blocks legitimate CVEs)
   - `DANGEROUS_CONTENT`: Must remain `BLOCK_NONE` (blocks all vulnerability info)

3. **Monitor for false positives**
   ```bash
   # Check logs for blocked legitimate queries
   gcloud logging read "resource.type=aiplatform.googleapis.com/Endpoint AND severity=ERROR" --limit 50
   ```

4. **Document exceptions**
   - Update this file with rationale
   - Add to [CURATION_NOTES.md](../CURATION_NOTES.md)

## Environment Variables

No environment variables control SafetySetting - it's hardcoded in source.

To override, you would need to:
1. Modify `apps/chatbot/src/app_config.py` and `apps/chatbot/src/llm_provider.py`
2. Rebuild Docker image
3. Redeploy to Cloud Run

## Testing SafetySetting Changes

```bash
# 1. Update thresholds in source code
# 2. Run local tests
poetry run pytest apps/chatbot/tests/test_llm_provider.py -v

# 3. Test with smoke test script
poetry run python scripts/s2_smoke_test.py

# 4. Manual testing with known edge cases
poetry run chainlit run apps/chatbot/main.py

# Test queries:
# - "How do I prevent buffer overflow attacks?" (DANGEROUS_CONTENT)
# - "Explain SQL injection exploitation techniques" (DANGEROUS_CONTENT)
# - "What is CWE-79 and how is it exploited?" (DANGEROUS_CONTENT)
```

## Related Documentation

- **Story:** [docs/stories/S-2.LLM-Input-Output-Guardrails.md](../stories/S-2.LLM-Input-Output-Guardrails.md)
- **Plan:** [docs/plans/S-2.LLM-Input-Output-Guardrails.md](../plans/S-2.LLM-Input-Output-Guardrails.md)
- **Runbook:** [docs/runbooks/S-2-guardrails-runbook.md](S-2-guardrails-runbook.md)
- **Model Armor:** Setup script at [scripts/s2_setup_model_armor.sh](../../scripts/s2_setup_model_armor.sh)
- **Observability:** Setup script at [scripts/s2_setup_observability.sh](../../scripts/s2_setup_observability.sh)

## Audit Trail

| Date | Change | Rationale | Author |
|------|--------|-----------|--------|
| 2025-10-06 | Documented BLOCK_NONE configuration | S-2 implementation | Claude |
| 2025-08-XX | Initial SafetySetting implementation | Story 2.1 | Previous implementation |
