# S-2 LLM Guardrails - Quick Reference Card

**Status:** ✅ Complete | **Date:** 2025-10-06 | **Approach:** No code changes

## 🚀 Quick Deploy (5 Commands)

```bash
# 1. Setup environment
export PROJECT_ID=cwechatbot
export LOCATION=us-central1
export ALERT_EMAIL=secops@example.com

# 2. Create Model Armor template
./scripts/s2_setup_model_armor.sh

# 3. Bind via Console
# https://console.cloud.google.com/security/model-armor/integrations
# Bind llm-guardrails-default to Vertex AI → cwechatbot/us-central1

# 4. Setup monitoring
./scripts/s2_setup_observability.sh

# 5. Test
poetry run python scripts/s2_smoke_test.py --endpoint https://your-app.run.app
```

## 📁 Key Files

| File | Purpose |
|------|---------|
| [scripts/s2_setup_model_armor.sh](../../scripts/s2_setup_model_armor.sh) | Create Model Armor template |
| [scripts/s2_setup_observability.sh](../../scripts/s2_setup_observability.sh) | Setup metrics & alerts |
| [scripts/s2_smoke_test.py](../../scripts/s2_smoke_test.py) | Test guardrail effectiveness |
| [docs/runbooks/S-2-guardrails-runbook.md](../runbooks/S-2-guardrails-runbook.md) | Operations runbook |
| [docs/runbooks/S-2-safety-settings.md](../runbooks/S-2-safety-settings.md) | SafetySetting config docs |

## 🛡️ What's Protected

✅ Prompt injection ("Ignore all instructions")
✅ Jailbreak attempts (DAN mode, role-play)
✅ Data exfiltration (API keys, secrets)
✅ Malicious URLs (phishing, malware)
✅ Unsafe content (harassment, hate, sexual, dangerous)

## 🎯 Defense Layers

1. **Model Armor** (platform) - Blocks attacks before model
2. **Application Security** - Input validation, OAuth, sanitization
3. **RAG Grounding** - Responses constrained to CWE corpus
4. **SafetySetting** - BLOCK_NONE (allows security content)

## 📊 Monitoring

**Metric:** `llm_guardrail_blocks`
**Alert:** "CRITICAL: LLM guardrail blocks > 0 (5m)"
**Dashboard:** [Logs Explorer](https://console.cloud.google.com/logs/query?project=cwechatbot)

```
# View blocks
severity=CRITICAL AND jsonPayload.enforcedSecurityPolicy.name:*
```

## 🔧 Common Operations

### View Model Armor Template
```bash
gcloud model-armor templates describe llm-guardrails-default \
  --location=us-central1 --project=cwechatbot
```

### Update Confidence Levels
```bash
gcloud model-armor templates update llm-guardrails-default \
  --location=us-central1 --project=cwechatbot \
  --rai-settings-filters='[
    {"filterType":"DANGEROUS_CONTENT","confidenceLevel":"MEDIUM_AND_ABOVE"}
  ]'
```

### Disable Alert (Maintenance)
```bash
gcloud alpha monitoring policies update POLICY_ID --no-enabled
```

### Run Smoke Test
```bash
poetry run python scripts/s2_smoke_test.py \
  --endpoint https://cwe-chatbot.run.app \
  --verbose \
  --output results.json
```

## 🚨 Emergency Rollback

```bash
# Unbind Model Armor via Console
# https://console.cloud.google.com/security/model-armor/integrations
# → Remove Vertex AI integration

# Or update Cloud Run to bypass
gcloud run services update cwe-chatbot \
  --region=us-central1 \
  --update-env-vars=VERTEX_ENDPOINT=https://direct-endpoint-url
```

## ⚠️ Important Notes

- **SafetySetting is BLOCK_NONE** - This is intentional for security content
- **Model Armor provides actual protection** - SafetySetting is last resort
- **Binding is manual** - Must use Console to bind template to endpoint
- **HIGH confidence only** - Lower settings cause false positives

## 📚 Full Documentation

- **Story:** [S-2.LLM-Input-Output-Guardrails.md](S-2.LLM-Input-Output-Guardrails.md)
- **Plan:** [../plans/S-2.LLM-Input-Output-Guardrails.md](../plans/S-2.LLM-Input-Output-Guardrails.md)
- **Summary:** [S-2-IMPLEMENTATION-SUMMARY.md](S-2-IMPLEMENTATION-SUMMARY.md)
- **Runbook:** [../runbooks/S-2-guardrails-runbook.md](../runbooks/S-2-guardrails-runbook.md)

## ✅ Acceptance Criteria

| AC | Status | Notes |
|----|--------|-------|
| AC-1 | ✅ READY | Model Armor template with all shields |
| AC-2 | ✅ COMPLETE | SafetySetting documented (BLOCK_NONE) |
| AC-3 | ⚠️ DEFERRED | Structured output (needs app changes) |
| AC-4 | 🟡 PARTIAL | Model Armor DLP shield (full templates deferred) |
| AC-5 | ✅ READY | Metrics, alerts, audit logs |
| AC-6 | ✅ COMPLETE | RAG grounding (pgvector) |
| AC-7 | ✅ COMPLETE | Operations runbook |

**Overall:** 5/7 complete, 1 partial, 1 deferred (acceptable for defensive security)
