# Model Armor Template Binding - Manual Steps

**Status**: Template Created ✅ | Binding to Vertex AI ⏳

## Template Details
- **Template ID**: `llm-guardrails-default`
- **Location**: `projects/cwechatbot/locations/us-central1/templates/llm-guardrails-default`
- **Project**: `cwechatbot`

## Manual Binding Steps (Console Required)

Since gcloud CLI commands are blocked by org permissions, complete binding via Console:

### Step 1: Navigate to Model Armor Integrations
```
https://console.cloud.google.com/security/model-armor/integrations?project=cwechatbot
```

### Step 2: Add Vertex AI Integration
1. Click **"Add Integration"**
2. Select **"Vertex AI"**
3. Choose integration settings:
   - **Project**: cwechatbot
   - **Location**: us-central1
   - **Template**: llm-guardrails-default

### Step 3: Verify Binding
After binding, the template should apply to all Vertex AI API calls in us-central1.

**Verification**: Check Cloud Run logs for Model Armor enforcement messages after sending test queries.

## Alternative: API-Based Binding (if Console blocked)

If you need to use REST API instead:

```bash
# Get OAuth token
TOKEN=$(gcloud auth print-access-token)

# Bind template to Vertex AI
curl -X POST \
  "https://modelarmor.googleapis.com/v1/projects/cwechatbot/locations/us-central1/integrations" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "integration": {
      "vertexAiIntegration": {
        "project": "cwechatbot",
        "location": "us-central1",
        "templateId": "llm-guardrails-default"
      }
    }
  }'
```

## Expected Behavior After Binding

Once bound, Model Armor will:
1. **Intercept** all Vertex AI generate_content calls
2. **Scan** prompts for prompt injection, jailbreaks, PII
3. **Block** HIGH confidence threats (returns 400/403 with enforcement metadata)
4. **Log** all enforcement actions to Cloud Logging

**Next Step**: After binding, proceed to observability deployment and smoke testing.
