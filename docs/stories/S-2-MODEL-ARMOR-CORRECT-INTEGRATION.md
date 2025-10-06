# Model Armor Correct Integration Method

**Date**: 2025-10-06
**Status**: Research Complete - Implementation Pending

## Key Discovery

Based on Google Cloud documentation:
- https://cloud.google.com/security-command-center/docs/model-armor-vertex-integration
- https://atamel.dev/posts/2025/08-11_secure_llm_model_armor/

**Model Armor is NOT bound via Console**. Instead, it's configured **at the API call level** using the `model_armor_config` parameter.

## Correct Integration Method

### REST API Format

```bash
curl -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://us-central1-aiplatform.googleapis.com/v1/projects/cwechatbot/locations/us-central1/publishers/google/models/gemini-2.0-flash-001:generateContent" \
  -d '{
    "contents": [{
        "role": "user",
        "parts": [{"text": "What is CWE-79?"}]
    }],
    "generationConfig": {
        "temperature": 0.1,
        "maxOutputTokens": 8192
    },
    "model_armor_config": {
        "prompt_template_name": "projects/cwechatbot/locations/us-central1/templates/llm-guardrails-default",
        "response_template_name": "projects/cwechatbot/locations/us-central1/templates/llm-guardrails-default"
    }
}'
```

### Key Parameters

- `model_armor_config`: Object containing template names
- `prompt_template_name`: Full template path for input screening
- `response_template_name`: Full template path for output screening
- Template format: `projects/PROJECT_ID/locations/LOCATION/templates/TEMPLATE_ID`

## Python SDK Investigation Needed

**Question**: Does the Vertex AI Python SDK (`vertexai.generative_models.GenerativeModel`) support the `model_armor_config` parameter?

### Option 1: Python SDK Support (Preferred)

If the SDK supports it, we'd add:

```python
# In VertexProvider.__init__
self._model_armor_config = {
    "prompt_template_name": f"projects/{project}/locations/{location}/templates/llm-guardrails-default",
    "response_template_name": f"projects/{project}/locations/{location}/templates/llm-guardrails-default"
}

# In generate_content_async calls
resp = await self._model.generate_content_async(
    prompt,
    generation_config=self._gen_cfg,
    safety_settings=self._safety,
    model_armor_config=self._model_armor_config,  # ADD THIS
)
```

### Option 2: REST API Fallback (If SDK doesn't support)

If the Python SDK doesn't support `model_armor_config` yet, we need to:

1. Use the Vertex AI REST API directly
2. Call `https://{location}-aiplatform.googleapis.com/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:generateContent`
3. Pass `model_armor_config` in the request body

**Implementation**:

```python
import aiohttp
import google.auth
from google.auth.transport.requests import Request

async def generate_with_model_armor(self, prompt: str) -> str:
    # Get credentials
    creds, project = google.auth.default()
    creds.refresh(Request())

    # Build REST API URL
    url = f"https://{self._location}-aiplatform.googleapis.com/v1/projects/{self._project}/locations/{self._location}/publishers/google/models/{self._model_name}:generateContent"

    # Build request body
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": self._gen_cfg,
        "model_armor_config": {
            "prompt_template_name": f"projects/{self._project}/locations/{self._location}/templates/llm-guardrails-default",
            "response_template_name": f"projects/{self._project}/locations/{self._location}/templates/llm-guardrails-default"
        }
    }

    # Make request
    async with aiohttp.ClientSession() as session:
        async with session.post(
            url,
            headers={"Authorization": f"Bearer {creds.token}"},
            json=body
        ) as resp:
            data = await resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
```

## Environment Variable Configuration

```bash
# Add to Cloud Run
MODEL_ARMOR_ENABLED=true
MODEL_ARMOR_TEMPLATE_ID=llm-guardrails-default
```

## Implementation Steps

1. **Test REST API first** - Verify Model Armor template works via curl
2. **Check Python SDK** - Test if `model_armor_config` parameter is accepted
3. **Implement solution**:
   - If SDK supports: Add parameter to generate_content_async
   - If SDK doesn't support: Use REST API directly
4. **Add env var control** - Make Model Armor optional via environment variable
5. **Deploy and test** - Verify guardrails are blocking attacks

## Expected Behavior After Integration

When Model Armor is active:

1. **Prompt Injection** → Returns 400/403 with enforcement metadata
2. **Jailbreak Attempts** → Blocked with CRITICAL log entry
3. **PII in Prompts** → DLP filter blocks or sanitizes
4. **Observability** → `llm_guardrail_blocks` metric increments

## Next Actions

1. Test REST API with curl to verify template works
2. Check if Python SDK accepts `model_armor_config`
3. Implement whichever method works
4. Document actual behavior in production

## References

- [Model Armor Vertex Integration](https://cloud.google.com/security-command-center/docs/model-armor-vertex-integration)
- [Model Armor Blog Post](https://atamel.dev/posts/2025/08-11_secure_llm_model_armor/)
- [Vertex AI REST API](https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/gemini)
