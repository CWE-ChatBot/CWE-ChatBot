# Phase 5 Troubleshooting Log

## Issue 1: "Startup error: configuration missing or database unavailable"

**Date**: 2025-10-05 20:00 UTC
**Symptom**: Accessing https://cwe-chatbot-bmgj6wj65a-uc.a.run.app showed error message instead of Chainlit UI

**Root Cause**:
Cloud Run traffic routing was misconfigured. 100% of traffic was routed to the "test" tag instead of the default route, which meant the main URL had no active revision serving requests.

**Diagnosis Steps**:
1. Checked logs: `_init_ok=False`, `conversation_manager=None`
2. Verified secrets configured correctly (GEMINI_API_KEY, DB_PASSWORD)
3. Found initialization completed successfully at deployment (17:14)
4. Discovered traffic routing issue:
   ```bash
   gcloud run services describe cwe-chatbot --format="value(status.traffic)"
   # Output: test -> cwe-chatbot-00136-wwp (100%)
   # Main URL had 0% traffic!
   ```

**Fix**:
```bash
gcloud run services update-traffic cwe-chatbot \
  --region=us-central1 \
  --project=cwechatbot \
  --to-latest
```

**Result**:
- ✅ Traffic now routes 100% to LATEST revision
- ✅ Main URL accessible (HTTP 200)
- ✅ Chainlit UI loads correctly
- ✅ Test tag still available at: https://test---cwe-chatbot-bmgj6wj65a-uc.a.run.app

**Prevention**:
- Always verify traffic routing after deployment
- Use `--to-latest` flag during deployment to avoid creating orphaned tags
- Check both main URL and test URL are accessible

---

## Verification Commands

### Check Traffic Routing
```bash
gcloud run services describe cwe-chatbot \
  --region=us-central1 \
  --project=cwechatbot \
  --format=json | jq -r '.status.traffic[]'
```

Expected output should show 100% to default route:
```json
{
  "latestRevision": true,
  "percent": 100,
  "revisionName": "cwe-chatbot-00136-wwp"
}
```

### Test Main URL
```bash
curl -sI https://cwe-chatbot-bmgj6wj65a-uc.a.run.app | head -5
# Should return: HTTP/2 200
```

### Check Initialization Status
```bash
gcloud logging read 'resource.type="cloud_run_revision"
  resource.labels.service_name="cwe-chatbot"
  "initialize_components() called"' \
  --limit=5 --project=cwechatbot \
  --format="value(timestamp,textPayload)"
```

---

## Common Issues and Solutions

### Issue: "configuration missing or database unavailable"

**Possible Causes**:
1. Traffic routing misconfigured (no default route) ✅ RESOLVED
2. Secrets not accessible
3. Database connection failure
4. Environment variables missing

**Debug Steps**:
```bash
# 1. Check traffic routing
gcloud run services describe cwe-chatbot --format="value(status.traffic)"

# 2. Check secrets configuration
gcloud run services describe cwe-chatbot --format=json | \
  jq -r '.spec.template.spec.containers[0].env[] | select(.valueFrom.secretKeyRef)'

# 3. Check initialization logs
gcloud logging read 'resource.labels.service_name="cwe-chatbot"
  "Configuration errors"' --limit=10

# 4. Check database connectivity
gcloud logging read 'resource.labels.service_name="cwe-chatbot"
  "database" OR "PostgreSQL"' --limit=10
```

### Issue: OAuth Login Not Working

**Check**:
1. CHAINLIT_AUTH_SECRET configured
2. OAuth provider secrets configured
3. Callback URLs match deployment URL

```bash
gcloud run services describe cwe-chatbot --format=json | \
  jq -r '.spec.template.spec.containers[0].env[] | select(.name | contains("OAUTH"))'
```

### Issue: PDF Upload Fails

**Check**:
1. PDF_WORKER_URL environment variable set
2. Chainlit SA has invoker permissions on PDF worker
3. PDF worker is ACTIVE

```bash
# Check environment variable
gcloud run services describe cwe-chatbot --format=json | \
  jq -r '.spec.template.spec.containers[0].env[] | select(.name=="PDF_WORKER_URL")'

# Check PDF worker status
gcloud functions describe pdf-worker --region=us-central1 --gen2 \
  --format="value(state)"

# Check IAM permissions
gcloud functions get-iam-policy pdf-worker --region=us-central1 --gen2
```

---

## Status After Fixes

✅ All issues resolved
✅ Chainlit UI accessible
✅ Traffic routing correct
✅ Ready for Phase 5 E2E testing
