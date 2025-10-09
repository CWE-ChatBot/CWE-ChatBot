# S-12 Security Hardening - Safe Deployment Strategy

**Date**: 2025-10-09
**Status**: IN PROGRESS
**Risk Level**: MEDIUM (new security features could break existing functionality)

---

## Deployment Strategy: Blue-Green with Test Tag

### Overview
Deploy S-12 security features to a test revision first, validate functionality, then promote to production.

### Current Production State
- **Revision**: `cwe-chatbot-00166-djt`
- **Traffic**: 100% production
- **Status**: ✅ Fully operational
- **URL**: https://cwe.crashedmind.com (via load balancer)
- **Features**: OAuth, database, CWE queries all working

---

## Phase 1: Deploy to Test Tag (No Production Impact)

### Step 1: Build New Image
```bash
# Build with current changes (S-12 security features)
gcloud builds submit --config=apps/chatbot/cloudbuild.yaml

# Image will be: gcr.io/cwechatbot/cwe-chatbot:latest
```

### Step 2: Deploy to Test Revision
```bash
# Deploy with --no-traffic flag (0% production traffic)
gcloud run services update cwe-chatbot \
  --region=us-central1 \
  --image=gcr.io/cwechatbot/cwe-chatbot:latest \
  --tag=s12-test \
  --no-traffic

# This creates a new revision with tag 's12-test' receiving 0% traffic
# Accessible via: https://s12-test---cwe-chatbot-bmgj6wj65a-uc.a.run.app
```

**Result**: New revision deployed but production unaffected

---

## Phase 2: Test the New Revision

### Test URL
```
https://s12-test---cwe-chatbot-bmgj6wj65a-uc.a.run.app
```

### Testing Checklist

#### 1. Security Headers Verification
```bash
curl -I https://s12-test---cwe-chatbot-bmgj6wj65a-uc.a.run.app/
```

**Expected Headers**:
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`

#### 2. OAuth Flow
- Navigate to test URL in browser
- Sign in with Google → Verify success
- Sign in with GitHub → Verify success

#### 3. CWE Query Functionality
- Send test query: "What is CWE-79?"
- Verify response generation works
- Check for any CSP violations in browser console

#### 4. WebSocket Connection
- Verify chat messages send/receive
- Check browser dev tools Network tab for WS connection
- No console errors

#### 5. Browser Console Check
- Open browser dev tools (F12)
- Look for CSP violations
- Look for JavaScript errors
- Look for failed network requests

#### 6. Manual Security Testing
- Try XSS payload: `<img src=x onerror=alert(1)>`
- Verify it's sanitized (no alert pops up)
- Check that message displays safely

---

## Phase 3: Gradual Traffic Migration (If Tests Pass)

### Option A: Immediate Cutover (If Confident)
```bash
# Route 100% traffic to new revision
gcloud run services update-traffic cwe-chatbot \
  --region=us-central1 \
  --to-latest
```

### Option B: Gradual Rollout (Recommended)
```bash
# Start with 10% traffic to new revision
gcloud run services update-traffic cwe-chatbot \
  --region=us-central1 \
  --to-revisions=LATEST=10,cwe-chatbot-00166-djt=90

# Wait 10-15 minutes, monitor logs for errors

# If OK, increase to 50%
gcloud run services update-traffic cwe-chatbot \
  --region=us-central1 \
  --to-revisions=LATEST=50,cwe-chatbot-00166-djt=50

# Wait 10-15 minutes, monitor logs

# If OK, go to 100%
gcloud run services update-traffic cwe-chatbot \
  --region=us-central1 \
  --to-latest
```

### Option C: Canary Deployment (Most Conservative)
```bash
# 5% to new revision, monitor for 30 minutes
gcloud run services update-traffic cwe-chatbot \
  --region=us-central1 \
  --to-revisions=LATEST=5,cwe-chatbot-00166-djt=95

# Then gradually: 10%, 25%, 50%, 100%
```

---

## Phase 4: Monitoring During Rollout

### Check Logs
```bash
# Watch logs from new revision
gcloud logging tail "resource.type=cloud_run_revision \
  AND resource.labels.service_name=cwe-chatbot \
  AND resource.labels.revision_name~'cwe-chatbot-.*' \
  AND severity>=WARNING"
```

### Monitor Metrics
1. **Error Rate**: Should remain <1%
2. **Response Time**: Should stay <2s
3. **OAuth Success Rate**: Should stay ~100%
4. **WebSocket Connections**: Should establish successfully

### Key Indicators of Problems
- ❌ 403 Forbidden errors (WebSocket origin validation too strict)
- ❌ CSP violations blocking Chainlit UI
- ❌ OAuth redirect failures
- ❌ Increased 500 errors
- ❌ Failed database connections

---

## Rollback Procedure (If Issues Found)

### Quick Rollback
```bash
# Immediately route all traffic back to known-good revision
gcloud run services update-traffic cwe-chatbot \
  --region=us-central1 \
  --to-revisions=cwe-chatbot-00166-djt=100
```

### Delete Problematic Revision (Optional)
```bash
# Get revision name
gcloud run revisions list --service=cwe-chatbot --region=us-central1

# Delete specific revision
gcloud run revisions delete cwe-chatbot-XXXXX-yyy --region=us-central1
```

---

## Testing Commands Reference

### Build Image
```bash
cd /home/chris/work/CyberSecAI/cwe_chatbot_bmad
gcloud builds submit --config=apps/chatbot/cloudbuild.yaml
```

### Deploy to Test Tag
```bash
gcloud run services update cwe-chatbot \
  --region=us-central1 \
  --image=gcr.io/cwechatbot/cwe-chatbot:latest \
  --tag=s12-test \
  --no-traffic
```

### Get Test URL
```bash
gcloud run services describe cwe-chatbot --region=us-central1 \
  --format='value(status.traffic[?tag=="s12-test"].url)'
```

### Check Security Headers
```bash
TEST_URL=$(gcloud run services describe cwe-chatbot --region=us-central1 --format='value(status.traffic[?tag=="s12-test"].url)')
curl -I $TEST_URL
```

### View Logs
```bash
gcloud logging read "resource.type=cloud_run_revision \
  AND resource.labels.service_name=cwe-chatbot \
  AND resource.labels.revision_name~'cwe-chatbot-.*' \
  AND timestamp>\"$(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S)Z\"" \
  --limit 50
```

---

## Decision Tree

```
Deploy to Test Tag (--no-traffic --tag=s12-test)
    ↓
Test Security Headers Present? ──NO──> Fix headers, rebuild, redeploy
    ↓ YES
Test OAuth Working? ──NO──> Fix OAuth, rebuild, redeploy
    ↓ YES
Test CWE Queries Working? ──NO──> Fix queries, rebuild, redeploy
    ↓ YES
Test No CSP Violations? ──NO──> Adjust CSP to compatible mode, rebuild
    ↓ YES
Test XSS Sanitization? ──NO──> Fix sanitization, rebuild
    ↓ YES
Route 10% Traffic ──> Monitor 15 min ──> Errors? ──YES──> Rollback
    ↓ NO
Route 50% Traffic ──> Monitor 15 min ──> Errors? ──YES──> Rollback
    ↓ NO
Route 100% Traffic ──> Production deployment complete ✅
```

---

## Success Criteria

Before promoting to 100% production:
- ✅ All security headers present in responses
- ✅ OAuth flow working (Google and GitHub)
- ✅ CWE queries returning results
- ✅ No CSP violations in browser console
- ✅ XSS payloads sanitized
- ✅ WebSocket connections establishing
- ✅ No increase in error rate
- ✅ Response times normal (<2s)
- ✅ At least 5 successful test queries

---

## Timeline Estimate

- **Phase 1 (Build & Deploy to Test)**: 15 minutes
- **Phase 2 (Testing)**: 30-45 minutes
- **Phase 3 (Gradual Rollout)**: 30-60 minutes
- **Total**: 1.5-2 hours for safe deployment

---

## Current Status

- ✅ Security modules implemented (middleware, CSRF, sanitization)
- 🔄 Main.py partially updated (middleware added, CSRF integration pending)
- ⏸️ **PAUSED FOR SAFE DEPLOYMENT STRATEGY**

**Next Steps**:
1. Complete main.py updates (CSRF in on_chat_start)
2. Write unit tests
3. Build image
4. Deploy to test tag
5. Test thoroughly
6. Gradual production rollout

---

## Recommendation

**Use Option B (Gradual Rollout)**: 10% → 50% → 100%

This provides good balance between safety and speed:
- Catches issues early with 10% traffic
- Validates at scale with 50% traffic
- Full deployment once confident

**Do NOT use immediate cutover** - S-12 introduces significant changes (middleware, headers, CSRF) that could have unexpected interactions with Chainlit UI.
