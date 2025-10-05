# Phase 5: E2E Testing Guide - Chainlit UI File Upload

**Date**: 2025-10-05
**Status**: Ready for Manual Testing
**Prerequisite**: Phase 0-4 complete, PDF worker deployed and tested

---

## Test Environment

- **Chainlit URL**: https://cwe-chatbot-bmgj6wj65a-uc.a.run.app
- **PDF Worker URL**: https://pdf-worker-bmgj6wj65a-uc.a.run.app
- **Test Fixtures**: `tests/fixtures/sample.pdf`, `encrypted.pdf`, `scanned.pdf`

---

## Pre-Test Verification

### Verify Deployment Status
```bash
# Check Chainlit is running
curl -sI https://cwe-chatbot-bmgj6wj65a-uc.a.run.app | head -5

# Check PDF worker is accessible
curl -sI https://pdf-worker-bmgj6wj65a-uc.a.run.app | head -5

# Verify PDF_WORKER_URL environment variable is set
gcloud run services describe cwe-chatbot --region=us-central1 --project=cwechatbot \
  --format="value(spec.template.spec.containers[0].env)" | grep PDF_WORKER_URL
```

Expected:
- Chainlit returns HTTP 200 or 302
- PDF worker returns HTTP 403 (requires auth)
- PDF_WORKER_URL = https://pdf-worker-bmgj6wj65a-uc.a.run.app

---

## Test Cases

### Test 1: OAuth Authentication
**Objective**: Verify user can log in via Google or GitHub OAuth

**Steps**:
1. Open https://cwe-chatbot-bmgj6wj65a-uc.a.run.app in browser
2. Click "Sign in with Google" or "Sign in with GitHub"
3. Complete OAuth flow
4. Verify you see the chat interface

**Expected**:
- OAuth login succeeds
- User sees welcome message
- Chat interface is functional

**Pass Criteria**: ✅ User successfully authenticated and can see chat

---

### Test 2: Upload Valid PDF (sample.pdf)
**Objective**: Verify PDF upload, worker processing, and text extraction

**Steps**:
1. In chat, click the "Attach Files" button (📎 icon)
2. Select `tests/fixtures/sample.pdf` (2-page PDF with text)
3. Type message: "What's in this PDF?"
4. Send message
5. Observe processing steps

**Expected**:
- File upload succeeds
- "Process file attachments" step shows
- PDF sent to worker via OIDC
- Text extracted: "CWE ChatBot Test Document\n\nThis is page 1 of 2..."
- Response references the PDF content
- No errors displayed

**Verification**:
```bash
# Check Cloud Run logs for successful PDF processing
gcloud logging read 'resource.type="cloud_run_revision"
  resource.labels.service_name="cwe-chatbot"
  timestamp>="2025-10-05T19:00:00Z"' \
  --limit=20 --project=cwechatbot --format=json | \
  jq -r '.[] | select(.textPayload | contains("File content extracted")) | .textPayload'
```

**Pass Criteria**:
✅ PDF uploaded successfully
✅ Text extracted (shows character count in logs)
✅ Response uses PDF content
✅ No errors in UI or logs

---

### Test 3: Upload Text File (.txt)
**Objective**: Verify text files are processed locally (no PDF worker call)

**Steps**:
1. Create test file: `echo "This is a test document about CWE-79 XSS" > test.txt`
2. In chat, attach `test.txt`
3. Type message: "Summarize this file"
4. Send message

**Expected**:
- File upload succeeds
- Text file processed locally (fast, no worker call)
- Content extracted: "This is a test document about CWE-79 XSS"
- Response references the text content

**Verification**:
```bash
# Verify NO calls to PDF worker for .txt files
gcloud logging read 'resource.type="cloud_run_revision"
  resource.labels.service_name="pdf-worker"
  timestamp>="2025-10-05T19:30:00Z"' \
  --limit=10 --project=cwechatbot
# Should show minimal/no recent activity
```

**Pass Criteria**:
✅ Text file processed locally
✅ No PDF worker calls in logs
✅ Content correctly extracted

---

### Test 4: Oversized File (11MB PDF)
**Objective**: Verify file size validation (10MB limit)

**Steps**:
1. Create oversized PDF:
   ```bash
   # Create an 11MB file
   dd if=/dev/zero of=large.pdf bs=1M count=11
   ```
2. Attempt to upload `large.pdf`
3. Observe error message

**Expected**:
- Upload rejected OR friendly error message
- Message: "File too large (11MB). Maximum size: 10MB"
- No crash or silent failure

**Pass Criteria**:
✅ Oversized file rejected with friendly error
✅ No server errors
✅ User can continue chatting

---

### Test 5: Encrypted PDF
**Objective**: Verify encrypted PDFs are rejected gracefully

**Steps**:
1. Upload `tests/fixtures/encrypted.pdf`
2. Type message: "What's in this PDF?"
3. Observe error handling

**Expected**:
- Upload succeeds (file is valid PDF)
- PDF worker returns 422 (encrypted/password-protected)
- User sees friendly error: "This PDF is password-protected and cannot be processed"
- No crash or stack trace shown to user

**Verification**:
```bash
# Check PDF worker logs for encryption detection
gcloud logging read 'resource.type="cloud_run_revision"
  resource.labels.service_name="pdf-worker"
  severity>=WARNING
  timestamp>="2025-10-05T19:40:00Z"' \
  --limit=10 --project=cwechatbot --format="value(textPayload)"
```

**Pass Criteria**:
✅ Encrypted PDF detected
✅ Friendly error message shown
✅ User can retry with different file

---

### Test 6: PDF with JavaScript/Embedded Files
**Objective**: Verify PDF sanitization removes dangerous elements

**Steps**:
1. Create malicious PDF with JavaScript (optional - can skip if no tool available)
2. Upload PDF
3. Verify it's sanitized before text extraction

**Expected**:
- PDF processed successfully
- Response metadata shows: `"sanitized": true`
- JavaScript/embedded files removed
- Text still extracted

**Verification**:
```bash
# Check for sanitization in logs
gcloud logging read 'resource.type="cloud_run_revision"
  resource.labels.service_name="pdf-worker"
  jsonPayload.sanitized=true
  timestamp>="2025-10-05T19:45:00Z"' \
  --limit=5 --project=cwechatbot
```

**Pass Criteria**:
✅ PDF sanitized before processing
✅ Dangerous elements removed
✅ Text extraction still works

---

### Test 7: Log Security - No Content Leakage
**Objective**: Verify PDF content doesn't appear in logs (metadata only)

**Steps**:
1. Upload `sample.pdf` (contains "CWE ChatBot Test Document")
2. After processing, check logs for content

**Expected**:
- Logs show metadata (file size, page count, character count)
- Logs DO NOT show actual PDF text content
- No "CWE ChatBot Test Document" string in logs

**Verification**:
```bash
# Search for PDF content in logs (should find NOTHING)
gcloud logging read 'resource.type="cloud_run_revision"
  (resource.labels.service_name="cwe-chatbot" OR resource.labels.service_name="pdf-worker")
  "CWE ChatBot Test Document"
  timestamp>="2025-10-05T19:00:00Z"' \
  --limit=10 --project=cwechatbot

# Should return: "Listed 0 items." (no matches)

# Verify only metadata is logged
gcloud logging read 'resource.type="cloud_run_revision"
  resource.labels.service_name="pdf-worker"
  timestamp>="2025-10-05T19:50:00Z"' \
  --limit=10 --project=cwechatbot --format="value(textPayload)" | \
  grep -E "(pages|size|characters)"
```

**Pass Criteria**:
✅ PDF content NOT in logs
✅ Only metadata logged (pages, size, char count)
✅ Security requirement met

---

### Test 8: Scanned/Image-Only PDF
**Objective**: Verify image-only PDFs handled gracefully (no OCR)

**Steps**:
1. Upload `tests/fixtures/scanned.pdf`
2. Type message: "What's in this PDF?"
3. Observe response

**Expected**:
- Upload succeeds
- PDF worker returns 200 (valid PDF)
- Minimal/no text extracted (image-only)
- Friendly message: "This appears to be a scanned/image-only PDF. Text extraction not available."

**Pass Criteria**:
✅ Image PDF handled without crash
✅ Friendly error/warning shown
✅ User informed about limitation

---

## Success Criteria

**All 8 tests must pass** for Phase 5 completion:

- [ ] Test 1: OAuth authentication working
- [ ] Test 2: Valid PDF processed and text extracted
- [ ] Test 3: Text files processed locally
- [ ] Test 4: Oversized files rejected gracefully
- [ ] Test 5: Encrypted PDFs rejected with friendly error
- [ ] Test 6: PDF sanitization working (JavaScript/embeds removed)
- [ ] Test 7: No PDF content in logs (metadata only)
- [ ] Test 8: Scanned PDFs handled gracefully

---

## Post-Test Verification

### Performance Check
```bash
# Check p95 latency for PDF processing
gcloud logging read 'resource.type="cloud_run_revision"
  resource.labels.service_name="pdf-worker"
  httpRequest.status=200
  timestamp>="2025-10-05T19:00:00Z"' \
  --limit=100 --project=cwechatbot --format=json | \
  jq -r '.[] | .httpRequest.latency' | \
  sed 's/s$//' | sort -n | awk '{arr[NR]=$1} END {print "p95:", arr[int(NR*0.95)]}'
```

**Target**: p95 < 5s for PDF processing

### Error Rate Check
```bash
# Check for any 5xx errors
gcloud logging read 'resource.type="cloud_run_revision"
  (resource.labels.service_name="cwe-chatbot" OR resource.labels.service_name="pdf-worker")
  httpRequest.status>=500
  timestamp>="2025-10-05T19:00:00Z"' \
  --limit=10 --project=cwechatbot
```

**Target**: Zero 5xx errors

---

## Troubleshooting

### PDF Upload Fails
1. Check FileProcessor initialization in logs
2. Verify PDF_WORKER_URL environment variable
3. Test PDF worker directly (see Phase 0 tests)

### No Text Extracted
1. Check PDF worker logs for errors
2. Verify pikepdf version (should have .Root fix)
3. Test with different PDF file

### Authentication Issues
1. Verify OAuth secrets are configured
2. Check CHAINLIT_AUTH_SECRET is set
3. Test with different browser (clear cookies)

### 401/403 Errors from PDF Worker
1. Verify IAM permissions (roles/run.invoker)
2. Check OIDC token generation in logs
3. Verify service account has invoker role

---

## Report Template

After completing all tests, document results:

```markdown
# Phase 5 E2E Test Results

**Date**: [DATE]
**Tester**: [NAME]
**Environment**: Production (cwe-chatbot-bmgj6wj65a-uc.a.run.app)

## Test Results

| Test | Status | Notes |
|------|--------|-------|
| T1: OAuth Login | ✅ PASS | Google OAuth working |
| T2: Valid PDF | ✅ PASS | Text extracted: 143 chars |
| T3: Text File | ✅ PASS | Processed locally |
| T4: Oversized File | ✅ PASS | Rejected with friendly error |
| T5: Encrypted PDF | ✅ PASS | 422 error, friendly message |
| T6: Sanitization | ✅ PASS | JavaScript removed |
| T7: Log Security | ✅ PASS | No content in logs |
| T8: Scanned PDF | ✅ PASS | Warning shown |

## Performance Metrics

- PDF processing latency (p95): [X]s
- Error rate: [X]%
- Upload success rate: [X]%

## Issues Found

[None / List any issues]

## Sign-off

Phase 5 E2E testing: **COMPLETE** ✅

Story 4.3 ready for: **Production Release**
```

---

## Next Steps After Phase 5

1. Update Story 4.3 status to "Ready for Review"
2. Document any issues found
3. Optional: Configure Cloud Armor rate limiting (Phase 6)
4. Create pull request / deployment summary
5. Update CURATION_NOTES.md with lessons learned
