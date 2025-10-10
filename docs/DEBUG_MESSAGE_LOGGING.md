# Debug Message Logging Feature

**Purpose:** Enable detailed logging of user messages and AI responses for testing and debugging production issues.

**Status:** Implemented (2025-10-10)
**Related:** Debug issues D1, D2, D3

## Overview

When investigating production issues (response truncation, message handling, etc.), we need visibility into actual user messages and responses. This feature provides controlled logging with privacy protection.

## Configuration

### Environment Variable

```bash
DEBUG_LOG_MESSAGES=true  # Enable debug logging (default: false)
```

**Important:** Set to `false` in production after debugging is complete to protect user privacy.

### Implementation

**File:** `apps/chatbot/src/app_config.py`
```python
# Debug: Log user messages and responses (enable for testing/debugging, disable in production)
debug_log_messages: bool = (
    os.getenv("DEBUG_LOG_MESSAGES", "false").lower() == "true"
)
```

## What Gets Logged

When `DEBUG_LOG_MESSAGES=true`:

### 1. User Messages (Inbound)
```
[DEBUG_MSG] User: crashedmind@gmail.com | Message: What is CWE-79 and how do I prevent it?
```

**Format:**
- User email (if authenticated) or "anonymous"
- First 200 characters of message (truncated if longer)
- Tagged with `[DEBUG_MSG]` for easy filtering

### 2. AI Responses (Outbound)
```
[DEBUG_RESP] User: crashedmind@gmail.com | Response length: 4193 chars | First 200: Cross-Site Scripting (XSS) is a...
```

**Format:**
- User email (if authenticated) or "anonymous"
- Total response length in characters
- First 200 characters of response (truncated if longer)
- Tagged with `[DEBUG_RESP]` for easy filtering

## Privacy Protection

### Automatic Safeguards

1. **Truncation**: Only first 200 chars logged (prevents logging entire conversations)
2. **User identification**: Email only (no PII beyond authentication identity)
3. **Default disabled**: Must explicitly enable via environment variable
4. **Clear tagging**: Easy to identify and filter debug logs

### Sensitive Data Handling

**What is NOT logged:**
- Full message content (only first 200 chars)
- File attachments
- Internal system prompts
- Database query results
- Retrieved CWE chunks

**What IS logged:**
- User email (authentication identity)
- Message preview (200 chars)
- Response length and preview
- Timestamps (from Cloud Logging)

## Usage

### Enable for Testing

**Local development:**
```bash
export DEBUG_LOG_MESSAGES=true
poetry run chainlit run apps/chatbot/main.py
```

**Production (Cloud Run):**
```bash
gcloud run services update cwe-chatbot \
  --region us-central1 \
  --set-env-vars DEBUG_LOG_MESSAGES=true
```

### Query Debug Logs

**Get all debug messages:**
```bash
gcloud logging read 'resource.type="cloud_run_revision"
  AND resource.labels.service_name="cwe-chatbot"
  AND (textPayload=~"DEBUG_MSG" OR textPayload=~"DEBUG_RESP")' \
  --limit=100 --format=json | \
  jq -r '.[] | select(.textPayload) | "\(.timestamp) | \(.textPayload)"'
```

**Get messages from specific user:**
```bash
gcloud logging read 'resource.type="cloud_run_revision"
  AND resource.labels.service_name="cwe-chatbot"
  AND textPayload=~"DEBUG_MSG.*crashedmind@gmail.com"' \
  --limit=50
```

**Get responses only:**
```bash
gcloud logging read 'resource.type="cloud_run_revision"
  AND resource.labels.service_name="cwe-chatbot"
  AND textPayload=~"DEBUG_RESP"' \
  --limit=50
```

### Disable After Debugging

```bash
gcloud run services update cwe-chatbot \
  --region us-central1 \
  --remove-env-vars DEBUG_LOG_MESSAGES
```

Or explicitly set to false:
```bash
gcloud run services update cwe-chatbot \
  --region us-central1 \
  --set-env-vars DEBUG_LOG_MESSAGES=false
```

## Use Cases

### 1. Response Truncation Investigation (D3)
Enable debug logging to compare:
- User query content (what they asked)
- Response length (how much was generated)
- Response preview (what was actually sent)

Compare with `finish_reason` logs to diagnose truncation:
```bash
# Get both debug logs and finish_reason logs
gcloud logging read 'resource.type="cloud_run_revision"
  AND resource.labels.service_name="cwe-chatbot"
  AND (textPayload=~"DEBUG_RESP" OR textPayload=~"finish_reason")' \
  --limit=100
```

### 2. Message Handling Issues (D2)
Verify messages are being received and processed:
```bash
# Check message flow for specific user
gcloud logging read 'resource.type="cloud_run_revision"
  AND resource.labels.service_name="cwe-chatbot"
  AND textPayload=~"crashedmind@gmail.com"
  AND (textPayload=~"DEBUG_MSG" OR textPayload=~"DEBUG_RESP")' \
  --limit=20
```

### 3. Query Pattern Analysis
Understand common user queries:
```bash
# Extract all user messages (first 200 chars)
gcloud logging read 'resource.type="cloud_run_revision"
  AND resource.labels.service_name="cwe-chatbot"
  AND textPayload=~"DEBUG_MSG"' \
  --limit=100 --format=json | \
  jq -r '.[] | select(.textPayload) | .textPayload' | \
  awk -F'Message: ' '{print $2}'
```

## Security Considerations

### ✅ Safe Practices

1. **Temporary enablement**: Only enable during active debugging
2. **Truncated content**: Only 200 chars logged (not full conversations)
3. **No sensitive data**: File contents, prompts, RAG results not logged
4. **Clear markers**: Easy to identify and purge debug logs

### ⚠️ Risks to Manage

1. **User privacy**: Messages contain user queries (could include sensitive CWE questions)
2. **Log retention**: Debug logs persist in Cloud Logging (90-day default retention)
3. **Cost**: More logs = higher Cloud Logging costs

### 🛡️ Mitigation

1. **Disable after debugging**: Always turn off when investigation complete
2. **Document usage**: Log when debug logging enabled/disabled
3. **Limited retention**: Consider shorter retention for debug logs
4. **Access control**: Only admins can read Cloud Logging

## Implementation Details

### Code Locations

**Configuration:**
- `apps/chatbot/src/app_config.py` line 108-110

**Message logging:**
- `apps/chatbot/main.py` line 599-608 (in `@cl.on_message` handler)

**Response logging:**
- `apps/chatbot/main.py` line 781-791 (after response generation)

### Log Format

```
[DEBUG_MSG] User: {email} | Message: {first_200_chars}
[DEBUG_RESP] User: {email} | Response length: {length} chars | First 200: {first_200_chars}
```

**Tags for filtering:**
- `[DEBUG_MSG]` - User messages
- `[DEBUG_RESP]` - AI responses

## Best Practices

### When to Enable

✅ **Good reasons:**
- Investigating reported truncation issues
- Debugging message handling problems
- Analyzing query patterns for improvement
- Reproducing user-reported bugs

❌ **Bad reasons:**
- "Always on" monitoring (use metrics instead)
- User behavior surveillance
- Performance profiling (use separate metrics)

### Deployment Workflow

```bash
# 1. Enable for testing
gcloud run services update cwe-chatbot --set-env-vars DEBUG_LOG_MESSAGES=true

# 2. Reproduce issue or collect data
# (use for specific investigation)

# 3. Query logs for analysis
gcloud logging read '...' --limit=100

# 4. Disable when done
gcloud run services update cwe-chatbot --remove-env-vars DEBUG_LOG_MESSAGES

# 5. Document findings in debug issue tracker (docs/stories/S2/)
```

### Documentation

**Always document:**
- When debug logging was enabled
- Why it was enabled (which issue)
- When it was disabled
- Key findings from the logs

**Example:**
```markdown
## Debug Logging Session

**Date:** 2025-10-10 15:00-16:30 UTC
**Enabled by:** crashedmind@gmail.com
**Reason:** Investigating D3 truncation issue
**Findings:** Found 1/17 queries hitting MAX_TOKENS limit (250K chars)
**Disabled:** 2025-10-10 16:30 UTC
```

## Related Documentation

- [D3: Response Truncation Investigation](docs/stories/S2/D3_truncation.md)
- [Cloud Logging Query Examples](https://cloud.google.com/logging/docs/view/logging-query-language)
- [Privacy Policy](docs/PRIVACY.md) (if applicable)

## Monitoring

### Check if Enabled

```bash
gcloud run services describe cwe-chatbot \
  --region us-central1 \
  --format="value(spec.template.spec.containers[0].env)" | \
  grep DEBUG_LOG_MESSAGES
```

**Expected when disabled:**
- Empty output or `DEBUG_LOG_MESSAGES=false`

**Expected when enabled:**
- `DEBUG_LOG_MESSAGES=true`

### Log Volume Impact

Estimate: ~200 bytes per debug log event
- User message: ~100 bytes
- AI response: ~100 bytes
- Total per interaction: ~200 bytes

For 1000 messages/day: ~200 KB/day = ~6 MB/month (negligible cost impact)

## Summary

Debug message logging provides targeted visibility for troubleshooting while maintaining:
- ✅ Privacy (truncated, no sensitive data)
- ✅ Security (admin-only access, temporary enablement)
- ✅ Utility (clear markers, easy querying)
- ✅ Cost-effectiveness (minimal log volume)

**Default state:** DISABLED
**Recommended usage:** Enable temporarily during active debugging only
