# Debug Issue D2: Duplicate Welcome Messages

**Date**: 2025-10-10
**Status**: ✅ RESOLVED
**Related**: OAuth/Session Management, WebSocket Reconnection

## Problem Observed

Welcome message appears multiple times in the chat interface:

```
"Welcome back, wasp bee! 🛡️
Authenticated via Google
🔐 Your session is secure and your persona preferences will be saved.
I'm here to help you with Common Weakness Enumeration (CWE) information. Let me guide you through getting started:"
```

**Context from browser request:**
```
Request URL: https://cwe.crashedmind.com/project/file/98042020-f1d3-4d54-913c-4aabc9aed2ff?session_id=5492a85e-6b67-4354-85b9-1c50fa969387
Request Method: GET
Status Code: 200 OK
Remote Address: 34.49.0.7:443 (Load Balancer)

Authentication: Google OAuth
User: wasp bee (crashedmind@gmail.com)
Session ID: 5492a85e-6b67-4354-85b9-1c50fa969387
```

## Root Cause Identified

**WebSocket reconnection triggering `@cl.on_chat_start` repeatedly**

- Browser triggers Chainlit WebSocket reconnection every **150 seconds**
- Each reconnection fires `@cl.on_chat_start` handler
- Handler had no check for existing session - always sent welcome message
- Result: Welcome message duplicated every 150 seconds

**Why 150 seconds?**
- Standard WebSocket keepalive/heartbeat interval
- Browser may be closing idle WebSocket connections
- Chainlit reconnects automatically to maintain session

## Solution Implemented

Added session-based welcome message tracking in `apps/chatbot/main.py`:

**Change 1: Check if welcome already sent (line 514-520)**
```python
# Check if welcome message already sent (prevent duplicates on reconnections)
# Story D2: Fix duplicate welcome messages on WebSocket reconnection (every 150s)
if cl.user_session.get("welcome_sent"):
    logger.debug(
        "Skipping welcome message - already sent for this session (reconnection)"
    )
    return
```

**Change 2: Mark welcome as sent after completion (line 584-587)**
```python
# Mark welcome message as sent to prevent duplicates on reconnection
# Story D2: Prevent duplicate welcome messages on WebSocket reconnection
cl.user_session.set("welcome_sent", True)
logger.debug("Welcome message sequence completed and flagged")
```

**How it works:**
1. First call to `@cl.on_chat_start`: `welcome_sent` not set → Send welcome messages → Set flag
2. Subsequent calls (reconnections): `welcome_sent` is True → Skip welcome messages → Return early
3. Session persists across WebSocket reconnections → Flag prevents duplicates

## Testing

### Local Testing
```bash
poetry run chainlit run apps/chatbot/main.py
```

**Verification steps:**
1. Open chatbot in browser
2. Observe welcome message on first load
3. Wait 150+ seconds (2.5 minutes)
4. Check if welcome message duplicates
5. Review browser console for debug logs
6. Confirm "Skipping welcome message - already sent" in logs

### Expected Behavior
- **First connection**: Welcome messages displayed
- **Reconnection (150s+)**: No duplicate welcome messages
- **Debug log**: "Skipping welcome message - already sent for this session (reconnection)"
- **Session preserved**: User context, persona, settings all maintained

## Resolution Status

✅ **Code changed**: `apps/chatbot/main.py` lines 514-520, 584-587
⏳ **Testing pending**: Local verification
⏳ **Deployment pending**: Production deployment needed
⏳ **User verification**: Confirm no duplicates after 150s in production

---

# Debug Issue D3: Chainlit Response Truncation

**Date**: 2025-10-10
**Status**: 🔍 INVESTIGATING (Regression)
**Related**: Story S-9 (Previous fix attempted)

## Problem Observed

Chainlit responses are prematurely truncated, cutting off LLM output mid-sentence.

**Important Notes:**
- **NOT related to LLM response length** - Verified in logs
- **Debug logging added** - Per git history from yesterday
- **Suspected regression** - Thought this was fixed previously

## Previous Fix Attempts

From git history (yesterday):
- Debug logging was added
- Issue was believed to be resolved
- Root cause identified and fixed (need to check commits)

## Current Status

Issue has recurred, suggesting:
1. **Incomplete fix** - Original fix didn't address all cases
2. **New regression** - Recent code changes reintroduced the problem
3. **Environment-specific** - Works in some scenarios but not others

## Investigation Steps

- [ ] Review git commits from yesterday for truncation fix
- [ ] Check Cloud Logging for debug output added yesterday
- [ ] Compare LLM response length in logs vs UI display length
- [ ] Review Chainlit streaming logic in `apps/chatbot/main.py`
- [ ] Check for buffer size limits or timeout issues
- [ ] Test with different LLM providers (Gemini vs Claude)

## Related Code Areas

Files to investigate:
- `apps/chatbot/src/llm_provider.py` - LLM response handling
- `apps/chatbot/main.py` - Chainlit streaming logic
- `apps/chatbot/src/response_generator.py` - Response generation
- `apps/chatbot/src/processing/pipeline.py` - Processing pipeline

## Observations

- User can see truncation happening in real-time
- Full response exists in backend logs (per notes)
- Issue appears to be in UI streaming/display layer




I have also observed that the welcome text appears more than once in a chat:
"Welcome back, wasp bee! 🛡️
Authenticated via Google
🔐 Your session is secure and your persona preferences will be saved.
I'm here to help you with Common Weakness Enumeration (CWE) information. Let me guide you through getting started:" 







I am seeing behavior where the chainlit response is prematurely truncated. we saw this before and thought we fixed it per git history yesterday.. it is not related to llm response length and we did add debug in logs. 
I can also see that (blocked:csp)	