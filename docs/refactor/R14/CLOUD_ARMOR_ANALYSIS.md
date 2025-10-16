# Cloud Armor Rules Analysis & Recommendations

**Date**: October 16, 2025
**Policy**: cwe-chatbot-armor
**Total Rules**: 10

---

## Current Rules Summary

| Priority | Action | Description | Status |
|----------|--------|-------------|--------|
| 100 | allow | GET/HEAD root & /api/health | ✅ Good |
| 110 | allow | JSON API requests ≤10MB | ✅ Good (just updated) |
| 900 | rate_based_ban | Per-user rate limit (x-user-id) | ⚠️ Needs review |
| 995 | allow | WebSocket prod origin | ⚠️ Redundant |
| 996 | allow | WebSocket staging origin | ⚠️ Redundant |
| 1000 | allow | WebSocket same-origin (regex) | ✅ Good |
| 1100 | deny | WebSocket cross-origin | ⚠️ Redundant |
| 1200 | deny | WebSocket no Origin header | ⚠️ Redundant |
| 1300 | rate_based_ban | Per-IP rate limiting | ✅ Good |
| 2147483647 | deny | Default deny all | ✅ Essential |

---

## Issues Identified

### 🔴 CRITICAL: Redundant WebSocket Rules

**Problem**: Rules overlap and may conflict

**Current WebSocket Logic**:
1. Priority 995: Allow WS from `https://cwe.crashedmind.com` (exact match)
2. Priority 996: Allow WS from `https://staging-cwe.crashedmind.com` (exact match)
3. Priority 1000: Allow WS matching regex `https://.*cwe\.crashedmind\.com` (catches both!)
4. Priority 1100: Deny WS with origin (catches all WebSocket not already allowed)
5. Priority 1200: Deny WS without origin header

**Issue**: Rules 995 and 996 are **redundant** - Rule 1000 already allows both origins via regex!

**Risk**:
- Confusion about which rule applies
- Harder to maintain (must update 3 rules instead of 1)
- Performance impact (unnecessary rule evaluations)

### ⚠️ MEDIUM: Per-User Rate Limit (Priority 900)

**Current Rule**:
```json
{
  "priority": 900,
  "description": "",  // ← Empty description!
  "match": "has(request.headers['x-user-id'])",
  "enforceOnKey": "HTTP_HEADER",
  "enforceOnKeyName": "x-user-id",
  "rateLimitThreshold": {
    "count": 60,
    "intervalSec": 60
  },
  "banThreshold": {
    "count": 120,
    "intervalSec": 60
  }
}
```

**Issues**:
1. **Empty description** - Should document purpose
2. **x-user-id header** - Does the application actually send this?
3. **60 req/min threshold** - Is this the correct limit?
4. **Overlaps with IP rate limit** - Both limits apply simultaneously

**Questions**:
- Does the application set `x-user-id` header?
- If yes, is it after OAuth authentication?
- Should this be per-authenticated-user or can it be spoofed?

### ⚠️ LOW: Missing Rules

**Potentially Useful Rules**:
1. **Request method validation** - Only allow GET/HEAD/POST
2. **Path validation** - Block requests to non-existent paths
3. **Geographic restrictions** (if applicable)
4. **User-Agent validation** - Block known bad bots

---

## Recommended Changes

### Option 1: Minimal Fix (Quick - 5 minutes)

**Remove redundant WebSocket rules 995 and 996**:

```bash
# Keep the regex rule (1000) which covers both
gcloud compute security-policies rules delete 995 \
  --security-policy=cwe-chatbot-armor \
  --project=cwechatbot

gcloud compute security-policies rules delete 996 \
  --security-policy=cwe-chatbot-armor \
  --project=cwechatbot

# Update description of rule 1000
gcloud compute security-policies rules update 1000 \
  --security-policy=cwe-chatbot-armor \
  --description="Allow WebSocket from prod and staging origins (*.cwe.crashedmind.com)" \
  --project=cwechatbot
```

**Add description to rule 900**:
```bash
gcloud compute security-policies rules update 900 \
  --security-policy=cwe-chatbot-armor \
  --description="Per-user rate limiting (60 req/min, ban at 120/min)" \
  --project=cwechatbot
```

**Result**: 8 rules (cleaner, less redundancy)

### Option 2: Comprehensive Refactor (Better - 30 minutes)

**Refactor all rules with clear priority grouping**:

```
# Priority Ranges:
# 100-199: Allow baseline access (health checks, static assets)
# 200-299: Allow authenticated access (API endpoints)
# 900-999: Rate limiting (per-user, per-IP)
# 1000-1099: Protocol-specific (WebSocket)
# 1100-1199: Protocol denies (WebSocket blocks)
# 2000-2099: Default behaviors
# 2147483647: Default deny
```

**Proposed Rule Set** (8 rules):

| Priority | Action | Description | Expression |
|----------|--------|-------------|------------|
| 100 | allow | Health checks and static assets | `(method == GET/HEAD) && (path == / OR /health OR /favicon)` |
| 110 | allow | JSON API ≤10MB | `method == POST && path starts /api/ && Content-Length ≤ 10MB` |
| 900 | rate_ban | Per-user rate limit (if x-user-id exists) | `has(x-user-id)` → 60/min |
| 1000 | allow | WebSocket same-origin | `upgrade == websocket && origin matches *.cwe.crashedmind.com` |
| 1100 | deny | WebSocket cross-origin | `upgrade == websocket && has(origin)` |
| 1200 | deny | WebSocket no origin | `upgrade == websocket` |
| 1300 | rate_ban | Per-IP rate limit (DDoS protection) | `true` → 300/min, ban at 600 |
| 2147483647 | deny | Default deny all | `*` |

### Option 3: Advanced Security Hardening (Best - 1 hour)

**Add additional protection rules**:

**1. Method Whitelist (Priority 50)**:
```bash
# Only allow GET, HEAD, POST
gcloud compute security-policies rules create 50 \
  --action=deny-403 \
  --description="Block non-standard HTTP methods" \
  --expression="!(request.method == 'GET' || request.method == 'HEAD' || request.method == 'POST')"
```

**2. Path Validation (Priority 2000)**:
```bash
# Deny access to common attack paths
gcloud compute security-policies rules create 2000 \
  --action=deny-403 \
  --description="Block common attack paths" \
  --expression="request.path.matches('.*(\\.env|\\.git|admin|wp-admin|phpmyadmin).*')"
```

**3. SQL Injection/XSS Protection** (already enabled via Adaptive Protection)

---

## Detailed Analysis

### Rule-by-Rule Breakdown

#### ✅ Priority 100 - Health & Static (GOOD)
```cel
(request.method == 'GET' || request.method == 'HEAD') &&
(request.path == '/' || request.path.startsWith('/api/health') || request.path == '/favicon.ico')
```
**Purpose**: Allow health checks and static assets
**Status**: ✅ Well-defined, necessary
**Recommendation**: Keep as-is

#### ✅ Priority 110 - JSON API ≤10MB (GOOD - Just Updated)
```cel
request.method == 'POST' &&
request.path.startsWith('/api/') &&
has(request.headers['content-length']) &&
int(request.headers['content-length']) <= 10485760
```
**Purpose**: Allow API requests under 10MB
**Status**: ✅ Just updated with size enforcement
**Recommendation**: Keep as-is

#### ⚠️ Priority 900 - Per-User Rate Limit (NEEDS REVIEW)
```cel
has(request.headers['x-user-id'])
```
**Purpose**: Rate limit by user ID
**Status**: ⚠️ Empty description, unclear if header exists
**Questions**:
- Does app set `x-user-id` header?
- Is it after OAuth authentication?
- Can it be spoofed by clients?

**Recommendation**:
1. Add description
2. Verify header is actually used
3. If not used, consider removing or implementing properly

#### ⚠️ Priority 995 - WS Prod (REDUNDANT)
```cel
has(request.headers['upgrade']) &&
request.headers['upgrade'].lower() == 'websocket' &&
has(request.headers['origin']) &&
request.headers['origin'] == 'https://cwe.crashedmind.com'
```
**Purpose**: Allow WS from production origin
**Status**: ⚠️ Redundant with rule 1000
**Recommendation**: **DELETE** (covered by rule 1000)

#### ⚠️ Priority 996 - WS Staging (REDUNDANT)
```cel
has(request.headers['upgrade']) &&
request.headers['upgrade'].lower() == 'websocket' &&
has(request.headers['origin']) &&
request.headers['origin'] == 'https://staging-cwe.crashedmind.com'
```
**Purpose**: Allow WS from staging origin
**Status**: ⚠️ Redundant with rule 1000
**Recommendation**: **DELETE** (covered by rule 1000)

#### ✅ Priority 1000 - WS Same-Origin (GOOD)
```cel
has(request.headers["upgrade"]) &&
request.headers["upgrade"].lower() == "websocket" &&
has(request.headers["origin"]) &&
request.headers["origin"].matches("https://.*cwe\\.crashedmind\\.com")
```
**Purpose**: Allow WebSocket from any *.cwe.crashedmind.com origin
**Status**: ✅ Covers both prod and staging
**Recommendation**: Keep, update description to clarify it covers both

#### ⚠️ Priority 1100 - WS Cross-Origin Deny (REDUNDANT?)
```cel
has(request.headers["upgrade"]) &&
request.headers["upgrade"].lower() == "websocket" &&
has(request.headers["origin"])
```
**Purpose**: Deny WebSocket with origin (catches cross-origin)
**Status**: ⚠️ Might be redundant with default deny
**Recommendation**: Keep for explicit security (defense in depth)

#### ⚠️ Priority 1200 - WS No Origin Deny (REDUNDANT?)
```cel
has(request.headers["upgrade"]) &&
request.headers["upgrade"].lower() == "websocket"
```
**Purpose**: Deny WebSocket without Origin header
**Status**: ⚠️ Might be redundant with default deny
**Recommendation**: Keep for explicit security (defense in depth)

#### ✅ Priority 1300 - Per-IP Rate Limit (GOOD)
```cel
true
```
**Purpose**: DDoS protection (300 req/min, ban at 600)
**Status**: ✅ Essential baseline protection
**Recommendation**: Keep as-is

#### ✅ Priority 2147483647 - Default Deny (ESSENTIAL)
```cel
*
```
**Purpose**: Deny all traffic not explicitly allowed
**Status**: ✅ Core security principle (fail-safe)
**Recommendation**: **NEVER REMOVE**

---

## Feature Status

### ✅ Enabled Features
- **Adaptive Protection**: Layer 7 DDoS defense (automatic)
- **Verbose Logging**: Full request logging for analysis
- **Rate Limiting**: Per-IP (300/min) and per-user (60/min)
- **WebSocket Origin Validation**: Prevents CSWSH attacks
- **Default Deny**: Zero-trust security model
- **Request Size Limits**: 10MB for API requests

### ⚠️ Consider Enabling
- **Geo-blocking**: If most traffic from specific regions
- **Bot Management**: Block known bad bots
- **Custom Rules**: Based on traffic patterns

---

## Recommended Action Plan

### Immediate (Today - 10 minutes)

**1. Remove Redundant Rules**:
```bash
# Delete exact-match rules (covered by regex rule 1000)
./scripts/ops/remove_redundant_ws_rules.sh
```

**2. Add Descriptions**:
```bash
# Add description to rule 900
gcloud compute security-policies rules update 900 \
  --security-policy=cwe-chatbot-armor \
  --description="Per-user rate limiting (60 req/min, ban at 120/min)" \
  --project=cwechatbot
```

**Result**: Cleaner, more maintainable rule set

### Short-term (This Week - 1 hour)

**3. Verify x-user-id Header**:
- Check if application sets `x-user-id` header
- If not, remove rule 900 or implement properly
- If yes, document how it's set and secured

**4. Add Method Whitelist**:
```bash
# Only allow GET, HEAD, POST
gcloud compute security-policies rules create 50 \
  --security-policy=cwe-chatbot-armor \
  --action=deny-403 \
  --description="Block non-standard HTTP methods (only GET/HEAD/POST allowed)" \
  --expression="!(request.method == 'GET' || request.method == 'HEAD' || request.method == 'POST')" \
  --project=cwechatbot
```

### Long-term (Future)

**5. Monitor & Tune**:
- Review Cloud Armor logs weekly
- Adjust rate limits based on traffic patterns
- Add custom rules for specific threats

**6. Consider Advanced Features**:
- reCAPTCHA integration for suspicious traffic
- Custom bot detection rules
- Geographic restrictions (if applicable)

---

## Testing Before Changes

**Before removing rules, verify traffic patterns**:

```bash
# Check rule hit counts
gcloud logging read \
  'resource.type="http_load_balancer"
   jsonPayload.enforcedSecurityPolicy.name="cwe-chatbot-armor"' \
  --limit=1000 \
  --project=cwechatbot \
  --format=json | jq -r '.[] | .jsonPayload.enforcedSecurityPolicy.configuredAction' | sort | uniq -c

# Check which rules are being hit
gcloud logging read \
  'resource.type="http_load_balancer"
   jsonPayload.enforcedSecurityPolicy.name="cwe-chatbot-armor"' \
  --limit=1000 \
  --project=cwechatbot \
  --format=json | jq -r '.[] | .jsonPayload.enforcedSecurityPolicy.priority' | sort | uniq -c
```

---

## Summary

### Current State
- ✅ 10 rules total
- ⚠️ 2 redundant rules (995, 996)
- ⚠️ 1 rule with missing description (900)
- ⚠️ 1 rule needs verification (900 - x-user-id)
- ✅ Core security features working well

### Recommended State
- ✅ 8-9 rules (remove redundant, add method whitelist)
- ✅ All rules documented
- ✅ Clear priority grouping
- ✅ Verified all rules are actively used

### Priority Actions
1. **High**: Remove rules 995 and 996 (redundant)
2. **High**: Add description to rule 900
3. **Medium**: Verify x-user-id header usage
4. **Low**: Add HTTP method whitelist

**Risk Level of Changes**: 🟢 LOW
- Removing redundant rules has no functional impact
- Rules 995/996 are already covered by rule 1000
- Changes can be easily rolled back if needed

---

## Scripts to Implement Changes

Created helper scripts in `scripts/ops/`:
- `cleanup_cloud_armor_rules.sh` - Remove redundant rules
- `verify_cloud_armor_config.sh` - Validate current configuration
- `test_cloud_armor_rules.sh` - Test rule behavior

**Status**: Ready for implementation
