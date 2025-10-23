# Cloud Run CPU Throttling Explained

## What Is CPU Throttling?

CPU throttling is a Cloud Run billing optimization that controls **when CPU is allocated** to your container.

### Without Throttling (`--no-cpu-throttling`)
```
Container State: IDLE → CPU: ALLOCATED ✅ (you pay for it)
Container State: BUSY → CPU: ALLOCATED ✅ (you pay for it)

Result: CPU always allocated = always billed
```

### With Throttling (`--cpu-throttling`)
```
Container State: IDLE → CPU: THROTTLED ⏸️ (you don't pay)
Container State: BUSY → CPU: ALLOCATED ✅ (you pay only when serving requests)

Result: CPU allocated on-demand = request-based billing
```

## How It Works (Technical)

### CPU Allocation States

**1. Always Allocated (--no-cpu-throttling)**
```
Time: 00:00 - Request arrives
Time: 00:01 - CPU is ALREADY allocated → instant processing
Time: 00:02 - Response sent
Time: 00:03 - No requests → CPU STILL allocated (idle, but you pay)
Time: 00:04 - No requests → CPU STILL allocated (idle, but you pay)
```

**2. Throttled (--cpu-throttling)**
```
Time: 00:00 - Request arrives
Time: 00:01 - CPU allocation starts (~10-50ms overhead)
Time: 00:02 - CPU allocated → processing begins
Time: 00:03 - Response sent
Time: 00:04 - No requests → CPU throttled (you DON'T pay)
Time: 00:05 - No requests → CPU throttled (you DON'T pay)
```

## Impact on Users

### Response Time Impact

**Typical Latency Addition: 10-50ms**

```
Without Throttling:
User Request → [0ms CPU allocation] → [100ms app processing] → Response
Total: 100ms

With Throttling (CPU already throttled):
User Request → [10-50ms CPU allocation] → [100ms app processing] → Response
Total: 110-150ms (10-50% slower)

With Throttling (CPU already allocated from recent request):
User Request → [0ms CPU allocation] → [100ms app processing] → Response
Total: 100ms (same as without throttling)
```

### Real-World Scenarios

#### Scenario 1: Chainlit Chat Application (Your Use Case)

**Traffic Pattern**: Sporadic interactive sessions, long idle periods

**Without Throttling**:
- User sends message → Response in 200ms ✅
- 23 hours of idle time → You pay for 23 hours of CPU ❌
- Daily cost: $2.07 for CPU

**With Throttling**:
- User sends message → Response in 220-250ms (10-25% slower) ⚠️
- 23 hours of idle time → You pay $0 for idle CPU ✅
- Daily cost: $0.20 for actual CPU usage

**User Impact**:
- Slight delay (20-50ms) on first interaction after idle period
- Subsequent requests are instant (CPU stays allocated)
- Most users won't notice 20-50ms difference
- Cost savings: ~90%

#### Scenario 2: High-Traffic API (NOT your case)

**Traffic Pattern**: Constant requests, never idle

**Without Throttling**:
- Every request: 100ms response time
- CPU always allocated (already needed)

**With Throttling**:
- Every request: 100ms response time
- CPU always allocated (because requests are constant)
- No cost difference (CPU never throttles due to constant activity)

**User Impact**: None (CPU never actually gets throttled)

#### Scenario 3: Burst Traffic (Worth Considering)

**Traffic Pattern**: Sudden spike of 10 concurrent users

**Without Throttling**:
- All 10 requests: CPU already allocated
- Response times: 100ms, 105ms, 110ms (parallel processing)

**With Throttling**:
- First request triggers CPU allocation: 50ms overhead
- Requests 2-10: CPU already allocated, no overhead
- Response times: 150ms (first), 105ms, 110ms (rest)

**User Impact**:
- First user in burst: +50ms delay
- Other 9 users: No delay
- Minimal overall impact

## Cost Comparison: Your Actual Service

### Current Configuration: `--no-cpu-throttling`

```
Billing Model: Always-Allocated CPU

Hourly Cost:
- 1 vCPU × $0.00002400/vCPU-second × 3600 seconds = $0.0864/hour

Daily Cost:
- $0.0864/hour × 24 hours = $2.07/day

Monthly Cost:
- $2.07/day × 30 days = $62.10/month

What You Pay For:
- Active processing time: ~1 hour/day → $0.0864
- Idle time: ~23 hours/day → $1.98
- Total: $2.07/day (95% is idle time waste)
```

### With CPU Throttling: `--cpu-throttling`

```
Billing Model: Request-Based CPU

Assuming 1 hour active per day, 23 hours idle:

Active Time Cost:
- 1 vCPU × $0.00002400/vCPU-second × 3600 seconds = $0.0864/hour
- Active time: 1 hour/day × $0.0864 = $0.0864/day

Idle Time Cost:
- CPU throttled = $0.00/hour
- Idle time: 23 hours/day × $0.00 = $0.00/day

Daily Cost:
- $0.0864/day (only active time)

Monthly Cost:
- $0.0864/day × 30 days = $2.59/month

Savings:
- $62.10 - $2.59 = $59.51/month (95% reduction)
```

## Performance Measurement

### CPU Allocation Overhead: What Does 10-50ms Mean?

**Perspective Comparison**:
```
DNS lookup:           20-120ms
TLS handshake:        50-100ms
Cross-region latency: 80-300ms
Database query:       5-50ms
CPU allocation:       10-50ms  ← Your throttling overhead

Total request time:   300-600ms (typical web app)
CPU allocation as %:  2-10% of total request time
```

### Chainlit Application Context

**Your Current Response Times** (from logs):
```
Socket.io polling:    25-30 second intervals
File upload:          200-500ms
Translation fetch:    100-300ms
User authentication:  50-150ms
```

**With CPU Throttling**:
```
Socket.io polling:    25-30 second intervals (no change, WebSocket keeps CPU active)
File upload:          220-550ms (+20-50ms on first request after idle)
Translation fetch:    120-350ms (+20-50ms on first request after idle)
User authentication:  70-200ms (+20-50ms on first request after idle)
```

**Impact Assessment**:
- WebSocket polling keeps CPU active → minimal throttling occurs
- User won't notice 20-50ms in 200-500ms total request time
- That's a 4-10% increase in latency for 95% cost savings

## When CPU Throttling Hurts

### ❌ DO NOT Use Throttling If:

1. **Real-time requirements** (< 100ms response time SLA)
   - Gaming backends
   - Financial trading systems
   - Real-time bidding platforms

2. **Constant high traffic** (CPU never idles anyway)
   - API serving 100+ requests/second
   - Streaming data processors
   - Always-busy background workers

3. **Background processing between requests**
   - Scheduled tasks running every minute
   - Cache warming between requests
   - Metrics collection during idle time

4. **WebSocket/SSE intensive** (if connections keep CPU active)
   - Chat applications with constant connections
   - Live dashboards with streaming updates
   - Collaborative editing tools

### ✅ DO Use Throttling If:

1. **Sporadic interactive usage** ← **YOUR CASE**
   - Development/testing environments
   - Internal tools with occasional use
   - Demo/POC applications

2. **Long idle periods**
   - Overnight: 8+ hours no traffic
   - Weekends: 48 hours minimal usage
   - Lunch breaks: 1-2 hours idle

3. **Burst traffic patterns**
   - Morning rush, then quiet
   - Event-driven spikes
   - Scheduled batch processing

4. **Cost-sensitive deployments**
   - Startup MVP
   - Side projects
   - Non-critical services

## Your Chainlit App: Detailed Analysis

### Current Behavior (--no-cpu-throttling)

```
07:00 - User logs in
        → CPU: Already allocated
        → Auth: 50ms (instant)
        → Cost: $0.0864/hour running

07:05 - User sends message
        → CPU: Already allocated
        → Response: 200ms (instant)
        → Cost: Still $0.0864/hour

07:10 - User logs out
        → CPU: STILL allocated (idle)
        → Cost: STILL $0.0864/hour (wasted)

08:00-15:00 - No activity (7 hours)
        → CPU: STILL allocated (idle)
        → Cost: 7 × $0.0864 = $0.60 (wasted)

Total: $0.69 for 5 minutes of actual use
```

### With Throttling (--cpu-throttling)

```
07:00 - User logs in
        → CPU: Allocation starts (20ms overhead)
        → Auth: 70ms (slightly slower)
        → Cost: $0.0864/hour while active

07:05 - User sends message
        → CPU: Already allocated (from auth at 07:00)
        → Response: 200ms (no overhead)
        → Cost: $0.0864/hour while active

07:10 - User logs out
        → CPU: Throttled after 60s idle
        → Cost: $0.00/hour (idle)

08:00-15:00 - No activity (7 hours)
        → CPU: Throttled (idle)
        → Cost: 7 × $0.00 = $0.00 (saved!)

Total: $0.14 for 5 minutes of actual use + 1 minute CPU cooldown
Savings: $0.55 (80% reduction) for this session
```

### WebSocket Impact (Important for Chainlit)

**Your logs show Socket.io polling every 25-30 seconds:**

```
With --cpu-throttling:
00:00 - WebSocket poll arrives
      → CPU allocates (10-50ms overhead)
      → Poll processed (5ms)
      → Response sent

00:30 - Next poll arrives (30 seconds later)
      → CPU STILL allocated? Depends on implementation

Case 1: Persistent WebSocket connection
      → CPU stays allocated (WebSocket keeps it busy)
      → No throttling overhead on subsequent polls
      → Total overhead: 10-50ms on initial connection only

Case 2: Long-polling with disconnects
      → CPU throttles between polls (30s gap)
      → 10-50ms overhead on EVERY poll
      → Total overhead: 10-50ms every 30 seconds
```

**Chainlit uses Socket.io with persistent connections** → CPU likely stays allocated during active sessions → minimal throttling impact.

## Recommendation for Your Service

### Analysis: cwe-chatbot

**Service Characteristics**:
- ✅ Sporadic usage (development/testing)
- ✅ Long idle periods (nights, weekends)
- ✅ Non-critical response times (200-500ms is acceptable)
- ✅ Interactive sessions (not real-time)
- ⚠️ WebSocket polling (but 25-30s intervals)

**Current Waste**:
- ~95% of CPU time is idle but paid for
- ~$60/month wasted on idle CPU allocation

**Throttling Impact**:
- +10-50ms latency on first request after idle (4-10% increase)
- WebSocket sessions keep CPU active (minimal subsequent overhead)
- Users unlikely to notice the difference
- 95% cost savings (~$60/month → ~$3/month for CPU)

### ✅ RECOMMENDED: Enable CPU Throttling

```bash
gcloud run services update cwe-chatbot \
  --region=us-central1 \
  --cpu-throttling
```

**Expected Outcome**:
- First interaction after idle: 220-250ms (was 200ms)
- Active session: 200ms (no change due to WebSocket)
- Monthly savings: ~$60 (95% reduction)
- User experience: Negligible impact

**Monitoring**:
```bash
# Before change: Record baseline
curl -w "@curl-format.txt" -o /dev/null -s https://cwe.crashedmind.com/

# After change: Compare performance
# Watch for +10-50ms on cold requests
```

## Testing CPU Throttling Impact

### Create Test Script

```bash
#!/bin/bash
# test-throttling-impact.sh

echo "Testing CPU throttling impact..."

# Test 1: Cold start (after 5 minutes idle)
echo "Test 1: Cold start (waiting 5 min for CPU throttle)..."
sleep 300
time curl -s -o /dev/null https://cwe.crashedmind.com/
echo ""

# Test 2: Warm request (immediate)
echo "Test 2: Warm request (CPU already allocated)..."
time curl -s -o /dev/null https://cwe.crashedmind.com/
echo ""

# Test 3: Burst test (10 concurrent)
echo "Test 3: Burst (10 concurrent requests)..."
for i in {1..10}; do
  (time curl -s -o /dev/null https://cwe.crashedmind.com/) &
done
wait
```

### Expected Results

**Without throttling** (`--no-cpu-throttling`):
```
Test 1 (cold): 0.20s
Test 2 (warm): 0.20s
Test 3 (burst): 0.20s, 0.21s, 0.22s (all similar)
```

**With throttling** (`--cpu-throttling`):
```
Test 1 (cold): 0.25s (+25% due to CPU allocation)
Test 2 (warm): 0.20s (no overhead, CPU still allocated)
Test 3 (burst): 0.25s, 0.20s, 0.21s (first request slower)
```

## Conclusion

**CPU throttling trades a small latency increase for massive cost savings.**

For your Chainlit chatbot:
- **Cost Impact**: 95% reduction (~$60/month savings)
- **User Impact**: 10-50ms added latency (4-10% increase)
- **Experience**: Virtually unnoticeable for interactive chat

**Bottom line**: The juice is worth the squeeze. Enable throttling.

The 20-50ms overhead is like adding one extra DNS lookup to your request chain—imperceptible to users, but saves you $720/year in cloud costs.
