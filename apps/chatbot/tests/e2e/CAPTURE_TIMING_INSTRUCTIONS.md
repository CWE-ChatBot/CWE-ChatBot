# Instructions to Capture Response Timing and Retrieval Behavior

## Purpose
Capture real production timing data and retrieval statistics to complete the regression test report.

## Deployed Version
**Revision:** `cwe-chatbot-00097-mdz`
**Region:** us-central1
**Status:** Deployed with enhanced logging

## Enhanced Logging Features

The deployed version now captures:
- **Embedding generation time** (ms)
- **Database query time** (ms)
- **Total query processing time** (ms)
- **Top CWE results** with hybrid scores
- **Candidate pooling statistics** (vec, fts, alias counts)

## Test Queries to Run

### Query 1: PSIRT Member - SQL Injection
```
Persona: PSIRT Member
Query: Show me SQL injection prevention techniques
```

### Query 2: Academic Researcher - Buffer Overflow
```
Persona: Academic Researcher
Query: Buffer overflow vulnerabilities
```

### Query 3: Product Manager - XSS Mitigation
```
Persona: Product Manager
Query: XSS mitigation strategies
```

### Query 4: Bug Bounty Hunter - Path Traversal
```
Persona: Bug Bounty Hunter
Query: Path traversal attack vectors
```

### Query 5: Developer - Authentication Bypass
```
Persona: Developer
Query: Authentication bypass weaknesses
```

## Steps to Capture Timing Data

### 1. Navigate to Application
```
https://cwe-chatbot-258315443546.us-central1.run.app
```

### 2. Run Each Test Query
- Select the persona from dropdown (if available)
- Enter the query text
- Submit the query
- **Note the time**: Record when you see first response (initial) and when response is complete (final)

### 3. Fetch Cloud Run Logs
After running all queries, execute:

```bash
gcloud run services logs read cwe-chatbot \
  --region=us-central1 \
  --limit=200 \
  --format='table(timestamp,severity,textPayload)' \
  | grep -E '(Processing query|Embedding generated|Retrieved|Top results|Candidate pooling)' \
  > /tmp/test_timing_logs.txt
```

### 4. Extract Timing Information
Look for log entries like:

```
2025-10-03 10:52:15  INFO  Processing query: 'Show me SQL injection prevention techniques' for persona: PSIRT Member
2025-10-03 10:52:15  INFO  ✓ Embedding generated: 3072D in 245.3ms
2025-10-03 10:52:15  INFO  Candidate pooling: vec=50, fts=18, alias=12, total=73
2025-10-03 10:52:15  INFO  ✓ Retrieved 10 chunks in 127.4ms (total: 372.7ms)
2025-10-03 10:52:15  INFO  Top results: [('CWE-89', '0.92'), ('CWE-564', '0.78'), ('CWE-20', '0.65')]
```

### 5. Calculate Response Times

**Initial Response Time** = Time from query submission to first token appearing
**Complete Response Time** = Time from query submission to response fully rendered
**Backend Processing Time** = Total time from logs (embedding + DB + processing)

## Expected Log Patterns

### Embedding Generation
```
INFO  ✓ Embedding generated: 3072D in <TIME>ms
```
**Expected range:** 50-300ms (depends on Gemini API latency)

### Candidate Pooling
```
INFO  Candidate pooling: vec=<N>, fts=<N>, alias=<N>, total=<N>
```
**Expected:**
- vec: ~50 (k_vec parameter)
- fts: ~15-50 (varies by query)
- alias: ~5-20 (varies by acronyms/terms)
- total: ~60-100 (unique after UNION)

### Database Query
```
INFO  ✓ Retrieved <N> chunks in <TIME>ms (total: <TOTAL>ms)
```
**Expected:**
- DB time: 50-150ms (with halfvec optimization)
- Total time: 150-400ms (embedding + DB + overhead)

### Top Results
```
INFO  Top results: [('CWE-XXX', 'SCORE'), ...]
```
**Expected:**
- Scores: 0.60-0.95 for good matches
- Top CWE should match expected CWE for query

## Analysis Checklist

After capturing logs, verify:

- [ ] All 5 queries executed successfully
- [ ] Embedding generation < 400ms
- [ ] Database query time < 200ms
- [ ] Total processing time < 500ms
- [ ] Candidate pooling shows contributions from vec, fts, and alias
- [ ] Top results include expected CWEs
- [ ] Hybrid scores in reasonable range (0.60-0.95)
- [ ] No errors or exceptions in logs

## Troubleshooting

### No log entries found
```bash
# Check if service is receiving requests
gcloud run services logs read cwe-chatbot --region=us-central1 --limit=10

# Verify revision is serving traffic
gcloud run revisions list --service=cwe-chatbot --region=us-central1 --limit=1
```

### Logs don't show timing details
Verify deployed revision is `cwe-chatbot-00097-mdz` or later (has enhanced logging).

### Candidate pooling not logged
Check for errors in database connection or SQL execution. The candidate pooling query is best-effort and failures are logged as debug warnings.

## Output Format for Test Report

Once data is captured, update `TEST_RESULTS_NON_CWE_REGRESSION.md` with:

```markdown
### Query Timing Breakdown

| Query | Embedding (ms) | DB Query (ms) | Total (ms) | Initial Response | Complete Response |
|-------|----------------|---------------|------------|------------------|-------------------|
| SQL injection | 245.3 | 127.4 | 372.7 | 0.4s | 2.1s |
| Buffer overflow | 198.7 | 143.2 | 341.9 | 0.3s | 1.9s |
| XSS mitigation | 212.5 | 135.8 | 348.3 | 0.4s | 2.0s |
| Path traversal | 223.1 | 129.6 | 352.7 | 0.3s | 1.8s |
| Auth bypass | 207.4 | 138.9 | 346.3 | 0.4s | 2.1s |

### Candidate Pooling Statistics

| Query | Vec | FTS | Alias | Total Candidates |
|-------|-----|-----|-------|------------------|
| SQL injection | 50 | 18 | 12 | 73 |
| Buffer overflow | 50 | 22 | 8 | 75 |
| XSS mitigation | 50 | 15 | 14 | 71 |
| Path traversal | 50 | 19 | 10 | 74 |
| Auth bypass | 50 | 17 | 11 | 72 |
```

## Next Steps

1. Run test queries in web UI
2. Capture logs with command above
3. Extract timing and pooling data
4. Update `TEST_RESULTS_NON_CWE_REGRESSION.md` with real metrics
5. Commit updated test report
