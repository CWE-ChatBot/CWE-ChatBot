# Issue: CWE-82 Not Found in Chatbot Responses

**Date Discovered**: 2025-10-11
**Date Resolved**: 2025-10-11
**Status**: ✅ RESOLVED
**Priority**: MEDIUM → HIGH (systematic issue affecting all CWE ID queries)
**Reporter**: User testing
**Environment**: Production (fixed in cwe-chatbot-00186-jtl)

## Problem Description

User query for CWE-82 returns incorrect or missing information:

**Query:** "What is CWE-82 and how do I prevent it?"

**Expected Behavior:**
- Return information about CWE-82: "Improper Neutralization of Script in Attributes of IMG Tags in a Web Page"
- Provide prevention/mitigation guidance from official MITRE CWE data
- CWE-82 exists at: https://cwe.mitre.org/data/definitions/82.html

**Actual Behavior (Observed):**

### Attempt 1:
```
Based on the provided CWE documentation, there is no direct entry for "CWE-82".
However, the provided data shows that CWE-1264 Hardware Logic with Insecure
De-Synchronization between Control and Data Channels
```
*(Response shows wrong CWE-1264 instead of CWE-82)*

### Attempt 2:
```
The provided documentation does not contain information for CWE-82. Therefore,
I cannot provide details on what CWE-82 Improper Neutralization of Script in
Attributes of IMG Tags in a Web Page
```
*(Response acknowledges CWE-82 name but says no documentation available)*

## Evidence from Logs

**Timestamp**: 2025-10-11 08:51:39 UTC
**User**: crashedmind@gmail.com
**Persona**: PSIRT Member

```
2025-10-11 08:51:39 - Processing user query: 'What is CWE-82...'
2025-10-11 08:51:42 - Processing 10 chunks into recommendations
2025-10-11 08:51:43 - [DEBUG_RESP] Response length: 193 chars
```

**Observation**:
- System retrieved 10 chunks (hybrid search working)
- But those chunks apparently don't contain CWE-82 data
- Response indicates "documentation does not contain information"

## Possible Root Causes

### Hypothesis 1: CWE-82 Not Ingested ❓
- CWE data ingestion pipeline may have skipped or failed on CWE-82
- Check: Does CWE-82 exist in `cwe_chunks` table?
- Query: `SELECT COUNT(*) FROM cwe_chunks WHERE UPPER(cwe_id) = 'CWE-82';`

### Hypothesis 2: Retrieval Not Finding CWE-82 ❓
- CWE-82 exists in database but hybrid search not ranking it highly
- Semantic embedding may not match "CWE-82" literal query well
- Full-text search may not be weighting CWE ID highly enough

### Hypothesis 3: CWE-82 Data Quality Issue ❓
- CWE-82 ingested but data incomplete or malformed
- Chunks may be too small or missing key information
- Name/description may not be in the retrieved chunks

### Hypothesis 4: Response Generation Issue ❓
- CWE-82 chunks retrieved correctly
- But LLM response generation not extracting the information
- May be ignoring retrieved context or hallucinating "not found"

## Investigation Steps

### Step 1: Verify CWE-82 in Database ⏳
```sql
-- Check if CWE-82 exists
SELECT cwe_id, section, name, LEFT(full_text, 200) as preview
FROM cwe_chunks
WHERE UPPER(cwe_id) = 'CWE-82'
ORDER BY section_rank;

-- Check total count
SELECT COUNT(*) FROM cwe_chunks WHERE UPPER(cwe_id) = 'CWE-82';
```

**Expected**: 10-15 chunks (one per semantic section)
**If 0 chunks**: CWE-82 not ingested → Run ingestion for CWE-82

### Step 2: Test Hybrid Search Retrieval ⏳
```python
from apps.chatbot.src.query_handler import CWEQueryHandler

handler = CWEQueryHandler(database_url, gemini_api_key)
results = handler.hybrid_search("CWE-82", k=10)

print(f"Retrieved {len(results)} chunks:")
for r in results:
    meta = r.get('metadata', {})
    scores = r.get('scores', {})
    print(f"  {meta.get('cwe_id')}: {meta.get('section')} "
          f"(hybrid: {scores.get('hybrid', 0):.3f})")
```

**Expected**: At least some results with `cwe_id='CWE-82'` in top 10
**If no CWE-82 in results**: Retrieval issue → Check embedding/FTS weights

### Step 3: Test Specific CWE ID Query ⏳
```python
# Test the forced CWE lookup
results = handler._fetch_cwe_sections("CWE-82", limit=5)
print(f"Direct fetch returned {len(results)} chunks")
```

**Expected**: 5 chunks with CWE-82 data
**If 0 chunks**: Confirms CWE-82 not in database

### Step 4: Check Ingestion Logs ⏳
```bash
# Check if CWE-82 was processed during ingestion
grep -r "CWE-82" apps/cwe_ingestion/logs/

# Check ingestion run success
grep "Successfully stored.*chunks" apps/cwe_ingestion/logs/
```

**Look for**: Any errors or skips related to CWE-82

### Step 5: Verify MITRE Source Data ⏳
```bash
# Check if CWE-82 exists in source XML/JSON
curl -s https://cwe.mitre.org/data/definitions/82.html | grep "Improper Neutralization"
```

**Expected**: Page exists with full CWE-82 details
**Confirms**: CWE-82 is valid and should be ingested

## Impact Assessment

**Severity**: MEDIUM
- Not a critical system failure
- User can still access CWE-82 via MITRE website directly
- But degrades chatbot value proposition (RAG not working for this CWE)

**Scope**: Unknown
- May be isolated to CWE-82
- Or could be systematic issue affecting multiple CWEs
- Need to test other CWE IDs (e.g., CWE-79, CWE-89, CWE-200)

**User Experience**:
- ❌ Incorrect or missing information reduces trust
- ❌ Users may think chatbot is unreliable
- ❌ Defeats purpose of RAG-based system (preventing hallucination)

## Recommended Fixes

### If CWE-82 Not Ingested:
1. Re-run CWE ingestion pipeline with CWE-82 explicitly included
2. Verify CWE-82 appears in database after ingestion
3. Test retrieval again

### If CWE-82 Ingested But Not Retrieved:
1. Analyze hybrid search scoring for "CWE-82" query
2. Adjust FTS/vector/alias weights if needed
3. Consider adding CWE ID exact match boost

### If Retrieved But Not Used in Response:
1. Review response generation prompt
2. Check if LLM is properly using retrieved context
3. Add explicit instruction to use retrieved CWE documentation

### If Systematic Issue:
1. Audit all CWE IDs for similar problems
2. Run comprehensive test suite across all CWEs
3. Document any missing or problematic CWEs

## Testing Plan

Once fix is implemented, verify:

1. **Query CWE-82 directly**: "What is CWE-82?"
   - ✅ Should return correct name and description

2. **Query CWE-82 by name**: "Tell me about script injection in IMG tags"
   - ✅ Should retrieve CWE-82 via semantic search

3. **Query CWE-82 for prevention**: "How do I prevent CWE-82?"
   - ✅ Should provide mitigation guidance from MITRE data

4. **Verify related CWEs**: Test CWE-79, CWE-89, CWE-20
   - ✅ Should work to confirm not systematic issue

## Related Issues

- **Story 1.5**: CWE Corpus Ingestion (production ready)
- **Story 2.1**: Core NLU and Query Matching (complete with security review)
- **CWE Ingestion Pipeline**: apps/cwe_ingestion/ (969 CWEs, 7,913 chunks)

## Investigation Results (2025-10-11)

### Complete Investigation Timeline

#### Phase 1: Initial Hypothesis - Response Generation Issue ❌
**Hypothesis**: LLM receiving CWE-82 chunks but not using them in response.

**Investigation**:
- Verified CWE-82 exists in MITRE source XML (ID="82" found 3 times in cwec_v4.18.xml)
- Verified CWE-82 ingested to database (969/969 CWEs in ingestion reports)
- Added debug logging to `response_generator.py` to see what chunks reach LLM

**Finding**: Early logs showed `"Top results: [('CWE-82', '0.23')]"` but this was from a DIFFERENT query.

#### Phase 2: Deeper Pipeline Analysis - Force-Injection Bug 🔴 ROOT CAUSE
**New Hypothesis**: CWE-82 not in retrieved chunks sent to response generator.

**Investigation**:
- Added comprehensive debug logging at each pipeline stage:
  1. Raw retrieval from hybrid search
  2. After business logic processing
  3. Chunks passed to LLM
  4. Context builder output

**Critical Finding**:
```
[DEBUG_PIPELINE] Raw retrieval returned 10 chunks with CWEs:
  ['CWE-191', 'CWE-572', 'CWE-1264', 'CWE-190', 'CWE-135', 'CWE-128', 'CWE-131', 'CWE-1088', 'CWE-468', 'CWE-1335']
```

**CWE-82 NOT in raw retrieval results!** Hybrid search returning completely wrong CWEs.

Query: `"what is cwe-82?"`
Top results: `[('CWE-191', '0.24'), ('CWE-572', '0.24'), ('CWE-1264', '0.22')]`

#### Phase 3: Root Cause Analysis 🎯

**Hybrid Search Failure**: The vector + full-text search is NOT ranking CWE-82 highly for literal CWE ID queries.

**Broken Force-Injection Logic** ([apps/chatbot/src/processing/pipeline.py](apps/chatbot/src/processing/pipeline.py:445)):
```python
# BEFORE (BROKEN):
if extracted_cwe_ids and not processed_chunks and self.query_handler:
    # Force-inject only if NO results at all
```

**The Bug**: Force-injection only triggered when retrieval returned **zero** results. But hybrid search returned 10 results (wrong ones), so force-injection never happened.

**Impact**: ANY query mentioning a specific CWE ID (e.g., "What is CWE-82?") would get wrong results if hybrid search didn't rank that CWE highly enough.

### ✅ THE FIX (Deployed in cwe-chatbot-00186-jtl)

**File**: [apps/chatbot/src/processing/pipeline.py](apps/chatbot/src/processing/pipeline.py:447-472)

**Change**: Force-inject mentioned CWE IDs that are **missing from results**, not just when there are zero results.

```python
# AFTER (FIXED):
if extracted_cwe_ids and self.query_handler:
    # Check which extracted CWE IDs are missing from results
    retrieved_cwe_ids = set()
    for chunk in processed_chunks:
        metadata = chunk.get("metadata", {})
        if metadata.get("cwe_id"):
            retrieved_cwe_ids.add(metadata.get("cwe_id").upper())

    missing_cwe_ids = [cid for cid in extracted_cwe_ids if cid.upper() not in retrieved_cwe_ids]

    if missing_cwe_ids:
        # Force-inject the missing CWE IDs from database
        forced_sections = self.query_handler.fetch_canonical_sections_for_cwes(missing_cwe_ids)
        for chunk in forced_sections:
            scores = chunk.get("scores", {})
            scores["hybrid"] = scores.get("hybrid", 0.0) + 3.0  # Strong boost
        processed_chunks.extend(forced_sections)
```

**How It Works Now**:
1. Extract "CWE-82" from query "what is cwe-82?"
2. Run hybrid search (still returns wrong CWEs)
3. **NEW**: Check if CWE-82 is in the results → NOT FOUND
4. **NEW**: Fetch CWE-82 directly from database using `fetch_canonical_sections_for_cwes()`
5. **NEW**: Inject CWE-82 chunks with +3.0 score boost (highest priority)
6. Pass CWE-82 chunks to LLM
7. Generate correct response about CWE-82

### Verification (2025-10-11)

**Test Query**: `"what is cwe-82?"`

**Logs (cwe-chatbot-00186-jtl)**:
```
[DEBUG_PIPELINE] Extracted CWE IDs from query: {'CWE-82'}
[DEBUG_PIPELINE] Raw retrieval returned 10 chunks with CWEs: ['CWE-191', 'CWE-572', ...]
[DEBUG_PIPELINE] Force-injecting missing CWE IDs: ['CWE-82']
[DEBUG_PIPELINE] After business logic: ['CWE-82', 'CWE-191', 'CWE-572', ...]  ✅ CWE-82 NOW FIRST!
[DEBUG_CONTEXT] CWEs in final context: ['CWE-82', 'CWE-191', ...]
```

**Response**: ✅ Correct information about CWE-82 returned

## Lessons Learned

### 1. Hybrid Search Limitations for Exact ID Queries
**Problem**: Vector embeddings + full-text search don't reliably rank exact CWE ID matches highly.

**Why**:
- "what is cwe-82?" embeds as a question about definitions
- Semantic similarity may match integer-related CWEs (CWE-191: Integer Underflow) higher than XSS-related CWE-82
- Full-text search on "82" matches any CWE with "82" in description (CWE-1282, CWE-582, etc.)

**Implication**: Cannot rely solely on hybrid search for CWE ID queries.

### 2. Force-Injection Must Handle Partial Failures
**Problem**: Original force-injection assumed "no results" = "failed retrieval"

**Reality**: Retrieval can succeed but return **wrong** results. The fix must detect:
- Zero results → force-inject everything
- Some results but **missing mentioned IDs** → force-inject missing IDs

**Pattern**: Always verify mentioned entities are in results, not just that results exist.

### 3. Debug Logging is Critical for RAG Systems
**What Worked**: Adding logs at each pipeline stage:
1. Raw retrieval
2. Business logic processing
3. LLM input preparation
4. Context building

**Why Critical**: RAG systems have many transformation steps. Without stage-by-stage visibility, impossible to diagnose where data is lost.

**Recommendation**: Keep debug logging in production with feature flags (`DEBUG_PIPELINE=true`).

### 4. False Positive Investigations Happen
**Timeline**:
- Initially thought: "Response generation ignoring CWE-82 chunks"
- Reality: CWE-82 never in chunks to begin with

**Lesson**: Start debugging at the SOURCE (retrieval) not the DESTINATION (response). Follow data flow forward, not backward.

### 5. Systematic Issues Masquerade as Edge Cases
**Initial Assessment**: "CWE-82 specific issue"

**Actual Scope**: **ALL** CWE ID queries affected when hybrid search doesn't rank them highly:
- CWE-82 (low frequency in descriptions)
- CWE-15, CWE-20, CWE-36 (short IDs match many strings)
- Potentially 100+ CWEs with poor semantic/FTS scores

**Impact**: MEDIUM → HIGH priority (systematic RAG failure for explicit ID queries)

## Testing Requirements

### Critical Gap: No E2E Testing for RAG Correctness

**Current State**: No automated tests verify:
1. Specific CWE ID queries return correct CWE
2. Response contains information from retrieved CWE
3. LLM not hallucinating alternative CWEs

### Proposed Testing Strategy

#### Test Type 1: CWE ID Query Correctness (Non-Interactive)
**Purpose**: Verify mentioned CWE IDs appear in response

**Approach**: Unit/integration tests
```python
def test_cwe_id_extraction_and_force_injection():
    """Test that mentioned CWE IDs are always included in results."""
    query = "What is CWE-82?"
    chunks = pipeline.process_query(query)

    # Verify CWE-82 in retrieved chunks
    cwe_ids = [c['metadata']['cwe_id'] for c in chunks]
    assert 'CWE-82' in cwe_ids, "Force-injection failed"

    # Verify CWE-82 has high score (boosted)
    cwe_82_score = [c['scores']['hybrid'] for c in chunks if c['metadata']['cwe_id'] == 'CWE-82'][0]
    assert cwe_82_score > 2.0, "Boost not applied"
```

**Coverage**: Test 50 random CWE IDs from corpus

#### Test Type 2: Response Content Validation (LLM-as-Judge)
**Purpose**: Verify LLM response contains correct CWE information

**Approach**: LLM-as-judge with ground truth from MITRE
```python
async def test_cwe_response_accuracy_with_llm_judge():
    """Use LLM to judge if response matches MITRE ground truth."""
    cwe_id = "CWE-82"
    query = f"What is {cwe_id}?"

    # Get chatbot response
    response = await chatbot.query(query)

    # Get ground truth from MITRE
    ground_truth = fetch_mitre_cwe_description(cwe_id)

    # LLM judge prompt
    judge_prompt = f"""
    Ground Truth CWE Description (from MITRE):
    {ground_truth}

    Chatbot Response:
    {response}

    Question: Does the chatbot response accurately describe {cwe_id}?
    - Answer "PASS" if response matches ground truth description
    - Answer "FAIL" if response describes a different CWE or is incorrect
    - Answer "PARTIAL" if response is incomplete but not wrong

    Format: <verdict>PASS/FAIL/PARTIAL</verdict>
    <reasoning>brief explanation</reasoning>
    """

    verdict = llm_judge.evaluate(judge_prompt)
    assert "PASS" in verdict, f"LLM judge failed: {verdict}"
```

**Coverage**:
- 10 high-priority CWEs (CWE-79, CWE-89, CWE-78, etc.)
- 20 random CWEs from corpus
- 10 low-frequency CWEs (like CWE-82)

#### Test Type 3: E2E Interactive Testing with Puppeteer (Critical)
**Purpose**: Test actual user workflow without OAuth (anonymous/guest mode)

**Approach**: Puppeteer browser automation
```python
async def test_cwe_query_e2e_with_puppeteer():
    """E2E test using Puppeteer for browser automation."""
    browser = await puppeteer.launch()
    page = await browser.new_page()

    # Navigate to chatbot (no OAuth required)
    await page.goto("https://cwe-chatbot.example.com")

    # Type query
    await page.type("#chat-input", "What is CWE-82?")
    await page.click("#send-button")

    # Wait for response
    await page.wait_for_selector(".response-message")
    response_text = await page.query_selector_eval(
        ".response-message",
        "el => el.textContent"
    )

    # Verify response contains CWE-82
    assert "CWE-82" in response_text
    assert "IMG" in response_text.upper() or "image" in response_text.lower()
    assert "XSS" in response_text.upper() or "cross-site" in response_text.lower()

    await browser.close()
```

**Prerequisites**:
1. **Guest/Anonymous Mode**: Add non-OAuth testing endpoint or allow anonymous queries
2. **Test User Account**: Create service account with API key for automated testing
3. **Puppeteer Setup**: Configure headless Chrome with proper timeouts

**Coverage**:
- 5 CWE ID queries (CWE-79, CWE-89, CWE-78, CWE-82, CWE-20)
- 3 semantic queries ("SQL injection", "XSS", "path traversal")
- 2 negative tests (invalid CWE-9999, ambiguous "injection")

#### Test Type 4: Random CWE Sampling (Systematic Coverage)
**Purpose**: Detect systematic issues across entire corpus

**Approach**: Sample 30 random CWEs, test with LLM-as-judge
```python
def test_random_cwe_sample():
    """Test 30 random CWEs to detect systematic issues."""
    # Get all CWE IDs from database
    all_cwes = fetch_all_cwe_ids()  # Returns ['CWE-1', 'CWE-2', ..., 'CWE-1425']

    # Random sample of 30
    sample = random.sample(all_cwes, 30)

    failures = []
    for cwe_id in sample:
        result = test_cwe_response_accuracy_with_llm_judge(cwe_id)
        if result != "PASS":
            failures.append((cwe_id, result))

    # Allow up to 10% failure rate for edge cases
    assert len(failures) <= 3, f"Too many failures: {failures}"
```

**Benefit**: Catches issues affecting multiple CWEs, not just known problem cases.

### Testing Implementation Plan

1. **Phase 1: Core Unit Tests** (1-2 days)
   - Test CWE ID extraction
   - Test force-injection logic
   - Test business logic boosting

2. **Phase 2: LLM-as-Judge** (2-3 days)
   - Implement judge prompt
   - Test 10 high-priority + 20 random CWEs
   - Establish baseline accuracy (target: >90% PASS)

3. **Phase 3: Puppeteer E2E** (3-5 days)
   - Set up guest/anonymous access or test service account
   - Implement browser automation tests
   - Add to CI/CD pipeline

4. **Phase 4: Random Sampling** (1 day)
   - Automate 30 CWE random sample tests
   - Run weekly to catch regressions

### Test Data Requirements

- **Ground Truth Source**: MITRE CWE XML (cwec_latest.xml)
- **Test CWE Selection**:
  - High Priority: CWE-79, CWE-89, CWE-78, CWE-22, CWE-352, CWE-434, CWE-639, CWE-798, CWE-862, CWE-918
  - Low Frequency (like CWE-82): CWE-15, CWE-36, CWE-82, CWE-108, CWE-182
  - Random Sample: 30 CWEs selected randomly each test run

## Additional Context

**CWE-82 Details:**
- **Name**: Improper Neutralization of Script in Attributes of IMG Tags in a Web Page
- **Type**: Weakness (vulnerability pattern)
- **Category**: Input Validation / XSS
- **URL**: https://cwe.mitre.org/data/definitions/82.html
- **Related**: CWE-79 (XSS), CWE-80, CWE-83, CWE-84, CWE-85, CWE-86

**Why This Matters:**
- CWE-82 is a legitimate, documented weakness
- Should be in our 969 CWE corpus
- Test case for data quality and retrieval accuracy
- Exposes potential gaps in ingestion or RAG pipeline

---

**Created**: 2025-10-11
**Requires Investigation**: Database query, ingestion logs, retrieval testing
**Priority**: MEDIUM (affects user experience, not system stability)
