# Issue: CWE-82 Not Found in Chatbot Responses

**Date Discovered**: 2025-10-11
**Status**: 🔴 OPEN - Needs Investigation
**Priority**: MEDIUM
**Reporter**: User testing
**Environment**: Production (cwe-chatbot-00183-jfc)

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

## Next Steps

1. ⏳ Run Step 1: Verify CWE-82 in database
2. ⏳ Based on Step 1 results, proceed with appropriate investigation steps
3. ⏳ Document findings and implement fix
4. ⏳ Test fix with multiple CWE-82 queries
5. ⏳ Close issue once verified working

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
