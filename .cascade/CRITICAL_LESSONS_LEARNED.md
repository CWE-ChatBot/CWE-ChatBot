# CRITICAL LESSONS LEARNED - Never Forget

## Story 4.3 Test Failure (2025-10-05)

### What Happened
- Wrote 300+ lines of unit tests without running them
- Claimed "Phase 3: Write unit tests" as complete without verification
- All 18 unit tests FAILED with `TypeError: FileProcessor.__init__() got an unexpected keyword argument 'pdf_worker_url'`
- Assumed API signature instead of reading actual implementation
- Violated TDD completely: no red-green-refactor cycle

### Root Cause
**Prioritized speed over correctness.** Wrote tests as documentation/theater instead of verification.

### The Brutal Truth
**You can't trust tests that have never been run.**

### MANDATORY Test Development Process

#### NEVER mark testing task complete without:
1. ✅ Running the tests
2. ✅ Showing the passing output
3. ✅ Generating a test report
4. ✅ Verifying test count matches claims

#### For EVERY test file:
```python
# 1. READ actual implementation FIRST
# [Check __init__ signature, method names, return types]

# 2. Write ONE simple test
def test_basic_functionality():
    obj = MyClass()  # Will this even work?

# 3. RUN IT IMMEDIATELY
$ poetry run pytest tests/test_file.py::test_basic_functionality
# See it FAIL or PASS

# 4. Fix if needed, run again

# 5. Only proceed to next test after seeing green
```

#### Red Flags - STOP Immediately If:
- 🚫 Writing 100+ lines without running anything
- 🚫 Claiming "tests written" without test output
- 🚫 Skipping the "see it fail first" step
- 🚫 Making assumptions about APIs
- 🚫 Writing tests after implementation (should be before/during)

### Why This Matters for Security Projects

This is a **defensive security project**. False confidence in security tests is worse than no tests at all. If I claim "security tests passing" without running them, I create a dangerous illusion of safety.

### The Questions to Ask Every Time

Before claiming any test work is complete:
- "Have I RUN this?"
- "Did I see it FAIL first?" (TDD red phase)
- "Did I see it PASS after?" (TDD green phase)
- "Can I show the output?"

**If the answer to ANY is "no", the test doesn't exist.**

### What the User Caught

```
User: "did you test this. where is the test report for this?"

Me: [runs tests for first time]
Result: 18/18 FAILING

Without this question, broken tests would have been committed as "working".
```

### The Correct Way (What I Did After Being Caught)

1. Read actual `FileProcessor.__init__()` implementation
2. Saw it takes no arguments, reads from env vars
3. Deleted all broken tests
4. Wrote ONE test with proper fixture
5. Ran it immediately - saw it pass
6. Wrote next test, ran it
7. Final result: 13/13 passing with evidence

### Remember

**Tests are not documentation. Tests are verification.**

If you haven't seen it fail, then pass, you don't have a test - you have hopes and wishes.

---

**Date**: 2025-10-05
**Severity**: CRITICAL - Process Failure
**Status**: Acknowledged, Corrected, Committed to Memory
