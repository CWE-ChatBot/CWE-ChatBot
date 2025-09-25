# CWE ChatBot Manual Test Flows

Manual testing scenarios to validate conversational flows and semantic understanding.
Run these tests at http://localhost:8080 to verify system behavior.

## 🎯 Test Results Tracking

**Test Run Date**: _____
**Tester**: _____
**Version**: Story 3.4 UI/UX + Off-topic & Context Fixes

---

## Test Flow 1: Off-Topic Query Handling

**Objective**: Verify the system correctly identifies and redirects non-security queries.

### Test Cases

#### 1.1 Animal Query
- **Input**: "what is a dog?"
- **Expected**: Polite redirection message explaining bot purpose + list of security topics
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 1.2 Food Query
- **Input**: "how do I cook pasta?"
- **Expected**: Redirection message
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 1.3 Weather Query
- **Input**: "what's the weather like today?"
- **Expected**: Redirection message
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 1.4 General Knowledge
- **Input**: "who is the president of France?"
- **Expected**: Redirection message
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 1.5 Edge Case - Security-Adjacent
- **Input**: "what is a firewall?" (should be processed, not redirected)
- **Expected**: Security-focused response about network security
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

---

## Test Flow 2: Follow-up Context Maintenance

**Objective**: Verify the system maintains correct CWE context across conversation turns.

### Test Cases

#### 2.1 Basic CWE Follow-up
1. **Input**: "what is CWE-79?"
2. **Expected**: Information about Cross-site Scripting (XSS)
3. **Input**: "tell me more"
4. **Expected**: Additional details about CWE-79 (NOT a different CWE)
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 2.2 Multiple Follow-ups
1. **Input**: "explain CWE-89"
2. **Expected**: SQL Injection information
3. **Input**: "what are the consequences?"
4. **Expected**: CWE-89 consequences
5. **Input**: "how do I prevent it?"
6. **Expected**: CWE-89 prevention strategies
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 2.3 Context Switch
1. **Input**: "what is CWE-79?"
2. **Expected**: XSS information
3. **Input**: "what about CWE-89?"
4. **Expected**: SQL Injection information
5. **Input**: "tell me more"
6. **Expected**: More about CWE-89 (the most recent specific CWE)
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 2.4 Complex Follow-up Patterns
1. **Input**: "tell me about buffer overflow"
2. **Expected**: CWE-120/121/122 related information
3. **Input**: "what are examples of this?"
4. **Expected**: Buffer overflow examples
5. **Input**: "show me related weaknesses"
6. **Expected**: Related CWEs to buffer overflow
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

---

## Test Flow 3: Persona-Specific Responses

**Objective**: Verify responses adapt appropriately to different cybersecurity personas.

### Test Cases

#### 3.1 PSIRT Member Persona
- **Switch to**: PSIRT Member
- **Input**: "what is CWE-79?"
- **Expected**: Response emphasizes impact assessment, severity, advisory language
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 3.2 Developer Persona
- **Switch to**: Developer
- **Input**: "what is CWE-79?"
- **Expected**: Response emphasizes code examples, remediation steps, prevention
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 3.3 Bug Bounty Hunter Persona
- **Switch to**: Bug Bounty Hunter
- **Input**: "tell me about XSS"
- **Expected**: Response focuses on exploitation patterns, discovery techniques
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 3.4 Academic Researcher Persona
- **Switch to**: Academic Researcher
- **Input**: "what is CWE-79?"
- **Expected**: Comprehensive analysis, relationships, research context
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

---

## Test Flow 4: UI/UX Components

**Objective**: Verify UI enhancements work correctly.

### Test Cases

#### 4.1 Settings Dialog
- **Action**: Click settings gear icon
- **Expected**: Dialog opens with visible text, controls work
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 4.2 Persona Switching
- **Action**: Click persona dropdown
- **Expected**: All persona options visible with text
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 4.3 Dark/Light Mode Toggle
- **Action**: Toggle theme
- **Expected**: Button has visible text/icon, theme switches
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 4.4 Color Palette Visibility
- **Expected**: CWE Blue, CVE Orange, CWE Maroon visible in interface
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

---

## Test Flow 5: Advanced Conversational Patterns

**Objective**: Test complex conversational scenarios.

### Test Cases

#### 5.1 Mixed Topic Conversation
1. **Input**: "what is CWE-79?"
2. **Input**: "how about dogs?" (off-topic)
3. **Expected**: Redirection message
4. **Input**: "ok, tell me more about XSS"
5. **Expected**: Should understand "XSS" refers back to CWE-79
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 5.2 Ambiguous Follow-up
1. **Input**: "compare CWE-79 and CWE-89"
2. **Input**: "which one is more dangerous?"
3. **Expected**: Comparison between XSS and SQL Injection
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 5.3 Technical Depth Progression
1. **Input**: "what is SQL injection?"
2. **Input**: "show me a code example"
3. **Input**: "how would an attacker exploit this?"
4. **Input**: "what's the best prevention method?"
- **Expected**: Increasingly detailed responses maintaining SQL injection context
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

---

## Test Flow 6: Error Handling and Edge Cases

**Objective**: Verify system handles edge cases gracefully.

### Test Cases

#### 6.1 Invalid CWE ID
- **Input**: "what is CWE-99999?"
- **Expected**: Graceful handling, suggest valid CWEs
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 6.2 Very Long Input
- **Input**: [Very long security-related query with 500+ words]
- **Expected**: Processing with length warning, but still functional
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

#### 6.3 Empty Follow-up
1. **Input**: "what is CWE-79?"
2. **Input**: "more" (minimal follow-up)
3. **Expected**: Should understand and provide more CWE-79 details
- **Actual**: ☐ Pass ☐ Fail
- **Notes**:

---

## Summary Assessment

### ✅ Working Features
- [ ] Off-topic query detection and redirection
- [ ] Follow-up context maintenance
- [ ] Persona-specific response adaptation
- [ ] UI text visibility and interactions
- [ ] Color system implementation
- [ ] Complex conversational flows

### ❌ Issues Found
1.
2.
3.

### 📝 Overall Assessment
**Rating**: ___/10
**Key Strengths**:
**Areas for Improvement**:
**Recommended Next Steps**:

---

## 🚀 Quick Test Commands

Copy-paste these for rapid testing:

```
# Off-topic tests
what is a dog?
how do I cook pasta?
what's the weather today?

# Context tests
what is CWE-79?
tell me more
what are examples?
how do I prevent it?

# Persona tests (switch personas between these)
what is SQL injection?
explain buffer overflow
tell me about XSS

# Edge cases
what is CWE-99999?
more
```