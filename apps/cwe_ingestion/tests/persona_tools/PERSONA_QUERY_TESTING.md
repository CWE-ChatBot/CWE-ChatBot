# Persona-Based CWE Query Testing

This directory contains a comprehensive test suite for validating CWE retrieval performance across different user personas, based on the user scenarios defined in `docs/personas_scenarios/User Personas.md`.

## 📁 Files Overview

### Core Query Dataset
- **`apps/cwe_ingestion/tests/persona_tools/test_queries_personas.py`** - Structured dataset of 20 test queries across 5 personas
- **`persona_queries_export.json`** - JSON export of queries for external tools

### Testing Tools
- **`apps/cwe_ingestion/tests/persona_tools/run_persona_query_tests.py`** - Execute queries against production database
- **`apps/cwe_ingestion/tests/persona_tools/validate_persona_queries.py`** - Validate query structure without database access
- **`apps/cwe_ingestion/tests/persona_tools/PERSONA_QUERY_TESTING.md`** - This documentation file

## 🎯 Query Dataset Summary

### Personas Covered (4 queries each)
1. **PSIRT Member** - Impact assessment and advisory creation
2. **Developer** - Remediation guidance and code examples
3. **Academic Researcher** - Relationships and comprehensive analysis
4. **Bug Bounty Hunter** - Exploitation patterns and black-box mapping
5. **Product Manager** - Trend analysis and prevention strategies

### Query Types Distribution
- **Semantic** (70%): Conceptual searches matching user intent
- **Hybrid** (20%): Combination of vector + full-text + alias matching
- **Direct** (5%): Exact CWE ID lookups
- **Keyword** (5%): Specific term searches

### Coverage
- **31 unique CWEs** expected across all queries
- **4 queries** use section boost (Mitigations, Examples)
- **Common CWEs**: SQL Injection (CWE-89), XSS (CWE-79), Input Validation (CWE-20)

## 🚀 Quick Start

### 1. Validate Query Structure
```bash
# Validate queries without database connection (run as module)
poetry run python -m apps.cwe_ingestion.tests.persona_tools.validate_persona_queries
```

### 2. Run All Persona Tests
```bash
# Test all queries against database (run as module)
poetry run python -m apps.cwe_ingestion.tests.persona_tools.run_persona_query_tests
```

### 3. Run Targeted Tests
```bash
# Test specific persona
poetry run python -m apps.cwe_ingestion.tests.persona_tools.run_persona_query_tests --persona psirt

# Test specific query types
poetry run python -m apps.cwe_ingestion.tests.persona_tools.run_persona_query_tests --query-type semantic

# Limit number of queries
poetry run python -m apps.cwe_ingestion.tests.persona_tools.run_persona_query_tests --max-queries 5

# Verbose output with detailed results
poetry run python -m apps.cwe_ingestion.tests.persona_tools.run_persona_query_tests --verbose
```

## 📊 Example Query Analysis

### PSIRT Member Query Example
```python
TestQuery(
    query_text="vulnerability report shows SQL commands being executed through user input form",
    persona="PSIRT Member",
    use_case="Mapping vulnerability report to correct CWE for advisory",
    query_type="semantic",
    expected_cwes=["CWE-89"],
    optimal_weights={"w_vec": 0.65, "w_fts": 0.25, "w_alias": 0.10},
    description="PSIRT members need to map technical bug reports to precise CWEs under time pressure"
)
```

**Why this query matters:**
- Simulates real vulnerability report language
- Tests semantic understanding vs exact keyword matching
- Validates time-pressured advisory creation workflow

### Developer Query Example
```python
TestQuery(
    query_text="how to prevent sql injection in database queries",
    persona="Developer",
    use_case="Getting remediation guidance for assigned vulnerability",
    query_type="semantic",
    expected_cwes=["CWE-89"],
    optimal_weights={"w_vec": 0.55, "w_fts": 0.30, "w_alias": 0.15},
    section_boost="Mitigations",
    description="Developers need actionable guidance on fixing vulnerabilities"
)
```

**Why this query matters:**
- Tests prevention-focused language detection
- Validates Mitigations section boost functionality
- Simulates developer remediation workflow

## 🔍 Query Validation Criteria

### Structure Validation
- ✅ Required fields present (query_text, persona, use_case, etc.)
- ✅ Valid query_type values
- ✅ Proper CWE ID format (CWE-XXX)
- ✅ Weight values in valid range (0-1)
- ✅ Weights sum to ~1.0

### Coverage Validation
- ✅ Minimum 3 queries per persona
- ✅ Query type diversity across personas
- ✅ Section boost usage for appropriate queries
- ✅ Diverse CWE coverage (15+ unique CWEs)

### Performance Criteria
- ✅ **Success Rate**: 80%+ queries pass accuracy test
- ✅ **Accuracy**: 50%+ expected CWEs found in results
- ✅ **Performance**: <2 seconds per query (including embedding)
- ✅ **Top Match**: Expected CWE appears in top results

## 📈 Expected Test Results

### Typical Performance Metrics
```
📊 TEST SUMMARY
========================================
✅ Successful: 18/20
❌ Failed: 2
⏱️  Average query time: 450ms
🎯 Average accuracy: 75%
🕐 Total test time: 12.5s

📈 Results by Persona:
  PSIRT Member        : 4/4 (100%) | Avg accuracy: 85%
  Developer           : 4/4 (100%) | Avg accuracy: 80%
  Academic Researcher : 3/4 (75%)  | Avg accuracy: 70%
  Bug Bounty Hunter   : 4/4 (100%) | Avg accuracy: 75%
  Product Manager     : 3/4 (75%)  | Avg accuracy: 65%
```

### Success Indicators
- **Overall success rate** ≥ 80%
- **Average query time** < 500ms
- **Average accuracy** ≥ 70%
- **No critical errors** in database connection or embedding generation

## 🛠️ Customizing Queries

### Adding New Persona Queries
1. Add queries to appropriate persona list in `apps/cwe_ingestion/tests/persona_tools/test_queries_personas.py`
2. Follow the `TestQuery` dataclass structure
3. Run validation: `poetry run python -m apps.cwe_ingestion.tests.persona_tools.validate_persona_queries`
4. Test new queries: `poetry run python -m apps.cwe_ingestion.tests.persona_tools.run_persona_query_tests`

### Query Design Best Practices
- **Realistic language**: Use terms your users actually say
- **Specific use cases**: Tie to actual user workflow scenarios
- **Expected CWEs**: Include 1-3 most relevant CWEs
- **Optimal weights**: Tune based on query characteristics:
  - Semantic queries: Higher `w_vec` (0.65-0.70)
  - Acronym queries: Higher `w_alias` (0.15-0.20)
  - Prevention queries: Higher `w_fts` (0.30) + section boost

## 🎯 Integration with CI/CD

### Automated Testing
```bash
# Basic validation (no database required)
poetry run python -m apps.cwe_ingestion.tests.persona_tools.validate_persona_queries

# Full testing (requires database)
poetry run python -m apps.cwe_ingestion.tests.persona_tools.run_persona_query_tests --max-queries 10
```

### Exit Codes
- **0**: All tests passed
- **1**: Tests failed or validation errors

### JSON Export
Use `persona_queries_export.json` for:
- External testing tools
- Performance benchmarking
- Integration with other systems
- Query analysis and reporting

## 🔗 Related Documentation

- **User Personas**: `docs/personas_scenarios/User Personas.md`
- **Query Format**: `apps/cwe_ingestion/README.md` (Query section)
- **Database Setup**: `apps/cwe_ingestion/README.md` (Installation section)
- **Hybrid Retrieval**: `apps/cwe_ingestion/README.md` (Hybrid Retrieval Details section)

## 🎉 Success Criteria

Your CWE retrieval system is **ready for production** when:

✅ **Validation passes** with minimal warnings
✅ **80%+ query success rate** across all personas
✅ **Sub-500ms average response time**
✅ **70%+ accuracy** on expected CWE mapping
✅ **Consistent performance** across multiple test runs

These persona-based tests ensure your CWE ChatBot will deliver excellent user experience for all target user types!
