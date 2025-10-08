#!/usr/bin/env python3
"""
Structured test queries for CWE retrieval testing based on user personas.

This file contains realistic queries that represent how different user types
would search for CWE information. Each query includes metadata about the
persona, expected use case, and optimal query configuration.

Based on user personas from docs/personas_scenarios/User Personas.md
and query format from apps/cwe_ingestion/README.md
"""

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class TestQuery:
    """Represents a test query with persona and configuration metadata."""

    query_text: str
    persona: str
    use_case: str
    query_type: str  # semantic, keyword, hybrid, direct
    expected_cwes: List[str]  # CWE IDs we expect to see in results
    optimal_weights: Dict[str, float]  # w_vec, w_fts, w_alias
    section_boost: str = None  # Optional section to boost
    description: str = ""  # Reasoning for this query


# PSIRT Member Queries - Focus on impact assessment and advisory creation
PSIRT_QUERIES = [
    TestQuery(
        query_text="vulnerability report shows SQL commands being executed through user input form",
        persona="PSIRT Member",
        use_case="Mapping vulnerability report to correct CWE for advisory",
        query_type="semantic",
        expected_cwes=["CWE-89"],
        optimal_weights={"w_vec": 0.65, "w_fts": 0.25, "w_alias": 0.10},
        description="PSIRT members need to map technical bug reports to precise CWEs under time pressure",
    ),
    TestQuery(
        query_text="user controlled script execution in web browser DOM manipulation",
        persona="PSIRT Member",
        use_case="Identifying XSS variants for security advisory",
        query_type="semantic",
        expected_cwes=["CWE-79", "CWE-94"],
        optimal_weights={"w_vec": 0.65, "w_fts": 0.25, "w_alias": 0.10},
        description="Complex XSS scenarios requiring precise CWE mapping for customer advisories",
    ),
    TestQuery(
        query_text="xss csrf sqli vulnerability report",
        persona="PSIRT Member",
        use_case="Quick mapping of scanner findings with acronyms",
        query_type="hybrid",
        expected_cwes=["CWE-79", "CWE-352", "CWE-89"],
        optimal_weights={"w_vec": 0.55, "w_fts": 0.25, "w_alias": 0.20},
        description="PSIRT often receives reports with security acronyms requiring alias matching",
    ),
    TestQuery(
        query_text="CWE-22",
        persona="PSIRT Member",
        use_case="Direct CWE lookup for advisory verification",
        query_type="direct",
        expected_cwes=["CWE-22"],
        optimal_weights={"w_vec": 0.65, "w_fts": 0.25, "w_alias": 0.10},
        description="PSIRT needs to verify CWE details when reviewing external reports",
    ),
]

# Developer Queries - Focus on remediation guidance and code examples
DEVELOPER_QUERIES = [
    TestQuery(
        query_text="how to prevent sql injection in database queries",
        persona="Developer",
        use_case="Getting remediation guidance for assigned vulnerability",
        query_type="semantic",
        expected_cwes=["CWE-89"],
        optimal_weights={"w_vec": 0.55, "w_fts": 0.30, "w_alias": 0.15},
        section_boost="Mitigations",
        description="Developers need actionable guidance on fixing vulnerabilities",
    ),
    TestQuery(
        query_text="input validation sanitization user data",
        persona="Developer",
        use_case="Understanding root cause of input validation bugs",
        query_type="semantic",
        expected_cwes=["CWE-20", "CWE-79", "CWE-89"],
        optimal_weights={"w_vec": 0.65, "w_fts": 0.25, "w_alias": 0.10},
        description="Developers need to understand underlying weakness patterns",
    ),
    TestQuery(
        query_text="buffer overflow memory corruption example code",
        persona="Developer",
        use_case="Looking for code examples to understand vulnerability",
        query_type="semantic",
        expected_cwes=["CWE-119", "CWE-120", "CWE-787"],
        optimal_weights={"w_vec": 0.60, "w_fts": 0.25, "w_alias": 0.15},
        section_boost="Examples",
        description="Developers prefer concrete code examples over abstract descriptions",
    ),
    TestQuery(
        query_text="path traversal directory file access vulnerability fix",
        persona="Developer",
        use_case="Understanding and fixing path traversal in file handling code",
        query_type="hybrid",
        expected_cwes=["CWE-22", "CWE-23", "CWE-36"],
        optimal_weights={"w_vec": 0.55, "w_fts": 0.30, "w_alias": 0.15},
        section_boost="Mitigations",
        description="Developers need specific guidance on path validation and sanitization",
    ),
]

# Academic Researcher Queries - Focus on relationships and comprehensive analysis
ACADEMIC_QUERIES = [
    TestQuery(
        query_text="all injection type vulnerabilities classification hierarchy",
        persona="Academic Researcher",
        use_case="Exploring CWE relationships for research paper",
        query_type="semantic",
        expected_cwes=["CWE-74", "CWE-89", "CWE-79", "CWE-78"],
        optimal_weights={"w_vec": 0.70, "w_fts": 0.20, "w_alias": 0.10},
        description="Researchers need to explore hierarchical relationships in CWE corpus",
    ),
    TestQuery(
        query_text="difference between CWE-23 and CWE-36 path traversal variants",
        persona="Academic Researcher",
        use_case="Understanding nuanced differences between similar CWEs",
        query_type="semantic",
        expected_cwes=["CWE-23", "CWE-36", "CWE-22"],
        optimal_weights={"w_vec": 0.65, "w_fts": 0.25, "w_alias": 0.10},
        description="Researchers need precise understanding of CWE distinctions for accurate categorization",
    ),
    TestQuery(
        query_text="memory safety vulnerabilities buffer overflow heap stack",
        persona="Academic Researcher",
        use_case="Categorizing memory corruption vulnerabilities for dataset analysis",
        query_type="semantic",
        expected_cwes=["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-787"],
        optimal_weights={"w_vec": 0.70, "w_fts": 0.20, "w_alias": 0.10},
        description="Academic analysis of memory safety vulnerability patterns and relationships",
    ),
    TestQuery(
        query_text="authentication authorization access control weakness patterns",
        persona="Academic Researcher",
        use_case="Research on access control vulnerability trends",
        query_type="semantic",
        expected_cwes=["CWE-287", "CWE-862", "CWE-863", "CWE-284"],
        optimal_weights={"w_vec": 0.65, "w_fts": 0.25, "w_alias": 0.10},
        description="Comprehensive research into authentication and authorization weakness families",
    ),
]

# Bug Bounty Hunter Queries - Focus on exploitation patterns and black-box mapping
BUG_BOUNTY_QUERIES = [
    TestQuery(
        query_text="file upload bypass filter validation payload",
        persona="Bug Bounty Hunter",
        use_case="Mapping exploit behavior to CWE for professional report",
        query_type="semantic",
        expected_cwes=["CWE-434", "CWE-20", "CWE-436"],
        optimal_weights={"w_vec": 0.60, "w_fts": 0.30, "w_alias": 0.10},
        description="Bug bounty hunters need to map exploitation techniques to precise CWEs",
    ),
    TestQuery(
        query_text="IDOR direct object reference bypass access control",
        persona="Bug Bounty Hunter",
        use_case="Identifying correct CWE for authorization bypass finding",
        query_type="hybrid",
        expected_cwes=["CWE-639", "CWE-862", "CWE-863"],
        optimal_weights={"w_vec": 0.60, "w_fts": 0.25, "w_alias": 0.15},
        description="Common bug bounty finding requiring precise CWE classification",
    ),
    TestQuery(
        query_text="parameter pollution HTTP request manipulation bypass",
        persona="Bug Bounty Hunter",
        use_case="Mapping unusual exploit technique to appropriate CWE",
        query_type="semantic",
        expected_cwes=["CWE-444", "CWE-20", "CWE-235"],
        optimal_weights={"w_vec": 0.65, "w_fts": 0.25, "w_alias": 0.10},
        description="Advanced exploitation techniques requiring careful CWE mapping",
    ),
    TestQuery(
        query_text="xxe xml external entity payload file disclosure",
        persona="Bug Bounty Hunter",
        use_case="Mapping XML exploitation to CWE for bounty submission",
        query_type="hybrid",
        expected_cwes=["CWE-611", "CWE-827"],
        optimal_weights={"w_vec": 0.60, "w_fts": 0.25, "w_alias": 0.15},
        description="XXE exploits common in bug bounty, need precise CWE for professional reports",
    ),
]

# Product Manager Queries - Focus on trend analysis and prevention strategies
PRODUCT_MANAGER_QUERIES = [
    TestQuery(
        query_text="CWE top 25 most dangerous software weaknesses 2023",
        persona="Product Manager",
        use_case="Accessing industry data for quarterly planning",
        query_type="keyword",
        expected_cwes=["CWE-79", "CWE-787", "CWE-20", "CWE-125", "CWE-89"],
        optimal_weights={"w_vec": 0.55, "w_fts": 0.35, "w_alias": 0.10},
        description="Product managers need credible industry data for resource allocation decisions",
    ),
    TestQuery(
        query_text="web application security common vulnerabilities prevention",
        persona="Product Manager",
        use_case="Building business case for proactive security training",
        query_type="semantic",
        expected_cwes=["CWE-79", "CWE-89", "CWE-287", "CWE-352"],
        optimal_weights={"w_vec": 0.60, "w_fts": 0.25, "w_alias": 0.15},
        section_boost="Mitigations",
        description="Strategic planning requires understanding common web vulnerability patterns",
    ),
    TestQuery(
        query_text="injection vulnerabilities impact business risk assessment",
        persona="Product Manager",
        use_case="Understanding risk for stakeholder presentations",
        query_type="semantic",
        expected_cwes=["CWE-74", "CWE-89", "CWE-79", "CWE-78"],
        optimal_weights={"w_vec": 0.65, "w_fts": 0.25, "w_alias": 0.10},
        description="Product managers need to communicate security risks to business stakeholders",
    ),
    TestQuery(
        query_text="mobile application security weaknesses common patterns",
        persona="Product Manager",
        use_case="Planning security epics for mobile development team",
        query_type="semantic",
        expected_cwes=["CWE-200", "CWE-327", "CWE-311", "CWE-312"],
        optimal_weights={"w_vec": 0.65, "w_fts": 0.25, "w_alias": 0.10},
        description="Mobile-specific security planning requires understanding platform-specific weaknesses",
    ),
]

# Combine all queries
ALL_PERSONA_QUERIES = {
    "psirt": PSIRT_QUERIES,
    "developer": DEVELOPER_QUERIES,
    "academic": ACADEMIC_QUERIES,
    "bug_bounty": BUG_BOUNTY_QUERIES,
    "product_manager": PRODUCT_MANAGER_QUERIES,
}

# Flat list of all queries for easy iteration
ALL_QUERIES = []
for persona_queries in ALL_PERSONA_QUERIES.values():
    ALL_QUERIES.extend(persona_queries)


def get_queries_by_persona(persona: str) -> List[TestQuery]:
    """Get all queries for a specific persona."""
    return ALL_PERSONA_QUERIES.get(persona, [])


def get_queries_by_type(query_type: str) -> List[TestQuery]:
    """Get all queries of a specific type (semantic, keyword, hybrid, direct)."""
    return [q for q in ALL_QUERIES if q.query_type == query_type]


def get_queries_with_section_boost() -> List[TestQuery]:
    """Get all queries that include section boost parameters."""
    return [q for q in ALL_QUERIES if q.section_boost is not None]


def print_query_summary():
    """Print a summary of all test queries."""
    print("📊 CWE Test Queries Summary")
    print("=" * 40)

    for persona_key, queries in ALL_PERSONA_QUERIES.items():
        persona_name = queries[0].persona if queries else persona_key
        print(f"{persona_name:20s}: {len(queries):2d} queries")

    print(f"{'Total':20s}: {len(ALL_QUERIES):2d} queries")

    print("\nQuery Types:")
    for query_type in ["semantic", "keyword", "hybrid", "direct"]:
        count = len(get_queries_by_type(query_type))
        print(f"  {query_type:10s}: {count:2d} queries")

    section_boost_count = len(get_queries_with_section_boost())
    print(f"  Section boost: {section_boost_count:2d} queries")


def export_for_cli_testing() -> List[Dict[str, Any]]:
    """Export queries in format suitable for CLI testing scripts."""
    export_data = []

    for query in ALL_QUERIES:
        query_data = {
            "query": query.query_text,
            "persona": query.persona,
            "use_case": query.use_case,
            "type": query.query_type,
            "expected_cwes": query.expected_cwes,
            "weights": query.optimal_weights,
            "description": query.description,
        }

        if query.section_boost:
            query_data["section_boost"] = query.section_boost

        export_data.append(query_data)

    return export_data


if __name__ == "__main__":
    print_query_summary()

    print("\n🔍 Sample Queries by Persona:")
    print("-" * 40)

    for persona_key, queries in ALL_PERSONA_QUERIES.items():
        if queries:
            sample = queries[0]
            print(f"\n{sample.persona}:")
            print(f"  Query: '{sample.query_text}'")
            print(f"  Use Case: {sample.use_case}")
            print(f"  Type: {sample.query_type}")
            print(
                f"  Expected: {', '.join(sample.expected_cwes[:3])}{'...' if len(sample.expected_cwes) > 3 else ''}"
            )
