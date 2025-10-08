#!/usr/bin/env python3
"""
Validation script for persona query structure and completeness.

This script validates the persona queries without requiring database access,
useful for CI/CD and development validation.
"""

import json
from typing import Dict

from .test_queries_personas import (
    ALL_PERSONA_QUERIES,
    ALL_QUERIES,
    export_for_cli_testing,
    get_queries_by_persona,
    get_queries_by_type,
    get_queries_with_section_boost,
)


def validate_query_structure():
    """Validate that all queries have required fields and valid values."""
    print("🔍 Validating Query Structure...")

    errors = []
    warnings = []

    for i, query in enumerate(ALL_QUERIES):
        query_id = f"Query {i+1} ({query.persona})"

        # Required fields validation
        if not query.query_text or not query.query_text.strip():
            errors.append(f"{query_id}: Empty query_text")

        if not query.persona:
            errors.append(f"{query_id}: Missing persona")

        if not query.use_case:
            errors.append(f"{query_id}: Missing use_case")

        if query.query_type not in ["semantic", "keyword", "hybrid", "direct"]:
            errors.append(f"{query_id}: Invalid query_type '{query.query_type}'")

        if not query.expected_cwes:
            warnings.append(f"{query_id}: No expected CWEs specified")
        else:
            # Validate CWE format
            for cwe in query.expected_cwes:
                if not cwe.startswith("CWE-") or not cwe[4:].isdigit():
                    errors.append(f"{query_id}: Invalid CWE format '{cwe}'")

        # Weights validation
        required_weights = ["w_vec", "w_fts", "w_alias"]
        for weight_name in required_weights:
            if weight_name not in query.optimal_weights:
                errors.append(f"{query_id}: Missing weight '{weight_name}'")
            else:
                weight_value = query.optimal_weights[weight_name]
                if not 0 <= weight_value <= 1:
                    errors.append(
                        f"{query_id}: Weight '{weight_name}' out of range: {weight_value}"
                    )

        # Check if weights sum to approximately 1.0
        if all(w in query.optimal_weights for w in required_weights):
            weight_sum = sum(query.optimal_weights[w] for w in required_weights)
            if not 0.95 <= weight_sum <= 1.05:
                warnings.append(
                    f"{query_id}: Weights don't sum to ~1.0: {weight_sum:.2f}"
                )

    return errors, warnings


def validate_persona_coverage():
    """Validate that all personas have good query coverage."""
    print("👥 Validating Persona Coverage...")

    warnings = []

    expected_personas = {
        "PSIRT Member": "psirt",
        "Developer": "developer",
        "Academic Researcher": "academic",
        "Bug Bounty Hunter": "bug_bounty",
        "Product Manager": "product_manager",
    }

    for persona_name, persona_key in expected_personas.items():
        queries = get_queries_by_persona(persona_key)

        if len(queries) < 3:
            warnings.append(
                f"{persona_name}: Only {len(queries)} queries (recommend 3+)"
            )

        # Check query type diversity
        query_types = set(q.query_type for q in queries)
        if len(query_types) < 2:
            warnings.append(
                f"{persona_name}: Limited query type diversity: {query_types}"
            )

    return warnings


def validate_query_diversity():
    """Validate overall query diversity and coverage."""
    print("🎯 Validating Query Diversity...")

    warnings = []

    # Query type distribution
    type_counts = {}
    for query_type in ["semantic", "keyword", "hybrid", "direct"]:
        count = len(get_queries_by_type(query_type))
        type_counts[query_type] = count

    total_queries = len(ALL_QUERIES)

    # Check for reasonable distribution
    if type_counts["semantic"] < total_queries * 0.5:
        warnings.append(
            f"Low semantic query ratio: {type_counts['semantic']}/{total_queries}"
        )

    if type_counts["hybrid"] < 2:
        warnings.append(f"Few hybrid queries: {type_counts['hybrid']} (recommend 3+)")

    if type_counts["direct"] < 1:
        warnings.append("No direct CWE lookup queries")

    # Section boost usage
    section_boost_queries = get_queries_with_section_boost()
    if len(section_boost_queries) < 2:
        warnings.append(
            f"Few section boost queries: {len(section_boost_queries)} (recommend 3+)"
        )

    # CWE coverage diversity
    all_expected_cwes = set()
    for query in ALL_QUERIES:
        all_expected_cwes.update(query.expected_cwes)

    if len(all_expected_cwes) < 15:
        warnings.append(
            f"Limited CWE coverage: {len(all_expected_cwes)} unique CWEs (recommend 15+)"
        )

    return warnings


def generate_query_report():
    """Generate a comprehensive report about the query dataset."""
    print("\n📊 PERSONA QUERY DATASET REPORT")
    print("=" * 50)

    # Basic statistics
    print(f"Total Queries: {len(ALL_QUERIES)}")
    print(f"Personas: {len(ALL_PERSONA_QUERIES)}")

    # Per-persona breakdown
    print("\n👥 Queries by Persona:")
    for persona_key, queries in ALL_PERSONA_QUERIES.items():
        persona_name = queries[0].persona if queries else persona_key
        print(f"  {persona_name:20s}: {len(queries):2d} queries")

    # Query type distribution
    print("\n🔍 Query Type Distribution:")
    for query_type in ["semantic", "keyword", "hybrid", "direct"]:
        count = len(get_queries_by_type(query_type))
        percentage = (count / len(ALL_QUERIES)) * 100
        print(f"  {query_type:10s}: {count:2d} queries ({percentage:4.1f}%)")

    # Section boost usage
    section_boost_queries = get_queries_with_section_boost()
    print(f"\n🎯 Section Boost Usage: {len(section_boost_queries)} queries")
    boost_sections: Dict[str, float] = {}
    for query in section_boost_queries:
        section = query.section_boost
        boost_sections[section] = boost_sections.get(section, 0) + 1

    for section, count in boost_sections.items():
        print(f"  {section:15s}: {count} queries")

    # CWE coverage
    all_expected_cwes = set()
    for query in ALL_QUERIES:
        all_expected_cwes.update(query.expected_cwes)

    print(f"\n🎯 CWE Coverage: {len(all_expected_cwes)} unique CWEs expected")

    # Most commonly expected CWEs
    cwe_frequency: Dict[str, int] = {}
    for query in ALL_QUERIES:
        for cwe in query.expected_cwes:
            cwe_frequency[cwe] = cwe_frequency.get(cwe, 0) + 1

    top_cwes = sorted(cwe_frequency.items(), key=lambda x: x[1], reverse=True)[:5]
    print("  Most frequent expected CWEs:")
    for cwe, freq in top_cwes:
        print(f"    {cwe}: {freq} queries")

    # Use case categories
    print("\n📋 Use Case Categories:")
    use_case_keywords = {
        "mapping": 0,
        "remediation": 0,
        "research": 0,
        "advisory": 0,
        "planning": 0,
        "exploit": 0,
    }

    for query in ALL_QUERIES:
        use_case_lower = query.use_case.lower()
        for keyword in use_case_keywords:
            if keyword in use_case_lower:
                use_case_keywords[keyword] += 1

    for category, count in use_case_keywords.items():
        print(f"  {category.title():12s}: {count} queries")


def export_queries_json():
    """Export queries to JSON format for external tools."""
    export_data = export_for_cli_testing()

    output_file = "persona_queries_export.json"
    with open(output_file, "w") as f:
        json.dump(export_data, f, indent=2)

    print(f"\n💾 Exported {len(export_data)} queries to {output_file}")
    return output_file


def main():
    """Run all validation checks and generate report."""
    print("🔍 PERSONA QUERY VALIDATION")
    print("=" * 40)

    # Structure validation
    errors, warnings = validate_query_structure()

    # Persona coverage validation
    persona_warnings = validate_persona_coverage()
    warnings.extend(persona_warnings)

    # Diversity validation
    diversity_warnings = validate_query_diversity()
    warnings.extend(diversity_warnings)

    # Report results
    print("\n📋 Validation Results:")
    print(f"  Errors: {len(errors)}")
    print(f"  Warnings: {len(warnings)}")

    if errors:
        print("\n❌ ERRORS (must fix):")
        for error in errors:
            print(f"  • {error}")

    if warnings:
        print("\n⚠️  WARNINGS (should review):")
        for warning in warnings:
            print(f"  • {warning}")

    if not errors and len(warnings) <= 3:
        print("\n✅ VALIDATION PASSED: Query dataset is well-structured!")
    elif not errors:
        print("\n⚠️  VALIDATION PASSED WITH WARNINGS: Minor issues to address.")
    else:
        print("\n❌ VALIDATION FAILED: Critical errors must be fixed.")

    # Generate comprehensive report
    generate_query_report()

    # Export for external use
    _ = export_queries_json()

    print("\n🎯 Ready for testing! Use:")
    print("  poetry run python run_persona_query_tests.py")
    print("  poetry run python run_persona_query_tests.py --persona psirt")
    print("  poetry run python run_persona_query_tests.py --verbose")

    return len(errors) == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
