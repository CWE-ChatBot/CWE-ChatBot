from src.processing.query_processor import QueryProcessor


def test_preprocess_direct_cwe_includes_flags_and_strategy():
    qp = QueryProcessor()
    out = qp.preprocess_query("Explain CWE-79")
    assert out["has_direct_cwe"] is True
    assert out["query_type"] in ("direct_cwe_lookup", "general_security")
    assert out["enhanced_query"]
    assert out["search_strategy"] == "direct_lookup"
