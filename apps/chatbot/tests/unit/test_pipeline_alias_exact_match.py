from src.processing.pipeline import ProcessingPipeline


def make_chunk(cwe_id: str, section: str, text: str, hybrid: float = 0.8):
    return {
        "metadata": {
            "cwe_id": cwe_id,
            "section": section,
            "section_rank": 1,
            "name": "",
        },
        "document": text,
        "scores": {"hybrid": hybrid, "vec": hybrid, "fts": 0.0, "alias": 0.0},
    }


def test_alias_exact_match_boosts_missing_authentication():
    pipeline = ProcessingPipeline()
    query = (
        "This vulnerability is due to missing authentication in a critical function."
    )

    # CWE-306 should be preferred because alias contains the exact phrase
    cwe_chunks = {
        "CWE-306": {
            "name": "Missing Authentication for Critical Function",
            "chunks": [
                make_chunk("CWE-306", "Aliases", "missing authentication; broken auth"),
                make_chunk(
                    "CWE-306",
                    "Description",
                    "Authentication controls are missing for critical functionality.",
                ),
            ],
            "exact_match": False,
        },
        "CWE-862": {
            "name": "Missing Authorization",
            "chunks": [
                make_chunk(
                    "CWE-862",
                    "Aliases",
                    "missing authorization; privilege not checked",
                    hybrid=0.82,
                ),
                make_chunk(
                    "CWE-862",
                    "Description",
                    "Authorization check is missing for a resource.",
                ),
            ],
            "exact_match": False,
        },
    }

    scored = pipeline._calculate_confidence_scores(query, cwe_chunks)
    # Sort descending by confidence
    scored.sort(key=lambda r: r["confidence"], reverse=True)

    top = scored[0]
    assert (
        top["cwe_id"] == "CWE-306"
    ), f"Expected CWE-306 to rank highest for 'missing authentication', got {top['cwe_id']}"
