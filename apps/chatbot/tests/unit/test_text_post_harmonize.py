from src.utils.text_post import harmonize_cwe_names_in_table


def test_harmonize_cwe_names_in_table_replaces_name_cells():
    content = (
        "| Candidate CWE | Suitability | Rationale |\n"
        "|---|---|---|\n"
        "| CWE-306 | Authentication Bypass Errors | correct CWE is missing authentication |\n"
        "| CWE-79  | XSS | example |\n"
    )

    mapping = {
        "CWE-306": "Missing Authentication for Critical Function",
        "CWE-79": "Cross-site Scripting",
    }

    out = harmonize_cwe_names_in_table(content, mapping, {})
    # Ensure the canonical names are present on the same lines as their CWE IDs
    line_306 = next((ln for ln in out.splitlines() if 'CWE-306' in ln), '')
    assert 'Missing Authentication for Critical Function' in line_306
    line_79 = next((ln for ln in out.splitlines() if 'CWE-79' in ln), '')
    assert 'Cross-site Scripting' in line_79


def test_harmonize_cwe_names_in_tab_separated_rows():
    content = (
        "Candidate CWE\tSuitability\tRationale\n"
        "CWE-306\tAuthentication Bypass Errors\tcorrect CWE is missing authentication\n"
        "CWE-79\tXSS\texample\n"
    )

    mapping = {
        "CWE-306": "Missing Authentication for Critical Function",
        "CWE-79": "Cross-site Scripting",
    }

    out = harmonize_cwe_names_in_table(content, mapping, {})
    assert "CWE-306\t Missing Authentication for Critical Function\t" in out
    assert "CWE-79\t Cross-site Scripting\t" in out

def test_harmonize_cwe_policy_in_table():
    content = (
        "| CWE ID | CWE Name | Confidence | CWE Abstraction Level | CWE Vulnerability Mapping Label | CWE-Vulnerability Mapping Notes |\n"
        "|---|---|---|---|---|---|\n"
        "| CWE-287 | Improper Authentication | 0.9 | Class | Primary | Allowed |\n"
    )

    id_to_name = {
        "CWE-287": "Improper Authentication",
    }
    id_to_policy = {
        "CWE-287": "Discouraged",
    }

    out = harmonize_cwe_names_in_table(content, id_to_name, id_to_policy)
    line_287 = next((ln for ln in out.splitlines() if 'CWE-287' in ln), '')
    assert '| Discouraged |' in line_287
