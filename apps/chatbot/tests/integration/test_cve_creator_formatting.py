"""
Integration-style unit test for CVE Creator formatting utility.
Ensures bracketed segments are converted to bold, while markdown links remain intact.
"""


from src.response_generator import ResponseGenerator


def test_format_cve_creator_brackets_to_bold(monkeypatch):
    rg = ResponseGenerator(gemini_api_key="dummy-key")

    sample = (
        "[Remote Code Execution] in [Apache Log4j] allows [attacker] to [execute code].\n"
        "See [details](https://example.com/details)."
    )
    formatted = rg._format_cve_creator(sample)

    assert "**Remote Code Execution**" in formatted
    assert "**Apache Log4j**" in formatted
    assert "[attacker]" not in formatted
    assert "[execute code]" not in formatted
    # Ensure markdown link preserved
    assert "[details](https://example.com/details)" in formatted
