# apps/cwe_ingestion/tests/unit/test_parser.py
import tempfile
from pathlib import Path


def test_cwe_parser_class_exists():
    """Test CWEParser class can be imported and instantiated."""
    from apps.cwe_ingestion.parser import CWEParser

    parser = CWEParser()
    assert parser is not None
    # This test MUST fail first - CWEParser doesn't exist yet


def test_parser_has_xxe_protection():
    """Test that parser is configured with XXE protection."""
    from apps.cwe_ingestion.parser import CWEParser

    parser = CWEParser()

    # Check that parser has XXE protection enabled
    assert hasattr(parser, "xxe_protection_enabled")
    assert parser.xxe_protection_enabled is True
    assert hasattr(parser, "_configure_secure_parser")


def test_parser_extracts_required_fields():
    """Test that parser extracts specific CWE fields: ID, Name, Abstraction, Status, Description, ExtendedDescription, AlternateTerms, ObservedExamples, RelatedWeaknesses."""
    from apps.cwe_ingestion.parser import CWEParser

    # Sample comprehensive CWE XML for testing all fields
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <Weakness_Catalog>
        <Weaknesses>
            <Weakness ID="79" Name="Cross-site Scripting" Abstraction="Base" Status="Stable">
                <Description>
                    <Description_Summary>The software does not neutralize user input...</Description_Summary>
                </Description>
                <Extended_Description>
                    Cross-site scripting attacks can lead to session hijacking...
                </Extended_Description>
                <Alternate_Terms>
                    <Alternate_Term>
                        <Term>XSS</Term>
                        <Description>Common abbreviation for Cross-site Scripting</Description>
                    </Alternate_Term>
                </Alternate_Terms>
                <Observed_Examples>
                    <Observed_Example>
                        <Reference>CVE-2002-0738</Reference>
                        <Description>XSS in web application allows remote attackers...</Description>
                    </Observed_Example>
                </Observed_Examples>
                <Related_Weaknesses>
                    <Related_Weakness Nature="ChildOf" CWE_ID="20" View_ID="1000"/>
                </Related_Weaknesses>
            </Weakness>
        </Weaknesses>
    </Weakness_Catalog>"""

    parser = CWEParser()

    # Test with sample data
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(sample_xml)
        temp_file = f.name

    try:
        result = parser.parse_file(temp_file, target_cwes=["CWE-79"])

        assert len(result) == 1
        cwe = result[0]

        # Test all required fields are extracted
        assert cwe.ID == "79"
        assert cwe.Name == "Cross-site Scripting"
        assert cwe.Abstraction == "Base"
        assert cwe.Status == "Stable"
        assert "The software does not neutralize user input" in cwe.Description
        assert "Cross-site scripting attacks can lead" in cwe.ExtendedDescription

        # Test alternate terms
        assert len(cwe.AlternateTerms) == 1
        assert cwe.AlternateTerms[0].Term == "XSS"
        assert "Common abbreviation" in cwe.AlternateTerms[0].Description

        # Test observed examples
        assert len(cwe.ObservedExamples) == 1
        assert cwe.ObservedExamples[0].Reference == "CVE-2002-0738"
        assert "XSS in web application" in cwe.ObservedExamples[0].Description

        # Test related weaknesses
        assert len(cwe.RelatedWeaknesses) == 1
        assert cwe.RelatedWeaknesses[0].Nature == "ChildOf"
        assert cwe.RelatedWeaknesses[0].CweID == "20"
        assert cwe.RelatedWeaknesses[0].ViewID == "1000"

        # Test full_text contains all information
        full_text = cwe.to_searchable_text()
        assert "CWE-79: Cross-site Scripting" in full_text
        assert "Abstraction Level: Base" in full_text
        assert "Status: Stable" in full_text
    finally:
        Path(temp_file).unlink()


def test_parser_filters_target_cwes():
    """Test that parser only extracts specified CWE IDs."""
    from apps.cwe_ingestion.parser import CWEParser

    # Sample XML with multiple CWEs (including required Abstraction and Status attributes)
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <Weakness_Catalog>
        <Weaknesses>
            <Weakness ID="79" Name="Cross-site Scripting" Abstraction="Base" Status="Stable">
                <Description><Description_Summary>XSS desc</Description_Summary></Description>
            </Weakness>
            <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Status="Stable">
                <Description><Description_Summary>SQL desc</Description_Summary></Description>
            </Weakness>
        </Weaknesses>
    </Weakness_Catalog>"""

    parser = CWEParser()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(sample_xml)
        temp_file = f.name

    try:
        # Request only CWE-79
        result = parser.parse_file(temp_file, target_cwes=["CWE-79"])

        assert len(result) == 1
        assert result[0].ID == "79"
        assert result[0].Name == "Cross-site Scripting"
    finally:
        Path(temp_file).unlink()


def test_parser_handles_missing_fields_gracefully():
    """Test parser handles XML with missing optional fields."""
    from apps.cwe_ingestion.parser import CWEParser

    # Minimal XML with only required fields
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <Weakness_Catalog>
        <Weaknesses>
            <Weakness ID="79" Name="Cross-site Scripting" Abstraction="Base" Status="Stable">
                <Description><Description_Summary>Basic desc</Description_Summary></Description>
            </Weakness>
        </Weaknesses>
    </Weakness_Catalog>"""

    parser = CWEParser()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(sample_xml)
        temp_file = f.name

    try:
        result = parser.parse_file(temp_file, target_cwes=["CWE-79"])

        assert len(result) == 1
        cwe = result[0]
        assert cwe.ID == "79"
        assert cwe.Name == "Cross-site Scripting"

        # Optional fields should be empty but present
        assert cwe.ExtendedDescription is None or cwe.ExtendedDescription == ""
        assert cwe.AlternateTerms == []
        assert cwe.ObservedExamples == []
        assert cwe.RelatedWeaknesses == []
    finally:
        Path(temp_file).unlink()


def test_parser_security_configuration():
    """Test that parser has security configurations enabled."""
    import apps.cwe_ingestion.parser as parser_module
    from apps.cwe_ingestion.parser import CWEParser

    parser = CWEParser()

    # Check security configuration
    assert hasattr(parser, "xxe_protection_enabled")
    assert parser.xxe_protection_enabled is True

    # Check that we're using defusedxml by verifying the import
    assert "defusedxml" in str(parser_module.ET)

    # Test that parser has secure configuration method
    assert hasattr(parser, "_configure_secure_parser")
