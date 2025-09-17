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
    assert hasattr(parser, 'xxe_protection_enabled')
    assert parser.xxe_protection_enabled is True
    assert hasattr(parser, '_configure_secure_parser')

def test_parser_extracts_required_fields():
    """Test that parser extracts specific CWE fields: ID, Name, Abstraction, Status, Description, ExtendedDescription, AlternateTerms, ObservedExamples, RelatedWeaknesses."""
    from apps.cwe_ingestion.parser import CWEParser

    # Sample comprehensive CWE XML for testing all fields
    sample_xml = '''<?xml version="1.0" encoding="UTF-8"?>
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
    </Weakness_Catalog>'''

    parser = CWEParser()

    # Test with sample data
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(sample_xml)
        temp_file = f.name

    try:
        result = parser.parse_file(temp_file, target_cwes=['CWE-79'])

        assert len(result) == 1
        cwe = result[0]

        # Test all required fields are extracted
        assert cwe['id'] == '79'
        assert cwe['name'] == 'Cross-site Scripting'
        assert cwe['abstraction'] == 'Base'
        assert cwe['status'] == 'Stable'
        assert 'The software does not neutralize user input' in cwe['description']
        assert 'Cross-site scripting attacks can lead' in cwe['extended_description']

        # Test alternate terms
        assert len(cwe['alternate_terms']) == 1
        assert cwe['alternate_terms'][0]['term'] == 'XSS'
        assert 'Common abbreviation' in cwe['alternate_terms'][0]['description']

        # Test observed examples
        assert len(cwe['observed_examples']) == 1
        assert cwe['observed_examples'][0]['reference'] == 'CVE-2002-0738'
        assert 'XSS in web application' in cwe['observed_examples'][0]['description']

        # Test related weaknesses
        assert len(cwe['related_weaknesses']) == 1
        assert cwe['related_weaknesses'][0]['nature'] == 'ChildOf'
        assert cwe['related_weaknesses'][0]['cwe_id'] == '20'
        assert cwe['related_weaknesses'][0]['view_id'] == '1000'

        # Test full_text contains all information
        assert 'CWE-79: Cross-site Scripting' in cwe['full_text']
        assert 'Type: Base' in cwe['full_text']
        assert 'Status: Stable' in cwe['full_text']
        assert 'Alternative Terms:' in cwe['full_text']
        assert 'Real-World Examples:' in cwe['full_text']
        assert 'Related Weaknesses:' in cwe['full_text']
    finally:
        Path(temp_file).unlink()

def test_parser_filters_target_cwes():
    """Test that parser only extracts specified CWE IDs."""
    from apps.cwe_ingestion.parser import CWEParser

    # Sample XML with multiple CWEs
    sample_xml = '''<?xml version="1.0" encoding="UTF-8"?>
    <Weakness_Catalog>
        <Weaknesses>
            <Weakness ID="79" Name="Cross-site Scripting">
                <Description><Description_Summary>XSS desc</Description_Summary></Description>
            </Weakness>
            <Weakness ID="89" Name="SQL Injection">
                <Description><Description_Summary>SQL desc</Description_Summary></Description>
            </Weakness>
        </Weaknesses>
    </Weakness_Catalog>'''

    parser = CWEParser()

    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(sample_xml)
        temp_file = f.name

    try:
        # Request only CWE-79
        result = parser.parse_file(temp_file, target_cwes=['CWE-79'])

        assert len(result) == 1
        assert result[0]['id'] == '79'
        assert result[0]['name'] == 'Cross-site Scripting'
    finally:
        Path(temp_file).unlink()

def test_parser_handles_missing_fields_gracefully():
    """Test parser handles XML with missing optional fields."""
    from apps.cwe_ingestion.parser import CWEParser

    # Minimal XML with only required fields
    sample_xml = '''<?xml version="1.0" encoding="UTF-8"?>
    <Weakness_Catalog>
        <Weaknesses>
            <Weakness ID="79" Name="Cross-site Scripting">
                <Description><Description_Summary>Basic desc</Description_Summary></Description>
            </Weakness>
        </Weaknesses>
    </Weakness_Catalog>'''

    parser = CWEParser()

    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(sample_xml)
        temp_file = f.name

    try:
        result = parser.parse_file(temp_file, target_cwes=['CWE-79'])

        assert len(result) == 1
        cwe = result[0]
        assert cwe['id'] == '79'
        assert cwe['name'] == 'Cross-site Scripting'

        # Optional fields should be empty but present
        assert cwe.get('extended_description', '') == ''
        assert cwe.get('alternate_terms', []) == []
        assert cwe.get('observed_examples', []) == []
        assert cwe.get('related_weaknesses', []) == []
    finally:
        Path(temp_file).unlink()

def test_parser_security_configuration():
    """Test that parser has security configurations enabled."""
    import apps.cwe_ingestion.parser as parser_module
    from apps.cwe_ingestion.parser import CWEParser

    parser = CWEParser()

    # Check security configuration
    assert hasattr(parser, 'xxe_protection_enabled')
    assert parser.xxe_protection_enabled is True

    # Check that we're using defusedxml by verifying the import
    assert 'defusedxml' in str(parser_module.ET)

    # Test that parser has secure configuration method
    assert hasattr(parser, '_configure_secure_parser')
