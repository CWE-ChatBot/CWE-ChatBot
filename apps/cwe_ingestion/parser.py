# apps/cwe_ingestion/parser.py
"""
Secure CWE XML parser module.
Implements secure XML parsing with XXE protection.
"""
import logging
from typing import Dict, List, Optional

import defusedxml.ElementTree as ET

logger = logging.getLogger(__name__)


class CWEParser:
    """Secure XML parser for CWE data with XXE protection."""

    def __init__(self):
        self.xxe_protection_enabled = True
        self._configure_secure_parser()

        logger.info("CWEParser initialized with XXE protection enabled")

    def _configure_secure_parser(self):
        """Configure parser with security protections."""
        # defusedxml is already secure by default
        # Additional security configuration can be added here if needed
        pass

    def parse_file(self, xml_file: str, target_cwes: List[str]) -> List[Dict]:
        """
        Parse CWE XML file and extract specified CWEs.

        Args:
            xml_file: Path to CWE XML file
            target_cwes: List of CWE IDs to extract (e.g., ['CWE-79', 'CWE-89'])

        Returns:
            List of extracted CWE data dictionaries
        """
        try:
            logger.info(f"Parsing CWE file: {xml_file}")
            logger.info(f"Target CWEs: {target_cwes}")

            # Normalize target CWEs (remove CWE- prefix if present)
            normalized_targets = []
            for cwe_id in target_cwes:
                if cwe_id.startswith('CWE-'):
                    normalized_targets.append(cwe_id[4:])  # Remove 'CWE-' prefix
                else:
                    normalized_targets.append(cwe_id)

            # Parse XML using defusedxml for security
            tree = ET.parse(xml_file)
            root = tree.getroot()

            cwe_data = []
            weaknesses_element = root.find('Weaknesses')

            if weaknesses_element is not None:
                for weakness in weaknesses_element.findall('Weakness'):
                    weakness_data = self._extract_weakness_data(weakness)

                    if weakness_data and weakness_data['id'] in normalized_targets:
                        cwe_data.append(weakness_data)

            logger.info(f"Extracted {len(cwe_data)} CWEs from XML")
            return cwe_data

        except Exception as e:
            logger.error(f"Failed to parse CWE file: {e}")
            raise

    def _extract_weakness_data(self, weakness_element) -> Optional[Dict]:
        """Extract specific CWE fields from weakness XML element."""
        try:
            weakness_id = weakness_element.get('ID')
            weakness_name = weakness_element.get('Name', '')
            weakness_abstraction = weakness_element.get('Abstraction', '')
            weakness_status = weakness_element.get('Status', '')

            # Extract description
            description = ""
            desc_element = weakness_element.find('Description')
            if desc_element is not None:
                desc_summary = desc_element.find('Description_Summary')
                if desc_summary is not None and desc_summary.text:
                    description = desc_summary.text.strip()

            # Extract extended description
            extended_description = ""
            extended_desc_element = weakness_element.find('Extended_Description')
            if extended_desc_element is not None and extended_desc_element.text:
                extended_description = extended_desc_element.text.strip()

            # Extract alternate terms
            alternate_terms = []
            alternate_terms_element = weakness_element.find('Alternate_Terms')
            if alternate_terms_element is not None:
                for term in alternate_terms_element.findall('Alternate_Term'):
                    term_data = {
                        'term': term.find('Term').text.strip() if term.find('Term') is not None else '',
                        'description': term.find('Description').text.strip() if term.find('Description') is not None else ''
                    }
                    alternate_terms.append(term_data)

            # Extract observed examples
            observed_examples = []
            observed_examples_element = weakness_element.find('Observed_Examples')
            if observed_examples_element is not None:
                for example in observed_examples_element.findall('Observed_Example'):
                    example_data = {
                        'reference': example.find('Reference').text.strip() if example.find('Reference') is not None else '',
                        'description': example.find('Description').text.strip() if example.find('Description') is not None else ''
                    }
                    observed_examples.append(example_data)

            # Extract related weaknesses
            related_weaknesses = []
            related_weaknesses_element = weakness_element.find('Related_Weaknesses')
            if related_weaknesses_element is not None:
                for related in related_weaknesses_element.findall('Related_Weakness'):
                    relationship = {
                        'nature': related.get('Nature'),
                        'cwe_id': related.get('CWE_ID'),
                        'view_id': related.get('View_ID', '')
                    }
                    related_weaknesses.append(relationship)

            # Build full searchable text using pattern from reference code
            full_text = self._build_searchable_text({
                'id': weakness_id,
                'name': weakness_name,
                'abstraction': weakness_abstraction,
                'status': weakness_status,
                'description': description,
                'extended_description': extended_description,
                'alternate_terms': alternate_terms,
                'observed_examples': observed_examples,
                'related_weaknesses': related_weaknesses
            })

            return {
                'id': weakness_id,
                'name': weakness_name,
                'abstraction': weakness_abstraction,
                'status': weakness_status,
                'description': description,
                'extended_description': extended_description,
                'alternate_terms': alternate_terms,
                'observed_examples': observed_examples,
                'related_weaknesses': related_weaknesses,
                'full_text': full_text
            }

        except Exception as e:
            logger.error(f"Failed to extract weakness data: {e}")
            return None

    def _build_searchable_text(self, cwe_data: Dict) -> str:
        """Build searchable text using pattern from reference CWEEntry.to_searchable_text()."""
        sections = []

        # Core Information
        sections.append(f"CWE-{cwe_data['id']}: {cwe_data['name']}")
        sections.append(f"Type: {cwe_data['abstraction']}")
        sections.append(f"Status: {cwe_data['status']}")

        # Primary Content
        sections.append("Description:")
        sections.append(cwe_data['description'])

        if cwe_data.get('extended_description'):
            sections.append("Extended Details:")
            sections.append(cwe_data['extended_description'])

        # Alternate Terms
        if cwe_data.get('alternate_terms'):
            terms = []
            for term in cwe_data['alternate_terms']:
                if term.get('description'):
                    terms.append(f"{term['term']} - {term['description']}")
                else:
                    terms.append(term['term'])
            if terms:
                sections.append("Alternative Terms:")
                sections.append("\n".join(terms))

        # Observed Examples
        if cwe_data.get('observed_examples'):
            sections.append("Real-World Examples:")
            for example in cwe_data['observed_examples']:
                sections.append(f"- {example['reference']}: {example['description']}")

        # Related Weaknesses
        if cwe_data.get('related_weaknesses'):
            sections.append("Related Weaknesses:")
            for weakness in cwe_data['related_weaknesses']:
                sections.append(f"- CWE-{weakness['cwe_id']} ({weakness['nature']})")

        return "\n\n".join(sections)
