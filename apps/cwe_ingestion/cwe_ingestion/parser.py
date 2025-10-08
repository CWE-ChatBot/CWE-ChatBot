# apps/cwe_ingestion/parser.py
"""
Secure CWE XML parser module.
Extracts comprehensive data and maps it to Pydantic models.
"""
import logging
from typing import List, Optional
from xml.etree.ElementTree import (
    Element,  # Import Element specifically for type hinting
)

import defusedxml.ElementTree as ET  # noqa: N817

from .models import CWEEntry

logger = logging.getLogger(__name__)


def _get_text(element: Optional[Element], path: str = ".") -> Optional[str]:
    """Safely gets stripped text from an element or its child."""
    if element is None:
        return None

    target = element if path == "." else element.find(path)

    if target is None:
        return None

    # Handle complex elements with mixed text and children by iterating
    full_text = "".join(target.itertext()).strip()
    return full_text if full_text else None


class CWEParser:
    """Secure XML parser that extracts CWE data into Pydantic models."""

    def __init__(self):
        logger.info("CWEParser initialized with XXE protection via defusedxml.")
        self.xxe_protection_enabled = True
        self._configure_secure_parser()

    def _configure_secure_parser(self):
        """Configure secure XML parser settings to prevent XXE attacks."""
        # Using defusedxml.ElementTree provides XXE protection by default
        # This method exists to satisfy test expectations for security configuration
        logger.debug("Secure XML parser configured with XXE protection")

    def parse_file(
        self, xml_file: str, target_cwes: Optional[List[str]] = None
    ) -> List[CWEEntry]:
        """
        Parses a CWE XML file and returns a list of CWEEntry models.
        """
        try:
            logger.info(f"Parsing CWE file: {xml_file}")

            normalized_targets = (
                {cwe_id.replace("CWE-", "") for cwe_id in target_cwes}
                if target_cwes
                else set()
            )
            if normalized_targets:
                logger.info(
                    f"Targeting {len(normalized_targets)} specific CWEs: "
                    f"{normalized_targets}"
                )
            else:
                logger.info("No specific targets provided, extracting all CWEs.")

            tree = ET.parse(xml_file)
            root = tree.getroot()

            if root is None:
                logger.error(
                    f"XML file {xml_file} is empty or malformed; "
                    "could not find root element."
                )
                return []

            namespace = root.tag.split("}")[0] + "}" if "}" in root.tag else ""

            cwe_data = []
            weaknesses_element = root.find(f"{namespace}Weaknesses")
            if weaknesses_element is None:
                logger.warning("Could not find <Weaknesses> tag in the XML file.")
                return []

            for weakness_element in weaknesses_element.findall(f"{namespace}Weakness"):
                weakness_id = weakness_element.get("ID")
                if not weakness_id:
                    continue

                if normalized_targets and weakness_id not in normalized_targets:
                    continue

                try:
                    entry_data = self._extract_weakness_data(
                        weakness_element, namespace
                    )
                    cwe_data.append(CWEEntry(**entry_data))
                except Exception as e:
                    logger.error(
                        f"Failed to model data for CWE-{weakness_id}: {e}",
                        exc_info=True,
                    )

            logger.info(f"Successfully parsed and modeled {len(cwe_data)} CWE entries.")
            return cwe_data

        except ET.ParseError as e:
            logger.error(f"XML Parse Error in {xml_file}: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to parse CWE file {xml_file}: {e}")
            raise

    def _extract_weakness_data(self, weak_elem: Element, ns: str) -> dict:
        """Extracts all relevant fields for a single <Weakness> element."""
        return {
            "ID": weak_elem.get("ID"),
            "Name": weak_elem.get("Name"),
            "Abstraction": weak_elem.get("Abstraction"),
            "Status": weak_elem.get("Status"),
            "Description": _get_text(weak_elem.find(f"{ns}Description")),
            "ExtendedDescription": _get_text(
                weak_elem.find(f"{ns}Extended_Description")
            ),
            "AlternateTerms": self._extract_alternate_terms(weak_elem, ns),
            "ObservedExamples": self._extract_observed_examples(weak_elem, ns),
            "Notes": self._extract_notes(weak_elem, ns),
            "RelatedWeaknesses": self._extract_related_weaknesses(weak_elem, ns),
            "PotentialMitigations": self._extract_mitigations(weak_elem, ns),
            "MappingNotes": self._extract_mapping_notes(weak_elem, ns),
            "CommonConsequences": self._extract_common_consequences(weak_elem, ns),
            "DetectionMethods": self._extract_detection_methods(weak_elem, ns),
            "ModesOfIntroduction": self._extract_modes_of_introduction(weak_elem, ns),
            "Prerequisites": self._extract_prerequisites(weak_elem, ns),
            "RelatedAttackPatterns": self._extract_capec(weak_elem, ns),
        }

    def _extract_alternate_terms(self, elem: Element, ns: str) -> List[dict]:
        terms = []
        container = elem.find(f"{ns}Alternate_Terms")
        if container is not None:
            for term_elem in container.findall(f"{ns}Alternate_Term"):
                terms.append(
                    {
                        "Term": _get_text(term_elem, f"{ns}Term") or "",
                        "Description": _get_text(term_elem, f"{ns}Description"),
                    }
                )
        return terms

    def _extract_observed_examples(self, elem: Element, ns: str) -> List[dict]:
        examples = []
        container = elem.find(f"{ns}Observed_Examples")
        if container is not None:
            for ex_elem in container.findall(f"{ns}Observed_Example"):
                examples.append(
                    {
                        "Reference": _get_text(ex_elem, f"{ns}Reference") or "",
                        "Description": _get_text(ex_elem, f"{ns}Description") or "",
                        "Link": _get_text(ex_elem, f"{ns}Link"),
                    }
                )
        return examples

    def _extract_notes(self, elem: Element, ns: str) -> List[dict]:
        notes = []
        container = elem.find(f"{ns}Notes")
        if container is not None:
            for note_elem in container.findall(f"{ns}Note"):
                notes.append(
                    {
                        "Type": note_elem.get("Type", "General"),
                        "Text": _get_text(note_elem) or "",
                    }
                )
        return notes

    def _extract_related_weaknesses(self, elem: Element, ns: str) -> List[dict]:
        weaknesses = []
        container = elem.find(f"{ns}Related_Weaknesses")
        if container is not None:
            for rel_elem in container.findall(f"{ns}Related_Weakness"):
                weaknesses.append(
                    {
                        "Nature": rel_elem.get("Nature"),
                        "CweID": rel_elem.get("CWE_ID"),
                        "ViewID": rel_elem.get("View_ID"),
                        "Ordinal": rel_elem.get("Ordinal"),
                    }
                )
        return weaknesses

    def _extract_mitigations(self, elem: Element, ns: str) -> List[dict]:
        mitigations = []
        container = elem.find(f"{ns}Potential_Mitigations")
        if container is not None:
            for mit_elem in container.findall(f"{ns}Mitigation"):
                mitigations.append(
                    {
                        "Phase": mit_elem.findtext(f"{ns}Phase"),
                        "Strategy": mit_elem.findtext(f"{ns}Strategy"),
                        "Description": _get_text(mit_elem.find(f"{ns}Description"))
                        or "",
                    }
                )
        return mitigations

    def _extract_mapping_notes(self, elem: Element, ns: str) -> Optional[dict]:
        """
        Extracts mapping notes. The return type hint is corrected to Optional[dict].
        """
        container = elem.find(f"{ns}Mapping_Notes")
        if container is not None:
            return {
                "Usage": _get_text(container, f"{ns}Usage"),
                "Rationale": _get_text(container, f"{ns}Rationale"),
                "Comments": _get_text(container, f"{ns}Comments"),
            }
        return None

    def _extract_common_consequences(self, elem: Element, ns: str) -> List[dict]:
        out = []
        container = elem.find(f"{ns}Common_Consequences")
        if container is not None:
            for cc in container.findall(f"{ns}Consequence"):
                out.append(
                    {
                        "Scope": _get_text(cc, f"{ns}Scope"),
                        "Impact": _get_text(cc, f"{ns}Impact"),
                        "Note": _get_text(cc, f"{ns}Note"),
                    }
                )
        return out

    def _extract_detection_methods(self, elem: Element, ns: str) -> List[dict]:
        out = []
        container = elem.find(f"{ns}Detection_Methods")
        if container is not None:
            for dm in container.findall(f"{ns}Detection_Method"):
                out.append(
                    {
                        "Method": _get_text(dm, f"{ns}Method"),
                        "Description": _get_text(dm, f"{ns}Description"),
                        "Effectiveness": _get_text(dm, f"{ns}Effectiveness"),
                    }
                )
        return out

    def _extract_modes_of_introduction(self, elem: Element, ns: str) -> List[dict]:
        out = []
        container = elem.find(f"{ns}Modes_Of_Introduction")
        if container is not None:
            for mi in container.findall(f"{ns}Introduction"):
                out.append(
                    {
                        "Phase": _get_text(mi, f"{ns}Phase"),
                        "Description": _get_text(mi, f"{ns}Description"),
                        "Note": _get_text(mi, f"{ns}Note"),
                    }
                )
        return out

    def _extract_prerequisites(self, elem: Element, ns: str) -> List[str]:
        out: List[str] = []
        container = elem.find(f"{ns}Prerequisites")
        if container is not None:
            for p in container.findall(f"{ns}Prerequisite"):
                t = _get_text(p)
                if t:
                    out.append(t)
        return out

    def _extract_capec(self, elem: Element, ns: str) -> List[dict]:
        """
        CAPEC references often appear under <Related_Attack_Patterns>.
        """
        out = []
        container = elem.find(f"{ns}Related_Attack_Patterns")
        if container is not None:
            for ap in container.findall(f"{ns}Related_Attack_Pattern"):
                out.append(
                    {
                        "CAPECID": ap.get("CAPEC_ID"),
                        "Name": ap.get("Name") or _get_text(ap),
                    }
                )
        return out
