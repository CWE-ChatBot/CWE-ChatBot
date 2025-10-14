#!/usr/bin/env python3
"""
Text post-processing utilities for chatbot responses.
"""

import re
from typing import Dict, Match


def harmonize_cwe_names_in_table(
    content: str, id_to_name: Dict[str, str], id_to_policy: Dict[str, str]
) -> str:
    """
    Replace CWE Name and Policy cells in Markdown tables with canonical values from DB.
    """
    if not content or (not id_to_name and not id_to_policy):
        return content
    try:
        # Pass 1: Markdown table rows starting with '|' columns
        lines = content.splitlines()
        out = []
        for line in lines:
            if not line.strip().startswith("|"):
                out.append(line)
                continue

            cols = [c.strip() for c in line.strip().split("|")]

            cwe_id_str = cols[1]
            m = re.match(r"CWE[-_\s]?(\d{1,5})", cwe_id_str, re.IGNORECASE)
            if not m:
                out.append(line)
                continue

            full_id = f"CWE-{m.group(1)}".upper()

            # Harmonize name
            if id_to_name and full_id in id_to_name and len(cols) > 2:
                cols[2] = id_to_name[full_id]

            # Harmonize policy
            if id_to_policy and full_id in id_to_policy and len(cols) > 6:
                cols[6] = id_to_policy[full_id]

            out.append(" | ".join(cols))

        content1 = "\n".join(out)

        # Pass 2: Generic cell pattern: CWE-XXXX then a separator (| or tab) then name
        def repl(m: Match[str]) -> str:
            full_id = m.group(1).upper().replace(" ", "").replace("_", "-")
            if not full_id.startswith("CWE-"):
                full_id = "CWE-" + m.group(2)
            canonical = id_to_name.get(full_id.upper())
            if not canonical:
                return m.group(0)
            # Replace the entire cell (ID + separator + name) with canonical name,
            # do not re-append the old name.
            return f"{full_id}{m.group(3)} {canonical}"

        generic_re = re.compile(
            r"\b(CWE[-_\s]?(\d{1,5}))([\s\|\t]+)([^|\t\r\n]+)", re.IGNORECASE
        )
        content2: str = generic_re.sub(repl, content1)
        return content2
    except Exception:
        return content
