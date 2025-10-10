import os
import sys
from typing import Dict, List

import psycopg
import pytest
from dotenv import load_dotenv

# Add the apps path to the python path
apps_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, apps_path)

load_dotenv(dotenv_path=os.path.expanduser("~/work/env/.env_cwe_chatbot"))
print(f"GEMINI_API_KEY: {os.getenv('GEMINI_API_KEY')}")

from src.conversation import ConversationManager

# Database connection details (from run_local_full.sh)
DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
DB_NAME = os.getenv("POSTGRES_DATABASE", "cwe")
DB_USER = os.getenv("POSTGRES_USER", "postgres")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")

DB_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Input samples from the user
INPUT_SAMPLES = [
    "NVIDIA Base Command Manager contains a missing authentication vulnerability in the CMDaemon component. A successful exploit of this vulnerability might lead to code execution, denial of service, escalation of privileges, information disclosure, and data tampering.",
    "A vulnerability has been found in PHPGurukul Boat Booking System 1.0 and classified as critical. Affected by this vulnerability is an unknown functionality of the file book-boat.php?bid=1 of the component Book a Boat Page. The manipulation of the argument nopeople leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.",
    "The Advanced Schedule Posts WordPress plugin through 2.1.8 does not sanitise and escape a parameter before outputting it back in the page, leading to a Reflected Cross-Site Scripting which could be used against high privilege users such as admins.",
]


@pytest.fixture(scope="module")
def conversation_manager():
    # This fixture will be slow as it initializes the ConversationManager
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY must be set for integration tests")
    return ConversationManager(DB_URL, api_key)


@pytest.fixture
def mock_chainlit_session(mocker):
    session = {}
    mocker.patch("src.conversation.cl.user_session.get", side_effect=session.get)
    mocker.patch(
        "src.conversation.cl.user_session.set",
        side_effect=lambda k, v: session.update({k: v}),
    )
    mocker.patch("src.conversation.cl.Step", autospec=True)
    mocker.patch("src.conversation.cl.Message", autospec=True)


@pytest.mark.asyncio
async def test_cwe_analyzer_end_to_end(
    conversation_manager: ConversationManager, _mock_chainlit_session
):
    for i, input_text in enumerate(INPUT_SAMPLES):
        print(f"Testing input {i+1}/{len(INPUT_SAMPLES)}")

        # Set persona to CWE Analyzer
        await conversation_manager.update_user_persona("test_session", "CWE Analyzer")

        # Process the message
        response = await conversation_manager.process_user_message_streaming(
            session_id="test_session",
            message_content=input_text,
            message_id="test_message",
        )

        # Print actual response for debugging
        print(f"\n=== ACTUAL RESPONSE FOR INPUT {i+1} ===")
        print(response["response"])
        print("=== END RESPONSE ===\n")

        # Extract the table from the response
        table_str = extract_table_from_response(response["response"])
        assert table_str, f"No table found in response for input {i+1}"

        # Parse the table
        parsed_table = parse_cwe_table(table_str)
        assert parsed_table, f"Failed to parse table for input {i+1}"

        # Get the correct data from the database for validation
        cwe_ids = [row["cwe_id"] for row in parsed_table]
        db_policies = get_policies_from_db(cwe_ids)
        db_catalog_data = get_catalog_data_from_db(cwe_ids)

        # Compare the parsed table with the database values
        for row in parsed_table:
            cwe_id = row["cwe_id"]

            # Validate policy
            assert (
                cwe_id in db_policies
            ), f"CWE ID {cwe_id} not found in policy database"
            assert (
                row["policy"] == db_policies[cwe_id]
            ), f"Incorrect policy for {cwe_id} in input {i+1}. Expected {db_policies[cwe_id]}, got {row['policy']}"

            # Validate name and abstraction level
            assert (
                cwe_id in db_catalog_data
            ), f"CWE ID {cwe_id} not found in catalog database"
            db_name, db_abstraction = db_catalog_data[cwe_id]

            if row.get("name"):
                assert (
                    row["name"] == db_name
                ), f"Incorrect name for {cwe_id} in input {i+1}. Expected '{db_name}', got '{row['name']}'"

            if row.get("abstraction"):
                assert (
                    row["abstraction"] == db_abstraction
                ), f"Incorrect abstraction for {cwe_id} in input {i+1}. Expected '{db_abstraction}', got '{row['abstraction']}'"


def extract_table_from_response(response: str) -> str:
    # Extract markdown table starting with CWE ID header
    lines = response.split("\n")
    table_lines = []
    in_table = False

    for line in lines:
        # Look for table header with CWE ID
        if "| CWE ID |" in line or "|CWE ID|" in line:
            in_table = True
            table_lines.append(line)
        elif in_table and line.strip().startswith("|") and "|" in line.strip()[1:]:
            table_lines.append(line)
        elif in_table and not line.strip().startswith("|"):
            # End of table
            break

    return "\n".join(table_lines) if table_lines else ""


def parse_cwe_table(table_str: str) -> List[Dict[str, str]]:
    rows = []
    lines = table_str.strip().split("\n")
    if len(lines) < 3:
        return rows

    header = [h.strip() for h in lines[0].split("|") if h.strip()]
    print(f"Table header columns: {header}")  # Debug output

    for line in lines[2:]:
        cols = [c.strip() for c in line.split("|") if c.strip()]
        if (
            len(cols) >= 5
        ):  # Must have at least CWE ID, Name, Confidence, Abstraction, Policy
            row_data = dict(zip(header, cols))
            print(f"Row data: {row_data}")  # Debug output

            # The policy is in the "CWE-Vulnerability Mapping Notes" column
            policy_col = None
            for col_name in header:
                if "Mapping" in col_name and "Notes" in col_name:
                    policy_col = col_name
                    break

            rows.append(
                {
                    "cwe_id": row_data.get("CWE ID"),
                    "name": row_data.get("Name"),
                    "abstraction": row_data.get("Abstraction"),
                    "policy": row_data.get(policy_col) if policy_col else None,
                }
            )
    return rows


def get_policies_from_db(cwe_ids: List[str]) -> Dict[str, str]:
    policies = {}
    if not cwe_ids:
        return policies

    conn = psycopg.connect(DB_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT cwe_id, mapping_label FROM cwe_policy_labels WHERE cwe_id IN %s",
                (cwe_ids,),
            )
            for row in cur.fetchall():
                policies[row[0]] = row[1]
    finally:
        conn.close()

    return policies


def get_catalog_data_from_db(cwe_ids: List[str]) -> Dict[str, tuple]:
    catalog_data = {}
    if not cwe_ids:
        return catalog_data

    conn = psycopg.connect(DB_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT cwe_id, name, abstraction FROM cwe_catalog WHERE cwe_id IN %s",
                (cwe_ids,),
            )
            for row in cur.fetchall():
                catalog_data[row[0]] = (row[1], row[2])  # (name, abstraction)
    finally:
        conn.close()

    return catalog_data
