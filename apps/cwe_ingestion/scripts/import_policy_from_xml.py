#!/usr/bin/env python3
"""
Standalone importer to populate CWE policy labels from the original CWE XML.

Why a standalone script?
- Safe to trial without touching the ingestion pipeline.
- Lets you validate the policy mapping strategy before integrating.

Policy data target table (created if missing):
    CREATE TABLE IF NOT EXISTS cwe_policy_labels (
      cwe_id TEXT PRIMARY KEY,
      mapping_label TEXT NOT NULL,   -- Allowed | Allowed-with-Review | Discouraged
      notes TEXT
    );

Allowed values for mapping_label (canonical, from CWE XSD UsageEnumeration):
- Allowed (this CWE ID may be used to map to real-world vulnerabilities)
- Allowed-with-Review
- Discouraged (this CWE ID should not be used to map to real-world vulnerabilities)
- Prohibited (this CWE ID must not be used to map to real-world vulnerabilities)

Default derivation (heuristic, used only if explicit Mapping_Notes/Usage is absent):
- Abstraction == 'Class'   -> Discouraged
- Abstraction == 'Base'    -> Allowed
- Abstraction == 'Variant' -> Allowed-with-Review

This is a pragmatic initial mapping based on CWE abstraction levels. If your XML
contains explicit guidance for mapping policies under Mapping_Notes or elsewhere,
you can adjust the heuristics here or extract that field directly once identified.


Usage: VERIFY_KNOWN=1 poetry run python ../cwe_ingestion/scripts/import_policy_from_xml.py --url https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
"""

import argparse
import logging
import os
from typing import Optional

import psycopg
import requests
import tempfile
import zipfile
from pathlib import Path
from io import BytesIO

try:
    # Use local module imports
    from apps.cwe_ingestion.parser import CWEParser
except Exception:
    # Fallback if executed from apps/cwe_ingestion
    from parser import CWEParser  # type: ignore

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


VALID_LABELS = {
    'Allowed',
    'Allowed-with-Review',
    'Discouraged',
    'Prohibited',
}

# Built-in verification set (can be extended)
KNOWN_EXPECTED = {
    'CWE-20': 'Discouraged',
    'CWE-79': 'Allowed',
    'CWE-1061': 'Allowed-with-Review',
    'CWE-1062': 'Prohibited',
}


def derive_policy_label(abstraction: Optional[str]) -> Optional[str]:
    if not abstraction:
        return None
    a = abstraction.strip().lower()
    if a == 'class':
        return 'Discouraged'
    if a == 'base':
        return 'Allowed'
    if a == 'variant':
        return 'Allowed-with-Review'
    return None


def ensure_table(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cwe_policy_labels (
              cwe_id TEXT PRIMARY KEY,
              mapping_label TEXT NOT NULL,
              notes TEXT
            );
            """
        )
        # Canonical catalog table for chatbot (used when single-row embeddings are not present)
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cwe_catalog (
              cwe_id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              abstraction TEXT,
              status TEXT
            );
            """
        )
    conn.commit()


def upsert_policy(conn: psycopg.Connection, cwe_id: str, label: str, notes: str = "") -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cwe_policy_labels (cwe_id, mapping_label, notes)
            VALUES (%s, %s, %s)
            ON CONFLICT (cwe_id) DO UPDATE SET
              mapping_label = EXCLUDED.mapping_label,
              notes = EXCLUDED.notes;
            """,
            (cwe_id, label, notes),
        )


def upsert_catalog(conn: psycopg.Connection, cwe_id: str, name: str, abstraction: Optional[str], status: Optional[str]) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cwe_catalog (cwe_id, name, abstraction, status)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (cwe_id) DO UPDATE SET
              name = EXCLUDED.name,
              abstraction = EXCLUDED.abstraction,
              status = EXCLUDED.status;
            """,
            (cwe_id, name, abstraction or '', status or ''),
        )


def load_env_file(path: str) -> None:
    try:
        p = Path(os.path.expanduser(path))
        if not p.exists():
            return
        for line in p.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, val = line.split('=', 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    except Exception as e:
        logger.warning(f"Failed to load env file {path}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Import CWE policy labels from CWE XML")
    parser.add_argument("--xml", help="Path to CWE XML file (e.g., cwec_v4.15.xml)")
    parser.add_argument("--url", help="Remote URL to CWE XML or ZIP (e.g., https://.../cwec_latest.xml.zip)")
    parser.add_argument("--db", default=None, help="Database URL (default from env)")
    parser.add_argument("--infer-by-abstraction", action="store_true", help="Derive mapping labels from Abstraction field")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of CWEs to import (for testing)")
    parser.add_argument("--dry-run", action="store_true", help="Parse and derive labels without writing to DB")

    parser.add_argument("--env-file", default=os.path.expanduser("~/work/env/.env_cwe_chatbot"), help="Path to env file with DB vars (default: ~/work/env/.env_cwe_chatbot)")

    args = parser.parse_args()

    # Load env file before resolving DB URL
    if args.env_file:
        load_env_file(args.env_file)

    if not args.xml and not args.url:
        parser.error("Either --xml (local file) or --url (remote) must be provided")
    # Resolve DB URL similar to run_local_full.sh if not provided
    db_url = args.db or os.getenv("DATABASE_URL") or os.getenv("LOCAL_DATABASE_URL")
    if not db_url:
        host = os.getenv("POSTGRES_HOST")
        port = os.getenv("POSTGRES_PORT")
        dbname = os.getenv("POSTGRES_DATABASE")
        user = os.getenv("POSTGRES_USER")
        password = os.getenv("POSTGRES_PASSWORD")
        if all([host, port, dbname, user, password]):
            db_url = f"postgresql://{user}:{password}@{host}:{port}/{dbname}"
    if not db_url and not args.dry_run:
        parser.error("Database URL not found. Provide --db or set DATABASE_URL/LOCAL_DATABASE_URL or POSTGRES_* env vars.")

    # Resolve XML path: download if URL provided
    xml_path = args.xml
    tmp_dir = None
    if args.url:
        logger.info(f"Downloading CWE corpus from: {args.url}")
        resp = requests.get(args.url, stream=True, timeout=60)
        resp.raise_for_status()
        content = resp.content
        tmp_dir = tempfile.TemporaryDirectory()
        tdir = Path(tmp_dir.name)
        # If ZIP, extract first XML
        if args.url.lower().endswith('.zip') or zipfile.is_zipfile(BytesIO(content)):
            with zipfile.ZipFile(BytesIO(content)) as zf:
                xml_members = [m for m in zf.namelist() if m.lower().endswith('.xml')]
                if not xml_members:
                    raise RuntimeError("ZIP did not contain any .xml file")
                # Prefer filenames containing 'cwe'
                xml_members.sort(key=lambda m: (0 if 'cwe' in m.lower() else 1, len(m)))
                target = xml_members[0]
                out_path = tdir / Path(target).name
                with zf.open(target) as src, open(out_path, 'wb') as dst:
                    dst.write(src.read())
                xml_path = str(out_path)
        else:
            out_path = tdir / 'cwe.xml'
            with open(out_path, 'wb') as f:
                f.write(content)
            xml_path = str(out_path)

    logger.info(f"Parsing XML: {xml_path}")
    entries = CWEParser().parse_file(xml_path)
    if args.limit:
        entries = entries[: args.limit]
    logger.info(f"Parsed {len(entries)} CWE entries")

    rows = []
    catalog_rows = []
    for e in entries:
        cwe_id = f"CWE-{getattr(e, 'ID', '')}".strip()
        if not cwe_id or cwe_id == 'CWE-':
            continue
        label: Optional[str] = None
        note = ""
        # Always collect catalog data
        name = getattr(e, 'Name', '') or ''
        abstraction = getattr(e, 'Abstraction', None)
        status = getattr(e, 'Status', None)
        catalog_rows.append((cwe_id, name, abstraction, status))

        # Strategy 1: explicit Usage from Mapping_Notes (preferred)
        usage = None
        try:
            mn = getattr(e, 'MappingNotes', None)
            if mn is not None:
                # Pydantic model MappingNote has attribute Usage
                usage = getattr(mn, 'Usage', None)
                if usage is None and isinstance(mn, dict):
                    usage = mn.get('Usage')
            if usage:
                usage = str(usage).strip()
        except Exception:
            usage = None
        if usage:
            # Normalize to canonical value per XSD
            u = usage.strip().lower().replace('_', '-').replace(' ', '-')
            if u == 'allowed':
                label = 'Allowed'
            elif u in ('allowed-with-review', 'allowed-(with-careful-review)', 'allowed-with-careful-review'):
                label = 'Allowed-with-Review'
            elif u == 'discouraged':
                label = 'Discouraged'
            elif u == 'prohibited':
                label = 'Prohibited'
            else:
                logger.warning(f"Unrecognized Usage value for {cwe_id}: '{usage}'")
            if label:
                note = f"source=UsageEnumeration;raw='{usage}'"

        # Strategy 2: derive from abstraction when enabled
        if args.infer_by_abstraction:
            if not label:
                label = derive_policy_label(getattr(e, 'Abstraction', None))
                if label:
                    note = f"derived_from_abstraction={getattr(e, 'Abstraction', '')}"

        # Strategy 3: extend here if additional XML fields define explicit policy

        if not label:
            continue  # skip rows without a derived label
        rows.append((cwe_id, label, note))

    logger.info(f"Prepared {len(rows)} policy rows; {len(catalog_rows)} catalog rows")

    # Optional verification against known expected labels using prepared rows
    def _verify_prepared(prepared_rows):
        if not prepared_rows:
            logger.info("Verification (prepared rows): no rows to check")
            return
        prepared_map = {cid.upper(): lab for cid, lab, _ in prepared_rows}
        for cid, expected in KNOWN_EXPECTED.items():
            got = prepared_map.get(cid)
            if got is None:
                logger.info(f"VERIFY (prepared): {cid} not in prepared set (possibly due to --limit or missing Usage)")
            elif got == expected:
                logger.info(f"VERIFY (prepared): {cid} PASS -> {got}")
            else:
                logger.warning(f"VERIFY (prepared): {cid} FAIL -> got '{got}', expected '{expected}'")

    if os.getenv('VERIFY_KNOWN') == '1':
        _verify_prepared(rows)

    if args.dry_run:
        for i, (cid, lab, nt) in enumerate(rows[:10]):
            logger.info(f"DRY-RUN sample {i+1}: {cid} -> {lab} ({nt})")
        logger.info("Dry run complete; no database writes performed.")
        if tmp_dir:
            tmp_dir.cleanup()
        return

    assert db_url, "Database URL is required for writes"
    logger.info(f"Connecting to DB: {db_url[:48]}...")
    conn = psycopg.connect(db_url)
    try:
        ensure_table(conn)
        with conn.transaction():
            # Upsert catalog for all parsed entries
            for cid, nm, absn, st in catalog_rows:
                upsert_catalog(conn, cid, nm, absn, st)
            # Upsert only policy rows with labels
            for cid, lab, nt in rows:
                upsert_policy(conn, cid, lab, nt)
        conn.commit()
        logger.info(f"Imported {len(rows)} policy labels into cwe_policy_labels")

        # DB verification against known expected labels
        try:
            with conn.cursor() as cur:
                ids = list(KNOWN_EXPECTED.keys())
                ids_upper = [i.upper() for i in ids]
                # Use ANY(%s) with an array parameter to avoid dynamic SQL
                cur.execute(
                    "SELECT cwe_id, mapping_label FROM cwe_policy_labels WHERE UPPER(cwe_id) = ANY(%s)",
                    (ids_upper,),
                )
                db_map = {row[0].upper(): row[1] for row in cur.fetchall()}
                for cid, expected in KNOWN_EXPECTED.items():
                    got = db_map.get(cid)
                    if got == expected:
                        logger.info(f"VERIFY (db): {cid} PASS -> {got}")
                    else:
                        logger.warning(f"VERIFY (db): {cid} FAIL -> got '{got}', expected '{expected}'")
        except Exception as e:
            logger.warning(f"DB verification failed: {e}")
    finally:
        conn.close()
        if tmp_dir:
            tmp_dir.cleanup()


if __name__ == "__main__":
    main()
