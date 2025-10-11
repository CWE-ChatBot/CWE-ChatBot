#!/usr/bin/env python3
"""Quick script to check if CWE-82 exists in production database."""
import subprocess
import time

import psycopg


def check_cwe82():
    """Check for CWE-82 in production database."""
    proxy_process = None

    try:
        # Start Cloud SQL Proxy
        print("Starting Cloud SQL Proxy...")
        subprocess.run(
            ["pkill", "-f", "cloud-sql-proxy"], check=False, capture_output=True
        )
        time.sleep(2)

        proxy_cmd = [
            "./cloud-sql-proxy-v2",
            "cwechatbot:us-central1:cwe-postgres-prod",
            "--port",
            "5434",
        ]

        proxy_process = subprocess.Popen(
            proxy_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        print("Waiting for proxy to start...")
        time.sleep(8)

        # Get IAM token
        print("Getting IAM token...")
        result = subprocess.run(
            ["gcloud", "sql", "generate-login-token"],
            capture_output=True,
            text=True,
            check=True,
        )
        token = result.stdout.strip()

        # Connect to database
        print("Connecting to database...")
        conn = psycopg.connect(
            host="127.0.0.1",
            port=5434,
            dbname="cwe",  # Use cwe database, not postgres
            user="cwe-postgres-sa@cwechatbot.iam",
            password=token,
            connect_timeout=20,
        )

        with conn.cursor() as cur:
            # Check for CWE-82
            print("\n" + "=" * 60)
            print("CHECKING FOR CWE-82")
            print("=" * 60)

            cur.execute(
                """
                SELECT COUNT(*) as chunk_count
                FROM cwe_chunks
                WHERE UPPER(cwe_id) = 'CWE-82'
            """
            )
            count = cur.fetchone()[0]
            print(f"\n✓ Total chunks for CWE-82: {count}")

            if count > 0:
                print("\n✅ CWE-82 EXISTS in database!")
                print("\nSample chunks:")
                cur.execute(
                    """
                    SELECT cwe_id, section, name, LEFT(full_text, 100) as preview
                    FROM cwe_chunks
                    WHERE UPPER(cwe_id) = 'CWE-82'
                    ORDER BY section_rank
                    LIMIT 5
                """
                )
                for cwe_id, section, name, preview in cur.fetchall():
                    print(f"\n  {cwe_id} - {section}")
                    print(f"  Name: {name}")
                    print(f"  Text: {preview}...")
            else:
                print("\n❌ CWE-82 NOT FOUND in database!")
                print("\nChecking similar CWEs:")
                cur.execute(
                    """
                    SELECT DISTINCT cwe_id
                    FROM cwe_chunks
                    WHERE cwe_id SIMILAR TO 'CWE-8[0-9]'
                    ORDER BY cwe_id
                """
                )
                similar = [row[0] for row in cur.fetchall()]
                print(f"  Found: {', '.join(similar)}")

                print("\nTotal CWEs in database:")
                cur.execute("SELECT COUNT(DISTINCT cwe_id) FROM cwe_chunks")
                total = cur.fetchone()[0]
                print(f"  {total} distinct CWEs")

        conn.close()
        print("\n" + "=" * 60)

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback

        traceback.print_exc()

    finally:
        if proxy_process:
            print("\nCleaning up proxy...")
            proxy_process.terminate()
            try:
                proxy_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy_process.kill()


if __name__ == "__main__":
    check_cwe82()
