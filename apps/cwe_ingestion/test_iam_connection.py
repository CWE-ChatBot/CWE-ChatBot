#!/usr/bin/env python3
"""
Simple IAM connection test for debugging proxy issues.
Run this after starting the proxy with verbose logging.
"""

import subprocess
import psycopg
import time
import sys

def test_iam_connection():
    print("🔍 Simple IAM Connection Test")
    print("=" * 40)

    try:
        # Generate IAM token
        print("1. Generating IAM token...")
        result = subprocess.run(
            ['gcloud', 'sql', 'generate-login-token'],
            capture_output=True, text=True, check=True
        )
        token = result.stdout.strip()
        print(f"   ✓ Token generated (length: {len(token)})")

        # Test connection
        print("2. Testing connection...")
        print("   Host: 127.0.0.1:5433")
        print("   User: cwe-postgres-sa@cwechatbot.iam")
        print("   Database: postgres")

        conn = psycopg.connect(
            host='127.0.0.1',
            port=5433,
            dbname='postgres',
            user='cwe-postgres-sa@cwechatbot.iam',
            password=token,
            connect_timeout=15
        )

        print("   ✅ Connection successful!")

        # Test query
        with conn.cursor() as cur:
            cur.execute('SELECT current_user, current_database();')
            user, db = cur.fetchone()
            print(f"   ✓ Connected as: {user}")
            print(f"   ✓ Database: {db}")

        conn.close()
        print("\n🎉 IAM authentication working!")
        return True

    except subprocess.CalledProcessError as e:
        print(f"   ❌ Token generation failed: {e}")
        return False

    except psycopg.OperationalError as e:
        print(f"   ❌ Database connection failed: {e}")

        # Analyze error
        error_str = str(e).lower()
        if 'password authentication failed' in error_str:
            print("   🔍 Issue: Database permissions - IAM user needs PostgreSQL grants")
        elif 'no pg_hba.conf entry' in error_str:
            print("   🔍 Issue: pg_hba.conf - IAM auth not configured in PostgreSQL")
        elif 'server closed the connection' in error_str:
            print("   🔍 Issue: Connection rejected - check proxy logs for details")
        elif 'connection refused' in error_str:
            print("   🔍 Issue: Proxy not running or wrong port")
        else:
            print(f"   🔍 Issue: Unknown - {error_str}")

        return False

    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    success = test_iam_connection()
    sys.exit(0 if success else 1)