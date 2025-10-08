#!/usr/bin/env python3
"""
Test production database connection with proper IAM authentication.
This demonstrates the working approach for production deployment.
"""

import os
import subprocess
import time

import psycopg


def get_access_token():
    """Get access token for service account."""
    try:
        result = subprocess.run(
            ["gcloud", "auth", "print-access-token"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Failed to get access token: {e}")
        return None


def start_cloud_sql_proxy():
    """Start Cloud SQL Auth Proxy in background."""
    try:
        # Kill existing proxy
        subprocess.run(
            ["pkill", "-f", "cloud_sql_proxy"], capture_output=True, check=False
        )
        time.sleep(2)

        # Start new proxy
        proxy_process = subprocess.Popen(
            [
                "./cloud_sql_proxy",
                "-instances=cwechatbot:us-central1:cwe-postgres-prod=tcp:5433",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for proxy to start
        time.sleep(5)
        return proxy_process
    except Exception as e:
        print(f"Failed to start proxy: {e}")
        return None


def test_production_connection():
    """Test production database connection with IAM authentication."""
    print("🔧 Testing Production Database IAM Authentication")
    print("=" * 60)

    # Set up service account
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "/tmp/cwe-postgres-sa-key.json"

    # Start Cloud SQL Auth Proxy
    print("Starting Cloud SQL Auth Proxy...")
    proxy = start_cloud_sql_proxy()
    if not proxy:
        print("❌ Failed to start proxy")
        return False

    try:
        # Get access token
        access_token = get_access_token()
        if not access_token:
            print("❌ Failed to get access token")
            return False

        print(f"✓ Got access token: {access_token[:20]}...")

        # Test connection with access token
        connection_params = {
            "host": "127.0.0.1",
            "port": 5433,
            "dbname": "postgres",
            "user": "cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com",
            "password": access_token,
        }

        print("Testing database connection...")
        conn = psycopg.connect(**connection_params)

        print("✅ PRODUCTION DATABASE CONNECTION SUCCESSFUL!")

        # Test basic operations
        with conn.cursor() as cur:
            cur.execute("SELECT version();")
            version = cur.fetchone()[0]
            print(f"✓ PostgreSQL version: {version[:60]}...")

            cur.execute("SELECT current_user;")
            user = cur.fetchone()[0]
            print(f"✓ Connected as: {user}")

        conn.close()
        return True

    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

    finally:
        # Clean up proxy
        if proxy:
            proxy.terminate()


if __name__ == "__main__":
    success = test_production_connection()
    if success:
        print("\n🎉 PRODUCTION IAM AUTHENTICATION: RESOLVED!")
    else:
        print("\n❌ PRODUCTION IAM AUTHENTICATION: STILL NEEDS WORK")
