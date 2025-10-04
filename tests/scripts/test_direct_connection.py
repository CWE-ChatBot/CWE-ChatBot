#!/usr/bin/env python3
"""Test direct psycopg connection from Cloud Run environment."""
import os
import psycopg

def test_connection():
    """Test database connection with current environment variables."""
    host = os.getenv("DB_HOST", "10.43.0.3")
    port = int(os.getenv("DB_PORT", "5432"))
    dbname = os.getenv("DB_NAME", "cwe")
    user = os.getenv("DB_USER", "app_user")
    password = os.getenv("DB_PASSWORD", "").strip()
    sslmode = os.getenv("DB_SSLMODE", "require")

    print(f"Testing connection...")
    print(f"  host={host}:{port}")
    print(f"  dbname={dbname}")
    print(f"  user={user}")
    print(f"  sslmode={sslmode}")
    print(f"  password_len={len(password)}")
    print(f"  password_tail={repr(password[-2:]) if len(password) >= 2 else 'N/A'}")

    try:
        conn = psycopg.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password,
            sslmode=sslmode,
            connect_timeout=10,
        )
        print("\n✅ CONNECTION SUCCESSFUL!")

        cur = conn.cursor()
        cur.execute("SELECT current_user, inet_client_addr(), inet_server_addr(), version()")
        row = cur.fetchone()
        print(f"\n  current_user: {row[0]}")
        print(f"  client_addr: {row[1]}")
        print(f"  server_addr: {row[2]}")
        print(f"  version: {row[3][:60]}...")

        conn.close()
        return True

    except Exception as e:
        print(f"\n❌ CONNECTION FAILED!")
        print(f"  Error type: {type(e).__name__}")
        print(f"  Error message: {e}")
        return False

if __name__ == "__main__":
    success = test_connection()
    exit(0 if success else 1)
