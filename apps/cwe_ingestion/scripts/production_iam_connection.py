#!/usr/bin/env python3
"""
PRODUCTION-READY IAM Connection for Cloud SQL PostgreSQL
Uses the corrected approach from Google Cloud documentation (Sept 2025)
"""

import subprocess
import psycopg
import time
import os
import signal
from pathlib import Path

class ProductionIAMConnection:
    def __init__(self):
        self.proxy_process = None
        self.connection = None
        
    def start_proxy(self, port=5434):
        """Start Cloud SQL Proxy v2."""
        # Kill existing proxies
        subprocess.run(['pkill', '-f', 'cloud-sql-proxy'], check=False, capture_output=True)
        time.sleep(2)
        
        # Start new proxy
        proxy_cmd = [
            './cloud-sql-proxy-v2',
            'cwechatbot:us-central1:cwe-postgres-prod',
            '--port', str(port)
        ]
        
        self.proxy_process = subprocess.Popen(
            proxy_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for proxy to start
        time.sleep(8)
        return port
        
    def get_iam_token(self):
        """Get IAM login token using correct command."""
        result = subprocess.run(
            ['gcloud', 'sql', 'generate-login-token'],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
        
    def connect(self, port=5434):
        """Connect to production database with IAM authentication."""
        try:
            # Get fresh token
            token = self.get_iam_token()
            
            # Connect with correct username format
            self.connection = psycopg.connect(
                host='127.0.0.1',
                port=port,
                dbname='postgres',
                user='cwe-postgres-sa@cwechatbot.iam',  # Correct format
                password=token,  # IAM token as password
                connect_timeout=20
            )
            
            return self.connection
            
        except Exception as e:
            raise Exception(f"IAM connection failed: {e}")
    
    def test_connection(self):
        """Test the complete IAM authentication flow."""
        try:
            print("🔧 Testing Production IAM Authentication")
            print("=" * 50)
            
            # Start proxy
            print("Starting Cloud SQL Proxy v2...")
            port = self.start_proxy()
            print(f"✓ Proxy started on port {port}")
            
            # Connect
            print("Connecting with IAM authentication...")
            conn = self.connect(port)
            print("✅ IAM connection successful!")
            
            # Test operations
            with conn.cursor() as cur:
                cur.execute('SELECT current_user, version(), current_database();')
                user, version, db = cur.fetchone()
                print(f"✅ User: {user}")
                print(f"✅ Database: {db}")
                print(f"✅ Version: {version[:60]}...")
            
            conn.close()
            print("\n🎉 PRODUCTION IAM AUTHENTICATION: WORKING!")
            return True
            
        except Exception as e:
            print(f"❌ Test failed: {e}")
            return False
            
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Clean up proxy process."""
        if self.proxy_process:
            try:
                self.proxy_process.terminate()
                self.proxy_process.wait(timeout=5)
            except:
                self.proxy_process.kill()

if __name__ == "__main__":
    # Set up service account authentication
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = '/tmp/cwe-postgres-sa-key.json'
    
    # Activate service account
    subprocess.run([
        'gcloud', 'auth', 'activate-service-account', 
        '--key-file=/tmp/cwe-postgres-sa-key.json'
    ], check=True, capture_output=True)
    
    # Test the connection
    iam_conn = ProductionIAMConnection()
    success = iam_conn.test_connection()
    
    if success:
        print("\n✅ Ready for production deployment!")
    else:
        print("\n❌ IAM authentication needs more work")
