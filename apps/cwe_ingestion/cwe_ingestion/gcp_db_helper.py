#!/usr/bin/env python3
"""
Helper script for creating Google Cloud SQL connection URLs and testing IAM authentication.
"""
import os
import sys

import click


@click.group()
def cli() -> None:
    """Google Cloud SQL helper utilities for CWE ingestion."""
    pass


@cli.command()
@click.option("--project-id", "-p", required=True, help="GCP project ID")
@click.option(
    "--region", "-r", required=True, help="Cloud SQL region (e.g., us-central1)"
)
@click.option("--instance", "-i", required=True, help="Cloud SQL instance name")
@click.option("--database", "-d", default="cwe", help="Database name (default: cwe)")
@click.option("--username", "-u", required=True, help="IAM database username")
def create_url(
    project_id: str, region: str, instance: str, database: str, username: str
) -> None:
    """Create a Google Cloud SQL connection URL for IAM authentication."""
    from multi_db_pipeline import create_google_cloud_sql_url

    url = create_google_cloud_sql_url(
        project_id=project_id,
        region=region,
        instance_name=instance,
        database_name=database,
        username=username,
    )

    click.echo("Google Cloud SQL Connection URL:")
    click.echo(f"  {url}")
    click.echo()
    click.echo("To use this URL, set environment variable:")
    click.echo(f"  export PROD_DATABASE_URL='{url}'")
    click.echo()
    click.echo("Ensure you have IAM authentication configured:")
    click.echo("  gcloud auth application-default login")
    click.echo("  # OR set service account credentials")
    click.echo(
        "  export GOOGLE_APPLICATION_CREDENTIALS='/path/to/service-account.json'"
    )


@cli.command()
@click.option(
    "--database-url",
    help="Database URL to test (uses PROD_DATABASE_URL if not provided)",
)
def test_iam_auth(database_url: str | None) -> bool:
    """Test Google Cloud SQL IAM authentication."""
    if not database_url:
        database_url = os.environ.get("PROD_DATABASE_URL")
        if not database_url:
            click.echo(
                "❌ No database URL provided. Set PROD_DATABASE_URL or use --database-url",
                err=True,
            )
            sys.exit(1)

    click.echo(f"🔍 Testing IAM authentication for: {_mask_url(database_url)}")

    try:
        # Import and test connection
        from pg_vector_store import PostgresVectorStore

        click.echo("📡 Attempting connection...")
        store = PostgresVectorStore(dims=3072, database_url=database_url)

        click.echo("📊 Getting database statistics...")
        stats = store.get_collection_stats()

        click.echo("✅ Google Cloud SQL IAM authentication successful!")
        click.echo(f"📊 Database stats: {stats}")

        # Check if we can detect IAM format
        if "@" in database_url and ":" in database_url.split("@")[1]:
            click.echo("✅ Google Cloud SQL IAM format detected correctly")

        return True

    except Exception as e:
        click.echo(f"❌ IAM authentication failed: {e}")
        click.echo()
        click.echo("💡 Troubleshooting tips:")
        click.echo(
            "  1. Ensure you're authenticated: gcloud auth application-default login"
        )
        click.echo("  2. Check service account has Cloud SQL Client role")
        click.echo(
            "  3. Verify database URL format: postgresql://username@project:region:instance/dbname"
        )
        click.echo("  4. Ensure Cloud SQL instance allows IAM authentication")
        return False


@cli.command()
def check_auth() -> None:
    """Check current Google Cloud authentication status."""
    import subprocess

    click.echo("🔍 Checking Google Cloud authentication...")

    try:
        # Check gcloud auth
        result = subprocess.run(
            [
                "gcloud",
                "auth",
                "list",
                "--filter=status:ACTIVE",
                "--format=value(account)",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        if result.stdout.strip():
            click.echo(f"✅ Active gcloud account: {result.stdout.strip()}")
        else:
            click.echo("⚠️  No active gcloud account found")

    except subprocess.CalledProcessError:
        click.echo("❌ gcloud command failed")
    except FileNotFoundError:
        click.echo("❌ gcloud not found - install Google Cloud SDK")

    # Check service account credentials
    creds_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if creds_path:
        if os.path.exists(creds_path):
            click.echo(f"✅ Service account credentials: {creds_path}")
        else:
            click.echo(f"❌ Service account file not found: {creds_path}")
    else:
        click.echo("ℹ️  No GOOGLE_APPLICATION_CREDENTIALS set (using default auth)")

    # Check for Cloud SQL proxy
    try:
        result = subprocess.run(
            ["cloud_sql_proxy", "--version"], capture_output=True, text=True
        )
        if result.returncode == 0:
            click.echo("✅ Cloud SQL proxy available")
        else:
            click.echo("ℹ️  Cloud SQL proxy not available (not required for IAM)")
    except FileNotFoundError:
        click.echo("ℹ️  Cloud SQL proxy not installed (not required for IAM)")


def _mask_url(url: str) -> str:
    """Mask sensitive parts of database URL for logging."""
    if "://" in url:
        parts = url.split("://", 1)
        if "@" in parts[1]:
            cred_part, host_part = parts[1].split("@", 1)
            if ":" in cred_part:
                user, _ = cred_part.split(":", 1)
                masked_creds = f"{user}:***"
            else:
                # Google Cloud SQL IAM format
                if len(cred_part) > 8:
                    masked_creds = f"{cred_part[:8]}***"
                else:
                    masked_creds = cred_part
            return f"{parts[0]}://{masked_creds}@{host_part}"
    return url


# Export CLI entry points and create explicit references for analyzers
__all__ = [
    "cli",
    "create_url",
    "test_iam_auth",
    "check_auth",
]

_CLI_COMMANDS: tuple[object, ...] = (
    cli,
    create_url,
    test_iam_auth,
    check_auth,
)

if __name__ == "__main__":
    cli()
