#!/bin/bash
# Setup script for GCP infrastructure for CWE ChatBot
# This script creates the necessary service account and IAM bindings

set -euo pipefail

# Set default project ID
GCP_PROJECT_ID="cwechatbot"

gcloud config set project cwechatbot

# Check required environment variables
if [[ -z "${GCP_PROJECT_ID:-}" ]]; then
    echo "Error: GCP_PROJECT_ID environment variable is required"
    exit 1
fi

echo "Setting up GCP infrastructure for project: ${GCP_PROJECT_ID}"

# Service account name
SA_NAME="cwe-chatbot-sa"
SA_EMAIL="${SA_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

# Create service account
echo "Creating service account: ${SA_NAME}"
gcloud iam service-accounts create ${SA_NAME} \
    --description="Minimal service account for CWE ChatBot Cloud Run deployment" \
    --display-name="CWE ChatBot Service Account" \
    --project=${GCP_PROJECT_ID}

# Grant minimal IAM roles
echo "Granting minimal IAM roles..."

# Cloud Run Invoker role (required for Cloud Run execution)
gcloud projects add-iam-policy-binding ${GCP_PROJECT_ID} \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/run.invoker"

# Log Writer role (required for application logging)
gcloud projects add-iam-policy-binding ${GCP_PROJECT_ID} \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/logging.logWriter"

echo "GCP infrastructure setup complete!"
echo "Service Account: ${SA_EMAIL}"
echo "IAM Roles: roles/run.invoker, roles/logging.logWriter"