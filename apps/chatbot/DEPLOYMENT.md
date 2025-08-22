# CWE ChatBot Deployment Guide

This document provides instructions for deploying the CWE ChatBot to Google Cloud Run.

## Prerequisites

1. **GCP Project**: Ensure you have a GCP project with billing enabled
2. **APIs Enabled**: Enable the following APIs:
   - Cloud Run API
   - Artifact Registry API
   - Cloud Build API (if using Cloud Build)
3. **Authentication**: Configure authentication (see below)

## Setup Instructions

### 1. GCP Infrastructure Setup

```bash
# Set your project ID
export GCP_PROJECT_ID=your-project-id

# Run the infrastructure setup script
cd apps/chatbot/infrastructure
./setup-gcp.sh
```

### 2. Create Artifact Registry Repository

```bash
# Create repository for container images
gcloud artifacts repositories create chatbot-repo \
    --repository-format=docker \
    --location=us-central1 \
    --description="CWE ChatBot container images"
```

### 3. GitHub Actions Deployment (Recommended)

#### Setup Workload Identity Federation

```bash
# Create Workload Identity Pool
gcloud iam workload-identity-pools create "github-pool" \
    --location="global" \
    --description="GitHub Actions pool"

# Create Workload Identity Provider
gcloud iam workload-identity-pools providers create-oidc "github-provider" \
    --location="global" \
    --workload-identity-pool="github-pool" \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository"

# Create service account for GitHub Actions
gcloud iam service-accounts create "github-actions-sa" \
    --description="Service account for GitHub Actions"

# Grant necessary permissions
gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
    --member="serviceAccount:github-actions-sa@$GCP_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/run.admin"

gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
    --member="serviceAccount:github-actions-sa@$GCP_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/artifactregistry.writer"

# Allow GitHub Actions to impersonate the service account
gcloud iam service-accounts add-iam-policy-binding \
    "github-actions-sa@$GCP_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/iam.workloadIdentityUser" \
    --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/attribute.repository/YOUR_GITHUB_USERNAME/cwe_chatbot_bmad"
```

#### GitHub Secrets

Add these secrets to your GitHub repository:

- `GCP_PROJECT_ID`: Your GCP project ID
- `WIF_PROVIDER`: `projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/providers/github-provider`
- `WIF_SERVICE_ACCOUNT`: `github-actions-sa@$GCP_PROJECT_ID.iam.gserviceaccount.com`

### 4. Cloud Build Deployment (Alternative)

```bash
# Submit build to Cloud Build
gcloud builds submit --config=apps/chatbot/cloudbuild.yaml
```

## Security Features

### Service Account
- **Minimal Permissions**: The service account has only the minimum required permissions:
  - `roles/run.invoker`: Execute the Cloud Run service
  - `roles/logging.logWriter`: Write application logs

### Network Security
- **Ingress Control**: Service is configured with `internal-and-cloud-load-balancing` ingress
- **No Direct Public Access**: Service is not exposed directly to the internet

### Container Security
- **Minimal Base Image**: Uses `python:3.11-slim` for reduced attack surface
- **Non-root User**: Container runs as non-root user `appuser`
- **Health Checks**: Built-in health check endpoint for service monitoring

## Monitoring and Logging

### Cloud Logging
Application logs are automatically sent to Cloud Logging and can be viewed at:
```
https://console.cloud.google.com/logs/query;query=resource.type%3D%22cloud_run_revision%22%0Aresource.labels.service_name%3D%22cwe-chatbot%22
```

### Health Check
The service exposes a health check endpoint at `/health` that returns:
```json
{"status": "healthy", "service": "cwe-chatbot"}
```

## Local Development

### Run Locally
```bash
cd apps/chatbot
pip install -r requirements.txt
chainlit run main.py
```

### Build and Test Container
```bash
cd apps/chatbot
docker build -t cwe-chatbot .
docker run -p 8080:8080 cwe-chatbot
```

## Deployment Success ✅

The CWE ChatBot has been successfully deployed to Cloud Run at:
**https://cwe-chatbot-258315443546.us-central1.run.app**

### Verified Functionality
- ✅ Chainlit interface loads correctly
- ✅ Welcome message displays: "Hello, welcome to CWE ChatBot!"
- ✅ Application logs available in Google Cloud Logging
- ✅ Secure configuration with minimal IAM permissions

## Troubleshooting

### Resolved Issues

1. **Chainlit Version Compatibility**: 
   - Issue: Pydantic compatibility error with Chainlit 1.3.2
   - Solution: Updated to Chainlit 2.7.1.1
   
2. **Ingress Configuration**:
   - Issue: Service deployed but not accessible
   - Solution: Use `--ingress=all` for testing, `internal-and-cloud-load-balancing` for production

### Additional Common Issues

1. **Permission Errors**: Ensure the service account has the correct IAM roles
2. **Build Failures**: Check that all required APIs are enabled
3. **Service Unreachable**: Verify ingress settings and network configuration

### Debug Commands

```bash
# Check service status
gcloud run services describe cwe-chatbot --region=us-central1

# View logs
gcloud logs read --filter="resource.type=cloud_run_revision AND resource.labels.service_name=cwe-chatbot"

# Test health endpoint
curl https://YOUR_SERVICE_URL/health
```