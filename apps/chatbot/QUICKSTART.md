# CWE ChatBot - Quick Start Guide

Complete guide to build and deploy the CWE ChatBot from scratch.

## Prerequisites

- **GCP Account**: Active Google Cloud Platform account with billing enabled
- **GCP Project**: `cwechatbot` (or your project ID)
- **Local Tools**:
  - `gcloud` CLI installed and authenticated
  - `docker` installed (for local testing)
  - `poetry` installed (for local development)
- **APIs Enabled**:
  ```bash
  gcloud services enable run.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    secretmanager.googleapis.com \
    sqladmin.googleapis.com
  ```

## 1. Environment Setup

### Local Development Setup

1. **Copy environment template**:
   ```bash
   cd apps/chatbot
   cp .env.example .env
   ```

2. **Get required secrets from GCP**:
   ```bash
   # Database password
   gcloud secrets versions access latest --secret=db-password-app-user --project=cwechatbot

   # Gemini API key
   gcloud secrets versions access latest --secret=gemini-api-key --project=cwechatbot

   # OAuth credentials (optional)
   gcloud secrets versions access latest --secret=oauth-google-client-id --project=cwechatbot
   gcloud secrets versions access latest --secret=oauth-google-client-secret --project=cwechatbot
   ```

3. **Edit `.env` file** with your values:
   ```bash
   # Required for local development
   DB_HOST=localhost                    # Or Cloud SQL Private IP for remote
   DB_PORT=5432
   DB_NAME=postgres
   DB_USER=postgres
   DB_PASSWORD=<from secret manager>
   GEMINI_API_KEY=<from secret manager>
   ```

### Production Environment Variables

Production secrets are stored in GCP Secret Manager and injected at runtime:

| Environment Variable | Secret Name | How to Get |
|---------------------|-------------|------------|
| `DB_PASSWORD` | `db-password-app-user` | `gcloud secrets versions access latest --secret=db-password-app-user` |
| `GEMINI_API_KEY` | `gemini-api-key` | `gcloud secrets versions access latest --secret=gemini-api-key` |
| `CHAINLIT_AUTH_SECRET` | `chainlit-auth-secret` | `gcloud secrets versions access latest --secret=chainlit-auth-secret` |
| `OAUTH_GOOGLE_CLIENT_ID` | `oauth-google-client-id` | `gcloud secrets versions access latest --secret=oauth-google-client-id` |
| `OAUTH_GOOGLE_CLIENT_SECRET` | `oauth-google-client-secret` | `gcloud secrets versions access latest --secret=oauth-google-client-secret` |
| `OAUTH_GITHUB_CLIENT_ID` | `oauth-github-client-id` | `gcloud secrets versions access latest --secret=oauth-github-client-id` |
| `OAUTH_GITHUB_CLIENT_SECRET` | `oauth-github-client-secret` | `gcloud secrets versions access latest --secret=oauth-github-client-secret` |

## 2. Local Development

### Run Locally (with Poetry)

```bash
# From project root
cd /home/chris/work/CyberSecAI/cwe_chatbot_bmad

# Install dependencies
poetry install

# Start the application
poetry run chainlit run apps/chatbot/main.py -w

# Access at: http://localhost:8000
```

### Run with Docker Locally

```bash
# Build Docker image
cd apps/chatbot
docker build -t cwe-chatbot-local .

# Run container (load .env file)
docker run -p 8080:8080 --env-file .env cwe-chatbot-local

# Access at: http://localhost:8080
```

## 3. Build and Deploy to Cloud Run

### Option A: Using Cloud Build (Recommended)

```bash
# From project root
gcloud builds submit --config=apps/chatbot/cloudbuild.yaml

# This will:
# 1. Build Docker image from project root
# 2. Push to Artifact Registry: gcr.io/cwechatbot/cwe-chatbot:latest
# 3. Image ready for deployment
```

### Option B: Manual Docker Build

```bash
# From project root (IMPORTANT!)
docker build -t us-central1-docker.pkg.dev/cwechatbot/chatbot/chatbot:latest -f apps/chatbot/Dockerfile .

# Authenticate Docker to GCP
gcloud auth configure-docker us-central1-docker.pkg.dev

# Push to Artifact Registry
docker push us-central1-docker.pkg.dev/cwechatbot/chatbot/chatbot:latest
```

**⚠️ Important**: Always build from project root, not `apps/chatbot/`, because:
- Dockerfile needs access to `apps/cwe_ingestion/` (outside chatbot directory)
- Build context must include entire repository structure
- Paths in Dockerfile are relative to project root

### Deploy to Cloud Run

```bash
# Use the deployment script
./deploy_chatbot.sh

# Or deploy manually:
gcloud run deploy cwe-chatbot \
  --region=us-central1 \
  --image=us-central1-docker.pkg.dev/cwechatbot/chatbot/chatbot:latest \
  --service-account=cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com \
  --vpc-connector=run-us-central1 \
  --vpc-egress=private-ranges-only \
  --memory=512Mi \
  --cpu=1 \
  --min-instances=1 \
  --max-instances=10 \
  --concurrency=80 \
  --timeout=300 \
  --allow-unauthenticated \
  --set-env-vars="DB_HOST=10.43.0.3,DB_PORT=5432,DB_NAME=postgres,DB_USER=app_user,DB_SSLMODE=require,PDF_WORKER_URL=https://pdf-worker-bmgj6wj65a-uc.a.run.app" \
  --update-secrets="GEMINI_API_KEY=gemini-api-key:latest,DB_PASSWORD=db-password-app-user:latest,CHAINLIT_AUTH_SECRET=chainlit-auth-secret:latest,OAUTH_GOOGLE_CLIENT_ID=oauth-google-client-id:latest,OAUTH_GOOGLE_CLIENT_SECRET=oauth-google-client-secret:latest,OAUTH_GITHUB_CLIENT_ID=oauth-github-client-id:latest,OAUTH_GITHUB_CLIENT_SECRET=oauth-github-client-secret:latest"
```

## 4. Verification

### Check Deployment Status

```bash
# Get service URL
gcloud run services describe cwe-chatbot --region=us-central1 --format='value(status.url)'

# Check service health
curl -sI https://cwe-chatbot-258315443546.us-central1.run.app

# View recent logs
gcloud logging read 'resource.type="cloud_run_revision" resource.labels.service_name="cwe-chatbot"' --limit=20
```

### Test the Application

```bash
# Get service URL
SERVICE_URL=$(gcloud run services describe cwe-chatbot --region=us-central1 --format='value(status.url)')

# Test health endpoint
curl $SERVICE_URL/health

# Open in browser
open $SERVICE_URL  # macOS
xdg-open $SERVICE_URL  # Linux
```

### Verify Configuration

```bash
# Check environment variables (non-sensitive)
gcloud run services describe cwe-chatbot --region=us-central1 --format=json | jq -r '.spec.template.spec.containers[0].env[]'

# Check secrets are mounted
gcloud run services describe cwe-chatbot --region=us-central1 --format=json | jq -r '.spec.template.spec.containers[0].env[] | select(.valueFrom.secretKeyRef)'

# Check capacity limits (from S-1 implementation)
gcloud run services describe cwe-chatbot --region=us-central1 --format=yaml | grep -E "(containerConcurrency|maxScale)"
# Expected:
#   autoscaling.knative.dev/maxScale: '10'
#   containerConcurrency: 80
```

## 5. Post-Deployment Configuration

### Update OAuth Redirect URIs

After deployment, update OAuth provider redirect URIs:

**Google Cloud Console** (https://console.cloud.google.com/apis/credentials):
```
Authorized redirect URIs:
  https://cwe-chatbot-258315443546.us-central1.run.app/auth/callback/google
```

**GitHub Developer Settings** (https://github.com/settings/developers):
```
Authorization callback URL:
  https://cwe-chatbot-258315443546.us-central1.run.app/auth/callback/github
```

### Monitor the Service

```bash
# Real-time logs
gcloud logging tail 'resource.type="cloud_run_revision" resource.labels.service_name="cwe-chatbot"'

# Check for errors
gcloud logging read 'resource.labels.service_name="cwe-chatbot" severity>=WARNING' --limit=20

# View Cloud Run metrics
open "https://console.cloud.google.com/run/detail/us-central1/cwe-chatbot/metrics?project=cwechatbot"
```

## 6. Common Issues and Solutions

### Issue: Build Fails with "Cannot Access apps/cwe_ingestion"

**Cause**: Building from wrong directory (apps/chatbot/ instead of project root)

**Solution**: Always build from project root:
```bash
# ✅ Correct
cd /home/chris/work/CyberSecAI/cwe_chatbot_bmad
gcloud builds submit --config=apps/chatbot/cloudbuild.yaml

# ❌ Wrong
cd apps/chatbot
gcloud builds submit --config=cloudbuild.yaml
```

### Issue: Service Starts but Database Connection Fails

**Cause**: Missing or incorrect environment variables

**Solution**: Check environment variables:
```bash
gcloud run services describe cwe-chatbot --region=us-central1 --format=yaml | grep -A5 "env:"

# Verify DB_HOST is set to Cloud SQL Private IP (10.43.0.3)
# Verify DB_PASSWORD secret is mounted
```

### Issue: OAuth Login Fails

**Cause**: Redirect URIs not updated after deployment

**Solution**: Update OAuth provider redirect URIs (see Post-Deployment Configuration above)

### Issue: 503 Errors Under Load

**Cause**: Hitting capacity limits (max-instances=10, concurrency=80)

**Solution**: Increase limits or optimize performance:
```bash
# Increase max instances (if budget allows)
gcloud run services update cwe-chatbot \
  --region=us-central1 \
  --max-instances=20

# Or increase concurrency per instance
gcloud run services update cwe-chatbot \
  --region=us-central1 \
  --concurrency=100
```

## 7. Key Files Reference

| File | Purpose |
|------|---------|
| `apps/chatbot/.env.example` | Environment variable template with all options |
| `apps/chatbot/Dockerfile` | Production Docker image definition |
| `apps/chatbot/cloudbuild.yaml` | Cloud Build configuration |
| `apps/chatbot/main.py` | Chainlit application entry point |
| `deploy_chatbot.sh` | Automated deployment script |
| `apps/chatbot/DEPLOYMENT.md` | Detailed deployment documentation |
| `apps/chatbot/README.md` | Complete feature and architecture overview |

## 8. Development Workflow

### Make Code Changes

```bash
# 1. Make changes to source code
# 2. Test locally
poetry run chainlit run apps/chatbot/main.py -w

# 3. Run tests
poetry run pytest apps/chatbot/tests/ -v

# 4. Build and push new image
gcloud builds submit --config=apps/chatbot/cloudbuild.yaml

# 5. Deploy to Cloud Run
./deploy_chatbot.sh
```

### Update CWE Data

```bash
# Re-run CWE ingestion pipeline
cd apps/cwe_ingestion
poetry run python cli.py ingest-multi --embedder-type gemini

# Application will automatically use updated data
```

## 9. Security Checklist

Before deploying to production:

- [ ] All secrets stored in Secret Manager (no hardcoded credentials)
- [ ] OAuth redirect URIs configured correctly
- [ ] VPC connector configured for private Cloud SQL access
- [ ] Capacity limits configured (max-instances, concurrency)
- [ ] Billing budget alerts configured
- [ ] Cloud Monitoring alerts set up
- [ ] HTTPS-only access enforced
- [ ] Service account has minimal required permissions
- [ ] Input sanitization enabled (`ENABLE_STRICT_SANITIZATION=true`)

## 10. Additional Resources

- **Architecture**: `../../docs/architecture/` - Technical specifications
- **Security**: `../../docs/security/` - Security analysis and testing
- **CWE Ingestion**: `../cwe_ingestion/README.md` - Data pipeline documentation
- **Story S-1**: `../../docs/stories/S-1.Rate-Limiting-and-Budget-Monitoring.md` - Capacity limits implementation
- **Cloud Run Docs**: https://cloud.google.com/run/docs

---

**Ready to deploy?** Follow the steps above to get your CWE ChatBot running in production! 🚀
