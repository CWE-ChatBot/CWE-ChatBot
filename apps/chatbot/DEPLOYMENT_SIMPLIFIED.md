# CWE ChatBot Deployment - Simplified Guide

## TL;DR

**Secrets are automatically retrieved from GCP Secret Manager at runtime. No .env files or --update-secrets needed!**

```bash
# 1. Build
gcloud builds submit --config=apps/chatbot/cloudbuild.yaml

# 2. Deploy
gcloud run deploy cwe-chatbot \
  --region=us-central1 \
  --image=us-central1-docker.pkg.dev/cwechatbot/chatbot/chatbot:latest \
  --service-account=cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com \
  --set-env-vars="GOOGLE_CLOUD_PROJECT=cwechatbot,DB_HOST=10.43.0.3,DB_PORT=5432,DB_NAME=postgres,DB_USER=app_user"

# That's it! App reads secrets from Secret Manager automatically.
```

## How It Works

### Architecture
```
Cloud Run Service
  └─> app_config.py (loads config)
       └─> secrets.py (retrieves secrets)
            ├─> GCP Secret Manager (production)
            └─> Environment variables (local dev fallback)
```

### What Happens at Runtime
1. App starts, imports `app_config.py`
2. `app_config.py` calls `secrets.py` functions for sensitive values
3. `secrets.py` checks if running in GCP (looks for `GOOGLE_CLOUD_PROJECT`)
4. If in GCP: Retrieve from Secret Manager using service account credentials
5. If local: Fall back to environment variables from `.env` file

## Required Secrets in GCP

These must exist in Secret Manager (project: `cwechatbot`):

- `db-password-app-user` - PostgreSQL password
- `gemini-api-key` - Google Gemini API key
- `chainlit-auth-secret` - OAuth state signing key
- `oauth-google-client-id` - Google OAuth client ID
- `oauth-google-client-secret` - Google OAuth client secret
- `oauth-github-client-id` - GitHub OAuth client ID (optional)
- `oauth-github-client-secret` - GitHub OAuth client secret (optional)

Service account needs: `roles/secretmanager.secretAccessor`

## Environment Variables Needed

### Production (Cloud Run)
Only non-sensitive config:
```bash
GOOGLE_CLOUD_PROJECT=cwechatbot  # Enables Secret Manager
DB_HOST=10.43.0.3                # Cloud SQL Private IP
DB_PORT=5432
DB_NAME=postgres
DB_USER=app_user
DB_SSLMODE=require
PDF_WORKER_URL=https://pdf-worker-bmgj6wj65a-uc.a.run.app
```

**No secrets in env vars!** They're retrieved from Secret Manager at runtime.

### Local Development
Option 1 - Use Secret Manager (recommended):
```bash
export GOOGLE_CLOUD_PROJECT=cwechatbot
gcloud auth application-default login
poetry run chainlit run apps/chatbot/main.py
```

Option 2 - Use `.env` file:
```bash
# apps/chatbot/.env
GOOGLE_CLOUD_PROJECT=cwechatbot
DB_HOST=localhost
DB_PASSWORD=your_local_password
GEMINI_API_KEY=your_api_key
```

## Quick Deploy Script

Use the included deployment script:

```bash
./apps/chatbot/deploy.sh
```

This script:
- ✅ Checks prerequisites (gcloud, docker)
- ✅ Builds from project root (correct context)
- ✅ Deploys with Secret Manager integration
- ✅ Verifies capacity limits
- ✅ Shows next steps

## Files Reference

| File | Purpose |
|------|---------|
| `src/secrets.py` | Secret Manager integration with env var fallback |
| `src/app_config.py` | Main config, uses `secrets.py` for sensitive values |
| `deploy.sh` | Automated build and deploy script |
| `SECRETS.md` | Detailed secret management documentation |
| `DEPLOYMENT.md` | Complete deployment guide |
| `.env.example` | Template for local development (optional) |

## Why This Approach?

### Old Way (Bad):
```bash
gcloud run deploy ... \
  --update-secrets="GEMINI_API_KEY=gemini-api-key:latest,DB_PASSWORD=db-password-app-user:latest,..."
  # 7 secrets as environment variables!
```

### New Way (Good):
```bash
gcloud run deploy ... \
  --set-env-vars="GOOGLE_CLOUD_PROJECT=cwechatbot,DB_HOST=..."
  # Zero secrets! Retrieved at runtime from Secret Manager
```

**Benefits:**
- ✅ No secrets in deploy commands or logs
- ✅ Automatic secret rotation (just restart service)
- ✅ Centralized secret management
- ✅ Audit trail in Secret Manager
- ✅ Same code works local and production

## Troubleshooting

**"Secret not found" error:**
- Verify secret exists: `gcloud secrets describe <secret-name> --project=cwechatbot`
- Check service account has `secretmanager.secretAccessor` role
- Ensure `GOOGLE_CLOUD_PROJECT=cwechatbot` is set

**Local development can't access secrets:**
- Run: `gcloud auth application-default login`
- Or create `.env` file with local values

**See detailed troubleshooting:** [`SECRETS.md`](SECRETS.md)

## Next Steps After Deployment

1. **Update OAuth redirect URIs** (if using OAuth):
   - Google: `https://SERVICE_URL/auth/callback/google`
   - GitHub: `https://SERVICE_URL/auth/callback/github`

2. **Monitor the service**:
   ```bash
   # View logs
   gcloud logging tail 'resource.labels.service_name="cwe-chatbot"'

   # Check metrics
   open https://console.cloud.google.com/run/detail/us-central1/cwe-chatbot/metrics?project=cwechatbot
   ```

3. **Verify capacity limits** (Story S-1):
   ```bash
   gcloud run services describe cwe-chatbot --region=us-central1 --format=yaml | grep -E "(containerConcurrency|maxScale)"
   # Expected: maxScale: 10, containerConcurrency: 80
   ```

---

**Ready to deploy?** Run `./apps/chatbot/deploy.sh` and you're done! 🚀
