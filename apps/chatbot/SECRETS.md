# Secret Management

The CWE ChatBot uses **GCP Secret Manager** for all sensitive values in production. Secrets are retrieved at runtime - no environment variables or `.env` files needed for secrets!

## How It Works

### Production (Cloud Run)
1. Secrets stored in GCP Secret Manager
2. Cloud Run service account has `secretmanager.secretAccessor` role
3. App reads secrets directly from Secret Manager at startup
4. **Zero secrets in environment variables** ✅

### Local Development
1. App tries Secret Manager first (if `GOOGLE_CLOUD_PROJECT` is set)
2. Falls back to environment variables (`.env` file)
3. You choose: Use Secret Manager locally OR use local `.env` file

## Architecture

```
app_config.py
  └─> secrets.py
       ├─> Secret Manager (production/authenticated local)
       └─> Environment Variables (fallback)
```

**File: `src/secrets.py`**
- `get_database_password()` - Tries Secret Manager, falls back to `DB_PASSWORD` env var
- `get_gemini_api_key()` - Tries Secret Manager, falls back to `GEMINI_API_KEY` env var
- `get_chainlit_auth_secret()` - Tries Secret Manager, falls back to `CHAINLIT_AUTH_SECRET` env var
- OAuth functions similarly

**File: `src/app_config.py`**
- Calls `secrets.py` functions instead of `os.getenv()` for sensitive values
- All other config (DB_HOST, DB_PORT, etc.) still from environment variables

## Required Secrets in GCP

These must exist in Secret Manager (project: `cwechatbot`):

| Secret Name | Purpose | Create Command |
|-------------|---------|----------------|
| `db-password-app-user` | PostgreSQL password | `echo -n "password" \| gcloud secrets create db-password-app-user --data-file=-` |
| `gemini-api-key` | Gemini API key | `echo -n "key" \| gcloud secrets create gemini-api-key --data-file=-` |
| `chainlit-auth-secret` | OAuth signing key | `openssl rand -base64 32 \| gcloud secrets create chainlit-auth-secret --data-file=-` |
| `oauth-google-client-id` | Google OAuth ID | `echo -n "id" \| gcloud secrets create oauth-google-client-id --data-file=-` |
| `oauth-google-client-secret` | Google OAuth secret | `echo -n "secret" \| gcloud secrets create oauth-google-client-secret --data-file=-` |
| `oauth-github-client-id` | GitHub OAuth ID | `echo -n "id" \| gcloud secrets create oauth-github-client-id --data-file=-` |
| `oauth-github-client-secret` | GitHub OAuth secret | `echo -n "secret" \| gcloud secrets create oauth-github-client-secret --data-file=-` |

## Production Deployment

**No secrets in environment variables!**

```bash
gcloud run deploy cwe-chatbot \
  --region=us-central1 \
  --image=gcr.io/cwechatbot/cwe-chatbot:latest \
  --service-account=cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com \
  --set-env-vars="GOOGLE_CLOUD_PROJECT=cwechatbot,DB_HOST=10.43.0.3,DB_PORT=5432,DB_NAME=postgres,DB_USER=app_user"
  # No --update-secrets needed! App reads from Secret Manager directly
```

The service account must have:
```bash
gcloud projects add-iam-policy-binding cwechatbot \
  --member="serviceAccount:cwe-chatbot-run-sa@cwechatbot.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

## Local Development Options

### Option 1: Use Secret Manager Locally (Recommended)

```bash
# Authenticate
gcloud auth application-default login

# Set project
export GOOGLE_CLOUD_PROJECT=cwechatbot

# Run app - secrets retrieved from Secret Manager!
poetry run chainlit run apps/chatbot/main.py
```

### Option 2: Use `.env` File (Simpler for quick dev)

```bash
# Create .env file
cat > apps/chatbot/.env <<EOF
GOOGLE_CLOUD_PROJECT=cwechatbot
DB_HOST=localhost
DB_PORT=5432
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=your_local_password
GEMINI_API_KEY=your_api_key
EOF

# Run app - secrets from .env file
poetry run chainlit run apps/chatbot/main.py
```

## Verifying Secrets

Check what secrets the app found at startup:

```bash
poetry run python -c "from apps.chatbot.src.secrets import initialize_secrets; initialize_secrets('cwechatbot')"
```

Output shows which secrets were found:
```
Secret initialization status:
  db_password: ✓ Found
  gemini_api_key: ✓ Found
  chainlit_auth_secret: ✓ Found
  oauth_google_client_id: ✓ Found
  oauth_google_client_secret: ✓ Found
  oauth_github_client_id: ✗ Missing
  oauth_github_client_secret: ✗ Missing
```

## Why This Approach?

### Before (Bad):
- Secrets in environment variables
- Need `--update-secrets` in deploy command
- Secrets rotation requires redeployment
- Risk of secrets in logs/commands

### Now (Good):
- ✅ Secrets only in Secret Manager
- ✅ Automatic secret rotation (Secret Manager handles versions)
- ✅ No secrets in deploy commands
- ✅ Centralized secret management
- ✅ Audit trail in Secret Manager
- ✅ Same code works local and prod

## Migration from Old Approach

If you previously used `--update-secrets`:

**Old deployment**:
```bash
gcloud run deploy ... \
  --update-secrets="GEMINI_API_KEY=gemini-api-key:latest,DB_PASSWORD=db-password-app-user:latest"
```

**New deployment** (secrets retrieved at runtime):
```bash
gcloud run deploy ... \
  --set-env-vars="GOOGLE_CLOUD_PROJECT=cwechatbot"
  # Secrets read from Secret Manager automatically!
```

## Troubleshooting

### "Failed to get secret from Secret Manager"
- Check service account has `secretmanager.secretAccessor` role
- Verify secret exists: `gcloud secrets describe <secret-name> --project=cwechatbot`
- Check project ID is set: `echo $GOOGLE_CLOUD_PROJECT`

### "Secret not found" in logs
- App falls back to environment variables (check `.env` file)
- For production, ensure Secret Manager secrets exist

### Local development can't access Secret Manager
- Run: `gcloud auth application-default login`
- Set: `export GOOGLE_CLOUD_PROJECT=cwechatbot`
- Or use `.env` file with local values

## Security Notes

- **Never log secret values** - `secrets.py` only logs if secrets were found (boolean)
- **Use LRU cache** - `@lru_cache` prevents repeated Secret Manager calls
- **Principle of least privilege** - Service account only needs `secretAccessor` role
- **Audit trail** - Secret Manager logs all access
- **Rotation ready** - Update secret in Secret Manager, restart service (no code change!)
