# OAuth Authentication Setup Guide

This guide walks you through setting up OAuth authentication for the CWE ChatBot application.

## Overview

The chatbot supports OAuth authentication with two providers:
- **Google OAuth 2.0**
- **GitHub OAuth**

OAuth can be enabled or disabled via environment variables, and you can configure user whitelisting to restrict access to specific email addresses or domains.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Google OAuth Setup](#google-oauth-setup)
3. [GitHub OAuth Setup](#github-oauth-setup)
4. [Environment Configuration](#environment-configuration)
5. [User Whitelisting](#user-whitelisting)
6. [Local Development](#local-development)
7. [Production Deployment](#production-deployment)
8. [Troubleshooting](#troubleshooting)

## Quick Start

**Minimum required environment variables:**

```bash
# Enable/disable OAuth
ENABLE_OAUTH=true

# Chainlit configuration
CHAINLIT_URL=https://your-app-url.com
CHAINLIT_AUTH_SECRET=your-random-secret-here

# At least one OAuth provider
OAUTH_GOOGLE_CLIENT_ID=your_google_client_id
OAUTH_GOOGLE_CLIENT_SECRET=your_google_secret
# OR
OAUTH_GITHUB_CLIENT_ID=your_github_client_id
OAUTH_GITHUB_CLIENT_SECRET=your_github_secret

# Optional: User whitelist
ALLOWED_USERS=user@example.com,@yourdomain.com
```

## Google OAuth Setup

### 1. Create OAuth 2.0 Credentials

1. Go to [Google Cloud Console - APIs & Services - Credentials](https://console.cloud.google.com/apis/credentials)
2. Click **"Create Credentials"** → **"OAuth client ID"**
3. Select **"Web application"** as the application type
4. Configure the OAuth consent screen if prompted
5. Add **Authorized redirect URIs**:
   - Production: `https://your-app-url.com/auth/oauth/google/callback`
   - Local dev: `http://localhost:8081/auth/oauth/google/callback`

### 2. Get Your Credentials

After creating the OAuth client, you'll receive:
- **Client ID**: Format like `258315443546-xxxxx.apps.googleusercontent.com`
- **Client Secret**: Format like `GOCSPX-xxxxxxxxxxxxxxxxx`

### 3. Set Environment Variables

```bash
OAUTH_GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
OAUTH_GOOGLE_CLIENT_SECRET="GOCSPX-your-client-secret"
```

### 4. OAuth Consent Screen Configuration

**Recommended settings:**
- **User Type**: External (for public access) or Internal (for organization only)
- **Scopes**:
  - `userinfo.email` (required)
  - `userinfo.profile` (optional, for user names)
- **Test users**: Add test users if app is in testing mode

## GitHub OAuth Setup

### 1. Create GitHub OAuth App

1. Go to [GitHub Settings → Developer settings → OAuth Apps](https://github.com/settings/developers)
2. Click **"New OAuth App"**
3. Fill in the application details:
   - **Application name**: CWE ChatBot (or your preferred name)
   - **Homepage URL**: `https://your-app-url.com`
   - **Authorization callback URL**:
     - Production: `https://your-app-url.com/auth/oauth/github/callback`
     - Local dev: `http://localhost:8081/auth/oauth/github/callback`

### 2. Get Your Credentials

After creating the OAuth App:
- **Client ID**: Format like `Ov23lixxxxxxxxxx`
- **Client Secret**: Click "Generate a new client secret"

### 3. Set Environment Variables

```bash
OAUTH_GITHUB_CLIENT_ID="Ov23lixxxxxxxxxx"
OAUTH_GITHUB_CLIENT_SECRET="your-github-client-secret"
```

### 4. Email Privacy Settings

**Important**: GitHub OAuth requires email access. If you have email privacy enabled:
- The app will request access to your email addresses
- The app retrieves the **primary verified email** for authentication
- The code handles both public and private email settings

## Environment Configuration

### Required Variables

```bash
# OAuth Control
ENABLE_OAUTH=true                    # Set to 'false' to disable OAuth

# Chainlit Configuration
CHAINLIT_URL=https://your-app-url.com  # Your app's public URL
CHAINLIT_AUTH_SECRET=random-secret-min-32-chars  # Generate securely

# Database Configuration (for production)
DB_HOST=10.43.0.3                    # Database host
DB_USER=app_user                     # Database user
DB_NAME=postgres                     # Database name
DB_PASSWORD=your-db-password         # Database password
```

### Generate CHAINLIT_AUTH_SECRET

**Using Python:**
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

**Using OpenSSL:**
```bash
openssl rand -base64 48
```

**Requirements:**
- Minimum 32 characters
- Use cryptographically secure random generation
- Keep secret and never commit to version control

## User Whitelisting

### Configuration

```bash
# Allow specific users and domains
ALLOWED_USERS=user1@example.com,user2@gmail.com,@yourdomain.com
```

### Whitelist Rules

**Email-based whitelisting:**
```bash
ALLOWED_USERS=alice@example.com,bob@company.com
```
- Only `alice@example.com` and `bob@company.com` can access

**Domain-based whitelisting:**
```bash
ALLOWED_USERS=@mitre.org,@yourcompany.com
```
- Anyone with `@mitre.org` or `@yourcompany.com` email can access

**Mixed whitelisting:**
```bash
ALLOWED_USERS=admin@example.com,@mitre.org
```
- `admin@example.com` specifically allowed
- Anyone with `@mitre.org` email allowed

**No whitelist (allow all authenticated users):**
```bash
# Leave ALLOWED_USERS empty or unset
```

### Whitelist Behavior

- **Email matching**: Case-insensitive exact match
- **Domain matching**: Case-insensitive suffix match (must start with `@`)
- **Empty whitelist**: All authenticated users from configured OAuth providers are allowed
- **Unauthorized access**: Users not in whitelist see error message and cannot access the app

## Local Development

### 1. Create `.env` File

Create a `.env` file in the `apps/chatbot/` directory:

```bash
# Local Development OAuth Configuration

# OAuth Control
ENABLE_OAUTH=true

# Chainlit Configuration
CHAINLIT_URL=http://localhost:8081
CHAINLIT_AUTH_SECRET=your-dev-secret-here

# Google OAuth (optional)
OAUTH_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
OAUTH_GOOGLE_CLIENT_SECRET=GOCSPX-your-client-secret

# GitHub OAuth (optional)
OAUTH_GITHUB_CLIENT_ID=Ov23lixxxxxxxxxx
OAUTH_GITHUB_CLIENT_SECRET=your-github-client-secret

# User Whitelist (optional)
ALLOWED_USERS=your-email@example.com

# Database Configuration
LOCAL_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/cwe
POSTGRES_PASSWORD=postgres

# LLM Configuration
GEMINI_API_KEY=your-gemini-api-key
```

### 2. Update OAuth Redirect URIs

**For local development, add to your OAuth apps:**

**Google OAuth:**
- Redirect URI: `http://localhost:8081/auth/oauth/google/callback`

**GitHub OAuth:**
- Callback URL: `http://localhost:8081/auth/oauth/github/callback`

### 3. Run Locally

```bash
# From project root
cd apps/chatbot

# Load environment variables (if using direnv or similar)
source .env

# Run with Chainlit
poetry run chainlit run main.py --host 0.0.0.0 --port 8081
```

### 4. Test OAuth Flow

1. Navigate to `http://localhost:8081`
2. Click OAuth provider button (Google or GitHub)
3. Complete OAuth flow in popup window
4. You should be redirected back and authenticated

## Production Deployment

### Google Cloud Run Example

#### 1. Store Secrets in Secret Manager

```bash
# Create secrets
echo -n "your-chainlit-secret" | gcloud secrets create chainlit-auth-secret --data-file=- --project=your-project
echo -n "your-google-client-id" | gcloud secrets create oauth-google-client-id --data-file=- --project=your-project
echo -n "your-google-secret" | gcloud secrets create oauth-google-client-secret --data-file=- --project=your-project
echo -n "your-github-client-id" | gcloud secrets create oauth-github-client-id --data-file=- --project=your-project
echo -n "your-github-secret" | gcloud secrets create oauth-github-client-secret --data-file=- --project=your-project
echo -n "your-db-password" | gcloud secrets create db-password --data-file=- --project=your-project
```

#### 2. Deploy to Cloud Run

```bash
# Deploy with OAuth secrets
gcloud run deploy cwe-chatbot \
  --image=gcr.io/your-project/cwe-chatbot:latest \
  --region=us-central1 \
  --project=your-project \
  --set-secrets=CHAINLIT_AUTH_SECRET=chainlit-auth-secret:latest,\
OAUTH_GOOGLE_CLIENT_ID=oauth-google-client-id:latest,\
OAUTH_GOOGLE_CLIENT_SECRET=oauth-google-client-secret:latest,\
OAUTH_GITHUB_CLIENT_ID=oauth-github-client-id:latest,\
OAUTH_GITHUB_CLIENT_SECRET=oauth-github-client-secret:latest,\
DB_PASSWORD=db-password:latest \
  --set-env-vars=CHAINLIT_URL=https://your-app-url.run.app,\
ENABLE_OAUTH=true,\
ALLOWED_USERS=admin@example.com,@yourcompany.com,\
DB_HOST=10.43.0.3,\
DB_USER=app_user,\
DB_NAME=postgres
```

#### 3. Update OAuth Redirect URIs

**Update your OAuth apps with production redirect URIs:**

**Google OAuth:**
- Add: `https://your-app-url.run.app/auth/oauth/google/callback`

**GitHub OAuth:**
- Add: `https://your-app-url.run.app/auth/oauth/github/callback`

#### 4. Enable Public Access (if needed)

```bash
# Allow unauthenticated access (OAuth handles authentication at app level)
gcloud run services add-iam-policy-binding cwe-chatbot \
  --region=us-central1 \
  --project=your-project \
  --member="allUsers" \
  --role="roles/run.invoker"
```

## Troubleshooting

### OAuth Login Button Not Appearing

**Symptom**: No login buttons on the page

**Possible causes:**
1. `ENABLE_OAUTH=false` - Check environment variable
2. Missing OAuth credentials - Check `OAUTH_GOOGLE_CLIENT_ID` or `OAUTH_GITHUB_CLIENT_ID`
3. Missing `CHAINLIT_AUTH_SECRET` - Required for OAuth to work

**Solution:**
```bash
# Check logs for OAuth initialization
# You should see: "OAuth callback registered for: Google, GitHub"
```

### "No email found in OAuth data" Error

**Symptom**: GitHub OAuth fails with "credentialssignin" error

**Possible causes:**
1. GitHub email privacy settings blocking email access
2. OAuth app doesn't have email scope

**Solution:**
- GitHub app automatically requests email scope
- Code handles private emails by fetching from `/user/emails` API
- Ensure your GitHub email is verified

### "Unauthorized user" Error

**Symptom**: Login succeeds but access is denied

**Possible causes:**
1. Email not in `ALLOWED_USERS` whitelist
2. Domain not matching whitelist pattern

**Solution:**
```bash
# Check your email against whitelist
# Example: crashedmind@gmail.com should match:
ALLOWED_USERS=crashedmind@gmail.com,@gmail.com

# Check application logs for:
# "Unauthorized user: your-email@example.com"
```

### Redirect URI Mismatch Error

**Symptom**: OAuth provider shows redirect URI error

**Possible causes:**
1. Redirect URI not configured in OAuth app settings
2. `CHAINLIT_URL` doesn't match deployed URL
3. HTTP vs HTTPS mismatch

**Solution:**
1. Verify `CHAINLIT_URL` environment variable matches your actual app URL
2. Add exact redirect URI to OAuth provider:
   - Google: `{CHAINLIT_URL}/auth/oauth/google/callback`
   - GitHub: `{CHAINLIT_URL}/auth/oauth/github/callback`
3. Check for trailing slashes - should NOT have trailing slash in `CHAINLIT_URL`

### OAuth Callback Fails Silently

**Symptom**: Redirects to callback but nothing happens

**Check logs for:**
```bash
# Success case:
"Successfully authenticated user: email@example.com via google"

# Failure cases:
"No email found in OAuth data for provider: github"
"Unauthorized user: email@example.com"
"OAuth callback error for provider github"
```

**Debug steps:**
1. Enable debug logging: `DEBUG=true`
2. Check application logs during OAuth flow
3. Verify all environment variables are set correctly
4. Test with a known-good email in whitelist

### Environment Variables Not Loading

**Symptom**: App doesn't recognize OAuth configuration

**Solution:**
```bash
# Verify environment variables are set
# In Cloud Run, check revision environment variables:
gcloud run revisions describe REVISION_NAME \
  --region=us-central1 \
  --project=your-project \
  --format=yaml | grep -A20 "env:"

# For local development, verify .env file is loaded:
poetry run python -c "import os; print(os.getenv('ENABLE_OAUTH'))"
```

## Security Best Practices

1. **Never commit secrets to version control**
   - Use secret management systems in production

2. **Use strong CHAINLIT_AUTH_SECRET**
   - Minimum 32 characters
   - Cryptographically random
   - Rotate periodically

3. **Implement user whitelisting**
   - Don't allow all authenticated users in production
   - Use domain-based whitelisting for organizations
   - Review access logs regularly

4. **Keep OAuth credentials secure**
   - Store in secret management systems (GCP Secret Manager, AWS Secrets Manager, etc.)
   - Rotate credentials if compromised
   - Limit OAuth app permissions to minimum required

5. **Use HTTPS in production**
   - OAuth requires secure redirect URIs
   - Never use HTTP for production OAuth callbacks

6. **Monitor OAuth usage**
   - Log authentication attempts
   - Alert on suspicious patterns
   - Review authorized users periodically

## Reference: OAuth Callback URLs

### Format

```
{CHAINLIT_URL}/auth/oauth/{provider}/callback
```

### Examples

**Local Development:**
- Google: `http://localhost:8081/auth/oauth/google/callback`
- GitHub: `http://localhost:8081/auth/oauth/github/callback`

**Production:**
- Google: `https://cwe-chatbot.run.app/auth/oauth/google/callback`
- GitHub: `https://cwe-chatbot.run.app/auth/oauth/github/callback`

**Important**: The callback URLs must **exactly match** what's configured in your OAuth provider settings. Even a trailing slash difference will cause errors.

## Support

For issues not covered in this guide:

1. Check application logs for detailed error messages
2. Review [Chainlit OAuth documentation](https://docs.chainlit.io/authentication/oauth)
3. Verify OAuth provider configuration:
   - [Google OAuth 2.0](https://developers.google.com/identity/protocols/oauth2)
   - [GitHub OAuth Apps](https://docs.github.com/en/apps/oauth-apps)
4. Check the project's issue tracker or documentation

## Related Documentation

- [chainlit.md](./chainlit.md) - Chainlit UI configuration with OAuth provider settings
- [apps/chatbot/src/app_config.py](./src/app_config.py) - OAuth configuration code
- [apps/chatbot/main.py](./main.py) - OAuth callback implementation
