# PDF Worker - Cloud Functions v2

Ephemeral PDF processing service for CWE ChatBot.

## Features

- **PDF Sanitization**: Removes JavaScript, embedded files, XFA forms, auto-actions
- **Magic Byte Validation**: Enforces PDF format
- **Size Limits**: 10MB max payload, 50 pages max
- **Memory-Only**: No disk persistence (uses BytesIO only)
- **OIDC Authentication**: Cloud Functions IAM with service account authentication
- **No Content Logging**: Logs metadata only (size, pages, duration)

## Deployment

```bash
export PROJECT=$(gcloud config get-value project)
export REGION=us-central1

gcloud functions deploy pdf-worker \
  --gen2 \
  --region=$REGION \
  --runtime=python312 \
  --entry-point=function_entry \
  --trigger-http \
  --no-allow-unauthenticated \
  --memory=512Mi \
  --timeout=60s \
  --max-instances=10 \
  --ingress-settings=internal-only
```

## Grant Access to Chainlit Service Account

```bash
CHAINLIT_SA=$(gcloud run services describe cwe-chatbot \
  --region=$REGION \
  --format='value(spec.template.spec.serviceAccountName)')

gcloud functions add-iam-policy-binding pdf-worker \
  --gen2 \
  --region=$REGION \
  --member="serviceAccount:$CHAINLIT_SA" \
  --role="roles/cloudfunctions.invoker"
```

## Testing

```bash
# Should return 403 (no auth)
curl -X POST https://$REGION-$PROJECT.cloudfunctions.net/pdf-worker \
  -H "Content-Type: application/pdf" \
  --data-binary @test.pdf
```

## Security

- **Input Validation**: PDF magic bytes, size limits, page limits
- **Sanitization**: Removes all executable content from PDFs
- **Authentication**: OIDC tokens required (IAM enforced)
- **Isolation**: Internal ingress only (not publicly accessible)
- **No Persistence**: Memory-only processing, no disk writes
