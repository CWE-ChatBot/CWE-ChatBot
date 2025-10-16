#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Expose Cloud Run STAGING via existing HTTPS Load Balancer (host-based routing)
# Idempotent: creates/updates only what's missing; leaves prod config intact.
# ─────────────────────────────────────────────────────────────────────────────

# Required inputs (override via env if needed)
PROJECT="${PROJECT:-cwechatbot}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-cwe-chatbot-staging}"                 # Cloud Run staging service name
URLMAP="${URLMAP:-cwe-chatbot-urlmap}"                    # existing URL map
PROXY="${PROXY:-cwe-chatbot-https-proxy}"                 # existing target HTTPS proxy
DOMAIN_STG="${DOMAIN_STG:-staging-cwe.crashedmind.com}"   # new staging host
NEG_STG="${NEG_STG:-cwe-chatbot-staging-neg}"
BE_STG="${BE_STG:-cwe-chatbot-staging-be}"
ARMOR_POLICY="${ARMOR_POLICY:-cwe-chatbot-armor}"         # reuse prod policy by default

# Pretty
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok(){ echo -e "${GREEN}✓${NC} $*"; }
warn(){ echo -e "${YELLOW}⚠${NC} $*"; }
err(){ echo -e "${RED}✗${NC} $*"; }

gcloud config set project "$PROJECT" --quiet >/dev/null

# 0) Pre-flight checks
if ! gcloud compute url-maps describe "$URLMAP" --quiet >/dev/null 2>&1; then
  err "URL map '$URLMAP' not found. Aborting."
  exit 1
fi
if ! gcloud compute target-https-proxies describe "$PROXY" --quiet >/dev/null 2>&1; then
  err "Target HTTPS proxy '$PROXY' not found. Aborting."
  exit 1
fi

# 1) Serverless NEG for staging
if gcloud compute network-endpoint-groups describe "$NEG_STG" --region="$REGION" --quiet >/dev/null 2>&1; then
  ok "NEG exists: $NEG_STG"
else
  gcloud compute network-endpoint-groups create "$NEG_STG" \
    --region="$REGION" \
    --network-endpoint-type=serverless \
    --cloud-run-service="$SERVICE" \
    --quiet
  ok "NEG created: $NEG_STG → Cloud Run service '$SERVICE'"
fi

# 2) Backend service for staging (HTTP for serverless NEGs, external managed)
if gcloud compute backend-services describe "$BE_STG" --global --quiet >/dev/null 2>&1; then
  ok "Backend service exists: $BE_STG"
else
  gcloud compute backend-services create "$BE_STG" \
    --global \
    --load-balancing-scheme=EXTERNAL_MANAGED \
    --protocol=HTTP \
    --quiet
  ok "Backend service created: $BE_STG"
fi

# 2a) Ensure NEG is attached to backend
if gcloud compute backend-services get-health "$BE_STG" --global --quiet >/dev/null 2>&1; then
  # Check if our NEG is already attached
  if gcloud compute backend-services describe "$BE_STG" --global \
      --format="value(backends[].group)" | grep -q "$NEG_STG"; then
    ok "NEG already attached to backend: $NEG_STG → $BE_STG"
  else
    gcloud compute backend-services add-backend "$BE_STG" \
      --global \
      --network-endpoint-group="$NEG_STG" \
      --network-endpoint-group-region="$REGION" \
      --quiet
    ok "Attached NEG to backend: $NEG_STG → $BE_STG"
  fi
else
  # If get-health failed for other reasons, still attempt add-backend (idempotent)
  gcloud compute backend-services add-backend "$BE_STG" \
    --global \
    --network-endpoint-group="$NEG_STG" \
    --network-endpoint-group-region="$REGION" \
    --quiet || true
  ok "Ensured NEG is attached to backend: $NEG_STG → $BE_STG"
fi

# 2b) Attach/re-attach Cloud Armor policy (optional but recommended)
if gcloud compute security-policies describe "$ARMOR_POLICY" --quiet >/dev/null 2>&1; then
  gcloud compute backend-services update "$BE_STG" \
    --global \
    --security-policy="$ARMOR_POLICY" \
    --quiet
  ok "Cloud Armor policy attached to staging backend: $ARMOR_POLICY"
else
  warn "Cloud Armor policy '$ARMOR_POLICY' not found; skipping WAF attach."
fi

# 3) Managed TLS certificate for staging host (attach alongside existing certs)
if gcloud compute ssl-certificates describe "cert-${DOMAIN_STG//./-}" --quiet >/dev/null 2>&1; then
  ok "Managed cert exists: cert-${DOMAIN_STG//./-}"
else
  gcloud compute ssl-certificates create "cert-${DOMAIN_STG//./-}" \
    --domains="$DOMAIN_STG" \
    --quiet
  ok "Managed cert created: cert-${DOMAIN_STG//./-} for $DOMAIN_STG"
fi

# Add the staging cert to the HTTPS proxy, preserving existing certs
CURR_CERTS=$(gcloud compute target-https-proxies describe "$PROXY" \
  --format="value(sslCertificates[])")
if [[ "${CURR_CERTS:-}" == *"cert-${DOMAIN_STG//./-}"* ]]; then
  ok "HTTPS proxy already has staging cert attached."
else
  # Avoid duplicate commas if CURR_CERTS is empty
  if [[ -n "${CURR_CERTS:-}" ]]; then
    NEW_CERTS="${CURR_CERTS},cert-${DOMAIN_STG//./-}"
  else
    NEW_CERTS="cert-${DOMAIN_STG//./-}"
  fi
  gcloud compute target-https-proxies update "$PROXY" \
    --ssl-certificates="$NEW_CERTS" \
    --quiet
  ok "Attached staging cert to HTTPS proxy."
fi

# 4) URL map: add path-matcher for staging and host-rule routing for the staging host
# Create a path matcher for staging if it doesn't exist.
if gcloud compute url-maps describe "$URLMAP" \
     --format="value(pathMatchers[].name)" | grep -q "^pm-staging$"; then
  ok "Path matcher exists: pm-staging"
else
  gcloud compute url-maps add-path-matcher "$URLMAP" \
    --path-matcher-name=pm-staging \
    --default-service="$BE_STG" \
    --quiet
  ok "Path matcher created: pm-staging → $BE_STG"
fi

# Add (or update) host rule for staging host → pm-staging
if gcloud compute url-maps describe "$URLMAP" \
     --format="flattened(hostRules[])"; then
  if gcloud compute url-maps describe "$URLMAP" \
       --format="value(hostRules[].hosts)" | tr ';' '\n' | tr ',' '\n' | grep -qx "$DOMAIN_STG"; then
    # Host exists; ensure it targets pm-staging (re-add to be safe/idempotent)
    gcloud compute url-maps remove-host-rule "$URLMAP" \
      --hosts="$DOMAIN_STG" --quiet || true
  fi
fi

gcloud compute url-maps add-host-rule "$URLMAP" \
  --hosts="$DOMAIN_STG" \
  --path-matcher-name=pm-staging \
  --quiet
ok "Host rule added: $DOMAIN_STG → pm-staging → $BE_STG"

# 5) Tell user the LB IP and DNS step
LB_IP=$(gcloud compute forwarding-rules list --global --format="value(IPAddress)" | head -n1)
if [[ -z "${LB_IP:-}" ]]; then
  warn "Could not resolve LB IP automatically. Check your forwarding rules."
else
  ok "Load balancer IP: $LB_IP"
  echo "Create an A record: ${DOMAIN_STG} → ${LB_IP}"
fi

# 6) Quick test instructions
cat <<EOF

${YELLOW}Next steps:${NC}
  1) Point DNS: ${DOMAIN_STG} → ${LB_IP} (same IP as prod).
     Wait for the managed cert to become ACTIVE.
  2) Smoke test (before DNS, using --resolve):
     curl -i --resolve ${DOMAIN_STG}:443:${LB_IP} https://${DOMAIN_STG}/api/health

${GREEN}Notes:${NC}
  - Prod stays on defaultService in URL map (unchanged).
  - Staging uses host-based routing via ${DOMAIN_STG}.
  - When using the LB hostname, clients only need ${YELLOW}OAuth Bearer tokens${NC}
    (Google ID token or GitHub access token). No Cloud Run ID token required.

Done.
EOF
