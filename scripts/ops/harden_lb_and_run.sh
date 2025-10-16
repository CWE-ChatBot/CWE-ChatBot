#!/usr/bin/env bash
set -euo pipefail

# Harden LB + Cloud Run posture for prod+staging behind HTTPS LB
# - Pins URL map default to PROD backend
# - Adds precise Cloud Armor WS allow rules (prod & staging origins)
# - Optionally adds baseline allow rules (health, JSON API <=10MB)
# - Flips final rule to default-deny
# - Asserts Cloud Run ingress=internal-and-cloud-load-balancing
# - Grants allUsers:roles/run.invoker ONLY when ingress is LB-only

# Config (override via env)
PROJECT="${PROJECT:-cwechatbot}"
REGION="${REGION:-us-central1}"
URLMAP="${URLMAP:-cwe-chatbot-urlmap}"
PROXY="${PROXY:-cwe-chatbot-https-proxy}"

# backends/services
BE_PROD="${BE_PROD:-cwe-chatbot-be}"
BE_STG="${BE_STG:-cwe-chatbot-staging-be}"
SERVICE_PROD="${SERVICE_PROD:-cwe-chatbot}"
SERVICE_STG="${SERVICE_STG:-cwe-chatbot-staging}"

# domains
DOMAIN_PROD="${DOMAIN_PROD:-cwe.crashedmind.com}"
DOMAIN_STG="${DOMAIN_STG:-staging-cwe.crashedmind.com}"

# security
ARMOR_POLICY="${ARMOR_POLICY:-cwe-chatbot-armor}"
HARDEN_ARMOR_ALLOW_BASELINES="${HARDEN_ARMOR_ALLOW_BASELINES:-1}"  # 1=add GET/HEAD & JSON API<=10MB allows
MANAGE_RUN_SETTINGS="${MANAGE_RUN_SETTINGS:-1}"                    # 1=assert ingress/IAM on Cloud Run

# Pretty
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok(){ echo -e "${GREEN}✓${NC} $*"; }
warn(){ echo -e "${YELLOW}⚠${NC} $*"; }
err(){ echo -e "${RED}✗${NC} $*"; }

gcloud config set project "$PROJECT" --quiet >/dev/null

# --- Sanity checks
gcloud compute url-maps describe "$URLMAP" >/dev/null || { err "URL map '$URLMAP' not found"; exit 1; }
gcloud compute target-https-proxies describe "$PROXY" >/dev/null || { err "HTTPS proxy '$PROXY' not found"; exit 1; }

# --- 1) URL map default → PROD backend
CUR_DEFAULT="$(gcloud compute url-maps describe "$URLMAP" --format='value(defaultService)')"
if [[ "$CUR_DEFAULT" != *"/backendServices/$BE_PROD" ]]; then
  gcloud compute url-maps set-default-service "$URLMAP" --default-service="$BE_PROD" --quiet
  ok "URL map default set to PROD backend: $BE_PROD"
else
  ok "URL map default already points to PROD: $BE_PROD"
fi

# Ensure staging host rule exists and points to its matcher
if ! gcloud compute url-maps describe "$URLMAP" --format='value(hostRules[].hosts)' | grep -q "$DOMAIN_STG"; then
  warn "No host rule found for $DOMAIN_STG; ensure your wiring script added it."
else
  ok "Host rule for $DOMAIN_STG present."
fi

# --- 2) Cloud Armor hardening
if gcloud compute security-policies describe "$ARMOR_POLICY" >/dev/null 2>&1; then
  # 2a) Allow WS from prod origin (priority 995)
  gcloud compute security-policies rules describe 995 --security-policy="$ARMOR_POLICY" >/dev/null 2>&1 \
    && gcloud compute security-policies rules update 995 --security-policy="$ARMOR_POLICY" \
         --action=allow --description="Allow WS from prod origin" \
         --expression="has(request.headers['upgrade']) && request.headers['upgrade'].lower() == 'websocket' && has(request.headers['origin']) && request.headers['origin'] == 'https://${DOMAIN_PROD}'" --quiet \
    || gcloud compute security-policies rules create 995 --security-policy="$ARMOR_POLICY" \
         --action=allow --description="Allow WS from prod origin" \
         --expression="has(request.headers['upgrade']) && request.headers['upgrade'].lower() == 'websocket' && has(request.headers['origin']) && request.headers['origin'] == 'https://${DOMAIN_PROD}'" --quiet
  ok "Armor: WS allow (prod origin)"

  # 2b) Allow WS from staging origin (priority 996)
  gcloud compute security-policies rules describe 996 --security-policy="$ARMOR_POLICY" >/dev/null 2>&1 \
    && gcloud compute security-policies rules update 996 --security-policy="$ARMOR_POLICY" \
         --action=allow --description="Allow WS from staging origin" \
         --expression="has(request.headers['upgrade']) && request.headers['upgrade'].lower() == 'websocket' && has(request.headers['origin']) && request.headers['origin'] == 'https://${DOMAIN_STG}'" --quiet \
    || gcloud compute security-policies rules create 996 --security-policy="$ARMOR_POLICY" \
         --action=allow --description="Allow WS from staging origin" \
         --expression="has(request.headers['upgrade']) && request.headers['upgrade'].lower() == 'websocket' && has(request.headers['origin']) && request.headers['origin'] == 'https://${DOMAIN_STG}'" --quiet
  ok "Armor: WS allow (staging origin)"

  # 2c) Optional baseline allows
  if [[ "$HARDEN_ARMOR_ALLOW_BASELINES" == "1" ]]; then
    gcloud compute security-policies rules describe 100 --security-policy="$ARMOR_POLICY" >/dev/null 2>&1 \
      || gcloud compute security-policies rules create 100 --security-policy="$ARMOR_POLICY" \
           --action=allow --description="Allow GET/HEAD root & /api/health" \
           --expression="(request.method == 'GET' || request.method == 'HEAD') && (request.path == '/' || request.path.startsWith('/api/health') || request.path == '/favicon.ico')" --quiet
    ok "Armor: allow GET/HEAD root & health (p100)"

    gcloud compute security-policies rules describe 110 --security-policy="$ARMOR_POLICY" >/dev/null 2>&1 \
      || gcloud compute security-policies rules create 110 --security-policy="$ARMOR_POLICY" \
           --action=allow --description="Allow JSON API requests ≤10MB" \
           --expression="request.method == 'POST' && request.path.startsWith('/api/') && has(request.headers['content-length']) && int(request.headers['content-length']) <= 10485760" --quiet
    ok "Armor: allow JSON API ≤10MB with size enforcement (p110)"
  fi

  # 2d) Default deny at max priority
  gcloud compute security-policies rules update 2147483647 \
    --security-policy="$ARMOR_POLICY" \
    --action=deny-403 --description="Default deny" --quiet
  ok "Armor: default deny enabled"
else
  warn "Security policy '$ARMOR_POLICY' not found; skipping WAF tweaks."
fi

# --- 3) Cloud Run ingress/IAM assertion (secure pair for LB)
ensure_run(){
  local svc="$1"
  # Ingress
  local ingress
  ingress="$(gcloud run services describe "$svc" --region="$REGION" \
              --format="value(spec.template.metadata.annotations['run.googleapis.com/ingress'])" 2>/dev/null || true)"
  if [[ "$ingress" != "internal-and-cloud-load-balancing" ]]; then
    gcloud run services update "$svc" --region="$REGION" \
      --ingress=internal-and-cloud-load-balancing --quiet
    ok "Run [$svc]: ingress set to internal-and-cloud-load-balancing"
  else
    ok "Run [$svc]: ingress already LB-only"
  fi

  # IAM (only if ingress is LB-only)
  ingress="$(gcloud run services describe "$svc" --region="$REGION" \
            --format="value(spec.template.metadata.annotations['run.googleapis.com/ingress'])" 2>/dev/null || true)"
  if [[ "$ingress" != "internal-and-cloud-load-balancing" ]]; then
    warn "Run [$svc]: ingress is not LB-only; NOT granting allUsers:run.invoker."
    return
  fi

  # Grant allUsers invoker if missing
  if ! gcloud run services get-iam-policy "$svc" --region="$REGION" --format=json \
      | grep -q '"role": "roles/run.invoker".*allUsers'; then
    gcloud run services add-iam-policy-binding "$svc" --region="$REGION" \
      --member="allUsers" --role="roles/run.invoker" --quiet
    ok "Run [$svc]: granted allUsers: roles/run.invoker"
  else
    ok "Run [$svc]: IAM already includes allUsers:run.invoker"
  fi
}

if [[ "$MANAGE_RUN_SETTINGS" == "1" ]]; then
  for SVC in "$SERVICE_PROD" "$SERVICE_STG"; do
    if gcloud run services describe "$SVC" --region="$REGION" >/dev/null 2>&1; then
      ensure_run "$SVC"
    else
      warn "Run service [$SVC] not found in $REGION; skipping."
    fi
  done
else
  warn "MANAGE_RUN_SETTINGS=0 (skipping ingress/IAM assertions)."
fi

ok "Hardening complete."
