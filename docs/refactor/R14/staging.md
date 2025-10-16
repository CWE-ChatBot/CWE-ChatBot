With your existing LB, the clean way to split prod vs staging is host-based routing:

Prod: cwe.crashedmind.com → backend cwe-chatbot-be (Cloud Run service cwe-chatbot)

Staging: staging-cwe.crashedmind.com → backend cwe-chatbot-staging-be (Cloud Run service cwe-chatbot-staging)

The LB uses the Host/SNI to tell them apart; both hostnames can share the same global IP. Below are exact, copy-paste commands to add staging safely.

1) Create a serverless NEG for the staging service
PROJECT=cwechatbot
REGION=us-central1
SERVICE=cwe-chatbot-staging

gcloud config set project $PROJECT

gcloud compute network-endpoint-groups create cwe-chatbot-staging-neg \
  --region=$REGION \
  --network-endpoint-type=serverless \
  --cloud-run-service=$SERVICE

2) Create a staging backend service and attach the NEG
gcloud compute backend-services create cwe-chatbot-staging-be \
  --global \
  --load-balancing-scheme=EXTERNAL_MANAGED \
  --protocol=HTTPS

gcloud compute backend-services add-backend cwe-chatbot-staging-be \
  --global \
  --network-endpoint-group=cwe-chatbot-staging-neg \
  --network-endpoint-group-region=$REGION


(Optional) Attach the same Cloud Armor policy you use for prod, or a stricter staging policy:

# reuse existing armor
gcloud compute backend-services update cwe-chatbot-staging-be \
  --global \
  --security-policy=cwe-chatbot-armor

3) Add TLS for the staging host

Best practice: create an additional managed cert just for staging-cwe.crashedmind.com and attach it alongside your prod cert.

DOMAIN_STG=staging-cwe.crashedmind.com
PROXY=cwe-chatbot-https-proxy

# Create a managed cert for staging
gcloud compute ssl-certificates create cert-staging-cwe \
  --domains=$DOMAIN_STG

# Get the currently attached cert(s) so we don't drop prod by accident
CURR_CERTS=$(gcloud compute target-https-proxies describe $PROXY \
  --format="value(sslCertificates[])")

# Attach BOTH the existing cert(s) and the new staging cert
gcloud compute target-https-proxies update $PROXY \
  --ssl-certificates=$CURR_CERTS,cert-staging-cwe


Managed cert will show PROVISIONING until DNS is in place; that’s fine.

4) Update the URL map to route the staging host

Your URL map is cwe-chatbot-urlmap. We’ll add a path matcher for staging and a host rule that points that hostname to the staging backend.

URLMAP=cwe-chatbot-urlmap

# Create a path matcher whose default service is the staging backend
gcloud compute url-maps add-path-matcher $URLMAP \
  --path-matcher-name=pm-staging \
  --default-service=cwe-chatbot-staging-be

# Route the staging hostname to that matcher
gcloud compute url-maps add-host-rule $URLMAP \
  --hosts=staging-cwe.crashedmind.com \
  --path-matcher-name=pm-staging


(Prod remains on the existing defaultService: cwe-chatbot-be.)

5) DNS: point the staging name at the LB IP

Find your existing global IP (you already saw 34.49.0.7):

gcloud compute forwarding-rules list --global --filter="name~cwe-chatbot-fr" \
  --format="value(IPAddress)"


Create an A record:

staging-cwe.crashedmind.com  A  34.49.0.7


Once DNS propagates, the managed cert will go ACTIVE automatically.

How the LB “identifies” prod vs staging

The LB uses the Host header (and TLS SNI) to match a hostRule in the URL map.

If Host: staging-cwe.crashedmind.com → pm-staging → cwe-chatbot-staging-be.

If Host: cwe.crashedmind.com (or anything else) → defaultService (prod).

In your upstream app and Cloud Run logs, you’ll also see X-Forwarded-Host/Host, so you can filter by environment in logging/metrics.

Test safely before DNS cut-in

You can validate the new path with --resolve (sends the Host header, skips DNS):

LB_IP=34.49.0.7

# Health check (expects 200)
curl -i --resolve staging-cwe.crashedmind.com:443:$LB_IP \
  https://staging-cwe.crashedmind.com/api/health

# OAuth-only API call (use a real Google ID token or GitHub access token)
ID_TOKEN="<paste from device flow>"
curl -s --resolve staging-cwe.crashedmind.com:443:$LB_IP \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"What is CWE-79?","persona":"DEVELOPER"}' \
  https://staging-cwe.crashedmind.com/api/v1/query


When using the LB hostname, you do not need a Cloud Run ID token — only your OAuth Bearer token (Google/GitHub), which your app already validates.

Rollback (if needed)
# Remove staging host rule and matcher
gcloud compute url-maps remove-host-rule $URLMAP --hosts=staging-cwe.crashedmind.com
gcloud compute url-maps remove-path-matcher $URLMAP --path-matcher-name=pm-staging

# (Optional) detach/remove staging backend
gcloud compute backend-services delete cwe-chatbot-staging-be --global
gcloud compute network-endpoint-groups delete cwe-chatbot-staging-neg --region=$REGION
# (Optional) remove staging cert from proxy AFTER it’s unused
# 1) get current certs, 2) update proxy without cert-staging-cwe, 3) delete cert

Headless/browser/API access (OAuth-only)

Browser: go to https://staging-cwe.crashedmind.com and login via Google/GitHub.

Python Playwright / Puppeteer / curl: use your device-flow token and send

Authorization: Bearer <token>


exactly like production; no special staging keys, no Cloud Run ID token when using the LB host.

If you want, I can fold steps 1–4 into a single idempotent bash task that checks for existing resources and only creates what’s missing, so staging exposure is a one-liner.



===================================================================
here’s a single, idempotent bash script that wires your existing load balancer to your staging Cloud Run service using host-based routing. It safely:

creates/updates a serverless NEG → cwe-chatbot-staging-neg

creates/updates a staging backend service → cwe-chatbot-staging-be

(re)attaches your Cloud Armor policy (configurable, defaults to prod one)

adds a managed TLS cert for staging-cwe.crashedmind.com and keeps existing certs

updates the URL map cwe-chatbot-urlmap to route the staging hostname to the staging backend

leaves prod untouched

gives you curl tests (with --resolve) so you can verify before DNS cutover




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

# 2) Backend service for staging (HTTPS, external managed)
if gcloud compute backend-services describe "$BE_STG" --global --quiet >/dev/null 2>&1; then
  ok "Backend service exists: $BE_STG"
else
  gcloud compute backend-services create "$BE_STG" \
    --global \
    --load-balancing-scheme=EXTERNAL_MANAGED \
    --protocol=HTTPS \
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






Short version: because a URL map can only point to a backend service, not directly to a NEG.
Your serverless NEG (which represents the Cloud Run service) must be attached to a backend service, and then the URL map routes to that backend service.

How GCLB is wired (for serverless)
Client (Host: staging-cwe…) ─▶ HTTPS LB
  URL Map  ──(host/path)──▶  Backend Service  ──▶  Serverless NEG  ──▶ Cloud Run svc
                                                (cwe-chatbot-staging-neg)   (cwe-chatbot-staging)


URL map rules choose backend services (field: defaultService / path matchers).

Backend service holds one or more backends (your serverless NEG).

A NEG can’t be referenced by the URL map directly.

Why a separate staging-be is helpful (and typical)

Lets host staging-cwe… route only to the staging NEG, while prod routes to the prod NEG.

Lets you attach different Cloud Armor policies, timeouts, logging/CDN settings per env.

Keeps blast radius small—you can change or drain staging independently.

Your plan, in GCLB terms

cwe-chatbot-be → attached to cwe-chatbot-neg (Cloud Run: cwe-chatbot)

cwe-chatbot-staging-be → attached to cwe-chatbot-staging-neg (Cloud Run: cwe-chatbot-staging)

URL map:

host staging-cwe.crashedmind.com → pathMatcher pm-staging → cwe-chatbot-staging-be

default (e.g., cwe.crashedmind.com) → cwe-chatbot-be

There isn’t a supported way to have a URL map send traffic directly to a NEG or “pick one backend inside a backend service” by host. So yes—you do need a staging backend service as the routing target.






here's an error with the backend service protocol. For serverless NEGs, we need to use HTTP protocol, not HTTPS. Let me fix the script:
Edit expose_staging_via_lb.sh
⎿
Now we need to delete the incorrectly created backend service and run the script again:
ChatGPT said:

Good catch — for serverless NEGs (Cloud Run) the backend service protocol must be HTTP. TLS terminates at the HTTPS proxy; the LB forwards HTTP to the serverless NEG.

Here’s exactly how to fix what’s already in place and make the script idempotent going forward.

A) One-time cleanup & recreate with the right protocol

Use these if you already created cwe-chatbot-staging-be with HTTPS and hit the error.

# Vars (adjust if you used different names)
PROJECT=cwechatbot
REGION=us-central1
URLMAP=cwe-chatbot-urlmap
DOMAIN_STG=staging-cwe.crashedmind.com
NEG_STG=cwe-chatbot-staging-neg
BE_STG=cwe-chatbot-staging-be
ARMOR_POLICY=cwe-chatbot-armor

gcloud config set project $PROJECT --quiet

# 1) If URL map references the bad backend, remove the staging host rule & matcher
gcloud compute url-maps remove-host-rule $URLMAP --hosts=$DOMAIN_STG --quiet || true
gcloud compute url-maps remove-path-matcher $URLMAP --path-matcher-name=pm-staging --quiet || true

# 2) Delete the incorrectly created backend service (HTTPS)
gcloud compute backend-services delete $BE_STG --global --quiet || true

# 3) Recreate the backend service with the CORRECT protocol (HTTP)
gcloud compute backend-services create $BE_STG \
  --global \
  --load-balancing-scheme=EXTERNAL_MANAGED \
  --protocol=HTTP \
  --quiet

# 4) Attach the serverless NEG to the backend
gcloud compute backend-services add-backend $BE_STG \
  --global \
  --network-endpoint-group=$NEG_STG \
  --network-endpoint-group-region=$REGION \
  --quiet

# 5) Re-attach Cloud Armor (optional but recommended)
gcloud compute backend-services update $BE_STG \
  --global \
  --security-policy=$ARMOR_POLICY \
  --quiet || true

# 6) Recreate the path matcher & host rule for staging
gcloud compute url-maps add-path-matcher $URLMAP \
  --path-matcher-name=pm-staging \
  --default-service=$BE_STG \
  --quiet

gcloud compute url-maps add-host-rule $URLMAP \
  --hosts=$DOMAIN_STG \
  --path-matcher-name=pm-staging \
  --quiet


You can now test with --resolve and then set DNS as planned.

B) Patch the script to be correct (protocol=HTTP) and self-heal

Update your tools/expose_staging_via_lb.sh (or whatever you named it) so it creates the backend with HTTP and auto-migrates if it finds an existing HTTPS backend.

- gcloud compute backend-services create "$BE_STG" \
-   --global \
-   --load-balancing-scheme=EXTERNAL_MANAGED \
-   --protocol=HTTPS \
-   --quiet
+ gcloud compute backend-services create "$BE_STG" \
+   --global \
+   --load-balancing-scheme=EXTERNAL_MANAGED \
+   --protocol=HTTP \
+   --quiet


Optionally add this protocol self-heal block after your “backend exists” check:

# Ensure backend protocol is HTTP for serverless NEGs
CUR_PROTO=$(gcloud compute backend-services describe "$BE_STG" --global --format='value(protocol)' || echo '')
if [[ "$CUR_PROTO" == "HTTPS" ]]; then
  warn "Backend $BE_STG is HTTPS; migrating to HTTP for serverless NEG."

  # Remove staging routing temporarily (to unlock deletion)
  gcloud compute url-maps remove-host-rule "$URLMAP" --hosts="$DOMAIN_STG" --quiet || true
  gcloud compute url-maps remove-path-matcher "$URLMAP" --path-matcher-name=pm-staging --quiet || true

  # Recreate backend with HTTP
  gcloud compute backend-services delete "$BE_STG" --global --quiet || true
  gcloud compute backend-services create "$BE_STG" \
    --global \
    --load-balancing-scheme=EXTERNAL_MANAGED \
    --protocol=HTTP \
    --quiet

  gcloud compute backend-services add-backend "$BE_STG" \
    --global \
    --network-endpoint-group="$NEG_STG" \
    --network-endpoint-group-region="$REGION" \
    --quiet

  gcloud compute backend-services update "$BE_STG" \
    --global \
    --security-policy="$ARMOR_POLICY" \
    --quiet || true

  # Recreate matcher & host rule
  gcloud compute url-maps add-path-matcher "$URLMAP" \
    --path-matcher-name=pm-staging \
    --default-service="$BE_STG" \
    --quiet
  gcloud compute url-maps add-host-rule "$URLMAP" \
    --hosts="$DOMAIN_STG" \
    --path-matcher-name=pm-staging \
    --quiet

  ok "Migrated $BE_STG to protocol HTTP and restored routing."
fi

Why HTTP here?

TLS terminates at the Target HTTPS Proxy (your LB).

Between the LB and a serverless NEG (Cloud Run), the correct/only supported backend protocol is HTTP.

Security is still end-to-end: public internet → HTTPS LB (TLS) → Google’s backbone → Cloud Run.

Quick verification
LB_IP=$(gcloud compute forwarding-rules list --global --filter='name~https' --format='value(IPAddress)' | head -n1)

# Health
curl -i --resolve staging-cwe.crashedmind.com:443:$LB_IP \
  https://staging-cwe.crashedmind.com/api/health

# OAuth-only API (use your Google ID token or GitHub access token)
ID_TOKEN="<paste>"
curl -s --resolve staging-cwe.crashedmind.com:443:$LB_IP \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"CWE-79?","persona":"DEVELOPER"}' \
  https://staging-cwe.crashedmind.com/api/v1/query


You’re set — staging host routed via LB, HTTP backend to the serverless NEG, OAuth-only at the app, and Cloud Armor still protecting the edge.



==================================================================

Short answer: your setup is very close, but there are a few security nits to fix and one misconception to keep in mind.

Is this statement correct?

“Production has allUsers as run.invoker, which means --allow-unauthenticated. When using a load balancer with Cloud Armor, you want --allow-unauthenticated on Cloud Run because the security is enforced at the load balancer level, not at Cloud Run IAM.”

Yes — with an important caveat.

For External HTTPS LB → Serverless NEG (Cloud Run), Cloud Run must accept unauthenticated requests (LB does not present a Run IAM identity), so roles/run.invoker to allUsers (or --allow-unauthenticated) is expected.

To avoid bypassing the WAF/LB, you must pair this with ingress restriction on the Cloud Run service:
--ingress=internal-and-cloud-load-balancing.
That way, only traffic coming through the LB reaches Cloud Run; direct public hits to the Run URL are blocked by ingress (even though the service is “allow unauthenticated”).

So the secure combo is:

Cloud Run: allow unauthenticated AND ingress=internal-and-cloud-load-balancing.

Edge security & auth enforcement: Cloud Armor/WAF + your OAuth/Bearer in-app auth.

No direct public path to the Run URL.

Specific findings & recommended fixes
1) Backend protocol for serverless NEG

You already fixed this. ✅
For Cloud Run via serverless NEG, the backend service must be HTTP (TLS ends at the HTTPS proxy).

gcloud compute backend-services update cwe-chatbot-staging-be --global --protocol=HTTP

2) URL map default might have been overwritten

Your script output showed:

hostRules[0].hosts[0]:    *
hostRules[0].pathMatcher: pm-staging


This suggests the “catch-all” (*) host rule may now point to staging. That would unintentionally send unknown hosts to staging.

Fix: ensure default goes to prod:

# Make sure the URL map default service is the prod backend:
gcloud compute url-maps set-default-service cwe-chatbot-urlmap \
  --default-service=cwe-chatbot-be

# Keep host rule ONLY for staging host → staging path matcher:
gcloud compute url-maps add-host-rule cwe-chatbot-urlmap \
  --hosts=staging-cwe.crashedmind.com \
  --path-matcher-name=pm-staging

3) Cloud Armor WebSocket origin rule

You temporarily loosened origin matching to https://.*cwe\.crashedmind\.com. That’s workable, but tighter is better. Because Cloud Armor CEL doesn’t allow capture groups and has an expression complexity limit, the clean approach is two explicit allow rules:

# Allow prod WS origin
gcloud compute security-policies rules create 995 \
  --security-policy=cwe-chatbot-armor \
  --action=allow \
  --description="Allow WS from prod origin" \
  --expression='has(request.headers["upgrade"]) && request.headers["upgrade"].lower() == "websocket" && has(request.headers["origin"]) && request.headers["origin"] == "https://cwe.crashedmind.com"'

# Allow staging WS origin
gcloud compute security-policies rules create 996 \
  --security-policy=cwe-chatbot-armor \
  --action=allow \
  --description="Allow WS from staging origin" \
  --expression='has(request.headers["upgrade"]) && request.headers["upgrade"].lower() == "websocket" && has(request.headers["origin"]) && request.headers["origin"] == "https://staging-cwe.crashedmind.com"'


Keep your existing deny rules for other WS traffic at a higher priority number (i.e., lower precedence) than these allows.

4) Cloud Armor: default “allow all” → tighten it

Your policy ends with an allow-all at priority 2147483647. That defeats the purpose of a default-deny stance.

Hardened pattern (example):

Explicit allow for GET/HEAD health/HTML.

Explicit allow for POST /api/* with Content-Type: application/json and Content-Length <= 10MB.

Explicit allow for PDF worker path if routed via the same LB (content-type application/pdf, size cap).

Default: deny(403).

Commands (adapt names/paths as needed):

# Allow GET/HEAD to root and health
gcloud compute security-policies rules create 100 \
  --security-policy=cwe-chatbot-armor \
  --action=allow \
  --description="Allow GET/HEAD root & health" \
  --expression="request.method in ['GET','HEAD'] && re.match('/($|api/health|favicon\\.ico$)', request.path)"

# Allow JSON API up to 10MB
gcloud compute security-policies rules create 110 \
  --security-policy=cwe-chatbot-armor \
  --action=allow \
  --description="Allow JSON API <=10MB" \
  --expression="request.method == 'POST' && starts_with(request.path, '/api/') && has(request.headers['content-type']) && request.headers['content-type'].lower().startsWith('application/json') && int(request.headers['content-length']?:'0') <= 10485760"

# (Optional) Allow PDF uploads if sharing LB
# gcloud compute security-policies rules create 120 ...

# Final default deny
gcloud compute security-policies rules update 2147483647 \
  --security-policy=cwe-chatbot-armor \
  --action=deny-403 \
  --description="Default deny"


Order matters: ensure your explicit allows have lower numeric priorities (higher precedence) than the existing rate-limit rules you rely on.

5) CSP header points to prod origin in connect-src

Your earlier 200 HTML showed:

connect-src 'self' https://cwe.crashedmind.com wss://cwe.crashedmind.com;


On staging, this should reference staging (or simply 'self' for both HTTPS and WSS if same host). Otherwise, the browser will block API/WS connections.

Fix: make CSP host-aware (derive from PUBLIC_ORIGIN or request host). For Chainlit/your app, set:

PUBLIC_ORIGIN=https://staging-cwe.crashedmind.com

Generate CSP like:

connect-src 'self' https://staging-cwe.crashedmind.com wss://staging-cwe.crashedmind.com;


or simply:

connect-src 'self';


if all calls are same-origin.

6) Keep Cloud Run ingress constrained

For both prod and staging services:

# Ensure only LB can reach the service (no direct public bypass)
gcloud run services update cwe-chatbot --region=us-central1 \
  --ingress=internal-and-cloud-load-balancing

gcloud run services update cwe-chatbot-staging --region=us-central1 \
  --ingress=internal-and-cloud-load-balancing


You can keep allUsers as invoker; ingress will still block any direct hits that do not come via the LB.

7) Backend timeouts (optional hardening)

Default serverless NEG backend timeout is 30s. If your endpoints can legitimately take longer (e.g., LLM calls), bump it to 60s but avoid masking timeouts:

gcloud compute backend-services update cwe-chatbot-staging-be \
  --global --timeout=60

8) Rate limiting by user (at app) + armor baseline

You already have Armor baseline rate limit rules; keep them.

In app, continue doing per-user rate limits using the OAuth identity (email/login) → headers like X-RateLimit-* in responses.

9) Logs & tokens

Keep OAuth tokens out of logs; log only provider + user id (email/login) + last 4 chars if you need correlation.

Ensure LB/Armor logs are enabled and retained per your policy.

TL;DR checklist

 Cloud Run allow unauthenticated and --ingress=internal-and-cloud-load-balancing.

 Backend service protocol is HTTP.

 URL map default service = prod backend; staging host rule points to staging.

 Cloud Armor:

 Add explicit allow for prod & staging WS origins (two rules).

 Add explicit allow for expected methods/paths/content-types; size caps.

 Change final rule to deny by default.

 CSP “connect-src” uses staging host (or 'self').

 Optional: backend timeout tuned, per-user rate limits in app.

If you want, I can produce a small patch to your expose_staging_via_lb.sh that (1) asserts the URL map default is prod, and (2) adds the two precise WS allow rules and flips the default deny._





===========================================================

Awesome — here’s a tight, idempotent patch to your tools/expose_staging_via_lb.sh that:

Forces URL-map default to prod (so * won’t route to staging by accident)

Adds two precise Cloud Armor allow rules for WebSocket origins (prod + staging)

Flips the final rule to default-deny (keeps your WAF meaningful)

I also included optional baseline allow rules (GET/HEAD root & health, JSON API ≤10MB) behind a toggle so you don’t accidentally lock yourself out.

Unified diff
--- a/tools/expose_staging_via_lb.sh
+++ b/tools/expose_staging_via_lb.sh
@@ -15,11 +15,15 @@
 PROJECT="${PROJECT:-cwechatbot}"
 REGION="${REGION:-us-central1}"
 SERVICE="${SERVICE:-cwe-chatbot-staging}"                 # Cloud Run staging service name
 URLMAP="${URLMAP:-cwe-chatbot-urlmap}"                    # existing URL map
 PROXY="${PROXY:-cwe-chatbot-https-proxy}"                 # existing target HTTPS proxy
 DOMAIN_STG="${DOMAIN_STG:-staging-cwe.crashedmind.com}"   # new staging host
 NEG_STG="${NEG_STG:-cwe-chatbot-staging-neg}"
 BE_STG="${BE_STG:-cwe-chatbot-staging-be}"
 ARMOR_POLICY="${ARMOR_POLICY:-cwe-chatbot-armor}"         # reuse prod policy by default
+# New: name of the existing PROD backend service (default from your config)
+BE_PROD="${BE_PROD:-cwe-chatbot-be}"
+# Optional: also add baseline allow rules (health, JSON API <=10MB)
+HARDEN_ARMOR_ALLOW_BASELINES="${HARDEN_ARMOR_ALLOW_BASELINES:-1}"
 
 # Pretty
 GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
 ok(){ echo -e "${GREEN}✓${NC} $*"; }
 warn(){ echo -e "${YELLOW}⚠${NC} $*"; }
 err(){ echo -e "${RED}✗${NC} $*"; }
@@ -58,9 +62,9 @@
   ok "NEG created: $NEG_STG → Cloud Run service '$SERVICE'"
 fi
 
-# 2) Backend service for staging (HTTPS, external managed)
+# 2) Backend service for staging (HTTP, external managed) — serverless NEGs require HTTP
 if gcloud compute backend-services describe "$BE_STG" --global --quiet >/dev/null 2>&1; then
-  ok "Backend service exists: $BE_STG"
+  ok "Backend service exists: $BE_STG (will ensure protocol is HTTP)"
 else
   gcloud compute backend-services create "$BE_STG" \
     --global \
     --load-balancing-scheme=EXTERNAL_MANAGED \
-    --protocol=HTTPS \
+    --protocol=HTTP \
     --quiet
   ok "Backend service created: $BE_STG"
 fi
@@ -95,6 +99,22 @@
   warn "Cloud Armor policy '$ARMOR_POLICY' not found; skipping WAF attach."
 fi
 
+# 2c) Ensure URL map DEFAULT goes to PROD backend (avoid '*' routing to staging)
+DEFAULT_BE=$(gcloud compute url-maps describe "$URLMAP" --format="value(defaultService)" 2>/dev/null || true)
+if [[ "$DEFAULT_BE" != *"/backendServices/$BE_PROD" ]]; then
+  gcloud compute url-maps set-default-service "$URLMAP" \
+    --default-service="$BE_PROD" --quiet
+  ok "URL map default service set to PROD: $BE_PROD"
+else
+  ok "URL map default already points to PROD: $BE_PROD"
+fi
+
+# Reaffirm host rule for staging host → staging matcher
+# (existing code keeps this idempotent)
+
 # 3) Managed TLS certificate for staging host (attach alongside existing certs)
 if gcloud compute ssl-certificates describe "cert-${DOMAIN_STG//./-}" --quiet >/dev/null 2>&1; then
   ok "Managed cert exists: cert-${DOMAIN_STG//./-}"
 else
@@ -143,6 +163,66 @@
 ok "Host rule added: $DOMAIN_STG → pm-staging → $BE_STG"
 
 # 5) Tell user the LB IP and DNS step
 LB_IP=$(gcloud compute forwarding-rules list --global --format="value(IPAddress)" | head -n1)
 if [[ -z "${LB_IP:-}" ]]; then
   warn "Could not resolve LB IP automatically. Check your forwarding rules."
 else
   ok "Load balancer IP: $LB_IP"
   echo "Create an A record: ${DOMAIN_STG} → ${LB_IP}"
 fi
 
+# 5b) Cloud Armor hardening: precise WS allows (prod + staging) and default deny
+if gcloud compute security-policies describe "$ARMOR_POLICY" --quiet >/dev/null 2>&1; then
+  # Allow WS from PROD origin (priority 995)
+  if gcloud compute security-policies rules describe 995 --security-policy="$ARMOR_POLICY" >/dev/null 2>&1; then
+    gcloud compute security-policies rules update 995 \
+      --security-policy="$ARMOR_POLICY" \
+      --action=allow \
+      --description="Allow WS from prod origin" \
+      --expression='has(request.headers["upgrade"]) && request.headers["upgrade"].lower() == "websocket" && has(request.headers["origin"]) && request.headers["origin"] == "https://cwe.crashedmind.com"' \
+      --quiet
+  else
+    gcloud compute security-policies rules create 995 \
+      --security-policy="$ARMOR_POLICY" \
+      --action=allow \
+      --description="Allow WS from prod origin" \
+      --expression='has(request.headers["upgrade"]) && request.headers["upgrade"].lower() == "websocket" && has(request.headers["origin"]) && request.headers["origin"] == "https://cwe.crashedmind.com"' \
+      --quiet
+  fi
+  ok "Cloud Armor: WS allow (prod origin)"
+
+  # Allow WS from STAGING origin (priority 996)
+  if gcloud compute security-policies rules describe 996 --security-policy="$ARMOR_POLICY" >/dev/null 2>&1; then
+    gcloud compute security-policies rules update 996 \
+      --security-policy="$ARMOR_POLICY" \
+      --action=allow \
+      --description="Allow WS from staging origin" \
+      --expression="has(request.headers[\"upgrade\"]) && request.headers[\"upgrade\"].lower() == \"websocket\" && has(request.headers[\"origin\"]) && request.headers[\"origin\"] == \"https://${DOMAIN_STG}\"" \
+      --quiet
+  else
+    gcloud compute security-policies rules create 996 \
+      --security-policy="$ARMOR_POLICY" \
+      --action=allow \
+      --description="Allow WS from staging origin" \
+      --expression="has(request.headers[\"upgrade\"]) && request.headers[\"upgrade\"].lower() == \"websocket\" && has(request.headers[\"origin\"]) && request.headers[\"origin\"] == \"https://${DOMAIN_STG}\"" \
+      --quiet
+  fi
+  ok "Cloud Armor: WS allow (staging origin)"
+
+  # Optional baseline allows (safe defaults) — enable/disable via HARDEN_ARMOR_ALLOW_BASELINES
+  if [[ "$HARDEN_ARMOR_ALLOW_BASELINES" == "1" ]]; then
+    # Allow GET/HEAD root & health (priority 100)
+    gcloud compute security-policies rules describe 100 --security-policy="$ARMOR_POLICY" >/dev/null 2>&1 || \
+    gcloud compute security-policies rules create 100 \
+      --security-policy="$ARMOR_POLICY" --action=allow \
+      --description="Allow GET/HEAD root & /api/health" \
+      --expression="request.method in ['GET','HEAD'] && re.match('/($|api/health|favicon\\.ico$)', request.path)" --quiet
+    ok "Cloud Armor: allow GET/HEAD root & health"
+
+    # Allow JSON API <= 10MB (priority 110)
+    gcloud compute security-policies rules describe 110 --security-policy="$ARMOR_POLICY" >/dev/null 2>&1 || \
+    gcloud compute security-policies rules create 110 \
+      --security-policy="$ARMOR_POLICY" --action=allow \
+      --description="Allow JSON API <=10MB" \
+      --expression="request.method == 'POST' && starts_with(request.path, '/api/') && has(request.headers['content-type']) && request.headers['content-type'].lower().startsWith('application/json') && int(request.headers['content-length']?:'0') <= 10485760" --quiet
+    ok "Cloud Armor: allow JSON API <=10MB"
+  fi
+
+  # Default deny (priority max)
+  gcloud compute security-policies rules update 2147483647 \
+    --security-policy="$ARMOR_POLICY" \
+    --action=deny-403 \
+    --description="Default deny" --quiet
+  ok "Cloud Armor: default deny enabled"
+else
+  warn "Cloud Armor policy '$ARMOR_POLICY' not found; skipping WS/default-deny hardening."
+fi
+
 # 6) Quick test instructions
 cat <<EOF
 
 ${YELLOW}Next steps:${NC}
   1) Point DNS: ${DOMAIN_STG} → ${LB_IP} (same IP as prod).
@@ -157,6 +237,11 @@
   - Staging uses host-based routing via ${DOMAIN_STG}.
   - When using the LB hostname, clients only need ${YELLOW}OAuth Bearer tokens${NC}
     (Google ID token or GitHub access token). No Cloud Run ID token required.
 
+${YELLOW}Ingress reminder:${NC}
+  Ensure Cloud Run services use ingress restriction:
+    gcloud run services update cwe-chatbot --region=${REGION} --ingress=internal-and-cloud-load-balancing
+    gcloud run services update ${SERVICE} --region=${REGION} --ingress=internal-and-cloud-load-balancing
+
 Done.
 EOF

Why this patch matters

Prevents accidental staging takeover: explicitly pins URL-map default to prod.

Precise WS origin control: only allows WebSocket handshakes from prod and staging origins; leaves your existing WS-deny rules in place for everything else.

WAF actually enforces: final rule set to default-deny; optional baseline allows keep the site usable.

Still OAuth-only at the app layer; LB/WAF gate the edge; Cloud Run ingress blocks direct calls.

One-time sanity checks (run once)
# Make sure both services only accept LB traffic
gcloud run services update cwe-chatbot --region=us-central1 --ingress=internal-and-cloud-load-balancing
gcloud run services update cwe-chatbot-staging --region=us-central1 --ingress=internal-and-cloud-load-balancing

# Both services should be allow-unauthenticated (LB doesn’t present IAM identity)
gcloud run services add-iam-policy-binding cwe-chatbot --region=us-central1 \
  --member=allUsers --role=roles/run.invoker
gcloud run services add-iam-policy-binding cwe-chatbot-staging --region=us-central1 \
  --member=allUsers --role=roles/run.invoker


If you want me to also make the script auto-assert those ingress/iam settings (with a --manage-run-ingress flag) I can add that too.

You said:
can you explain this "script auto-assert those ingress/iam settings"
ChatGPT said:
Thought for 5s

Totally — by “script auto-assert those ingress/IAM settings” I mean:

Your LB script can also make sure each Cloud Run service is configured the safe way for LB usage:

Ingress is internal-and-cloud-load-balancing (so the direct Cloud Run URL can’t be hit from the public internet).

IAM has allUsers: roles/run.invoker (so the LB can reach the service without a Run identity).

If either is missing or drifted, the script fixes it (idempotently), so you don’t end up with a WAF/LB that’s “working” while traffic still bypasses it or is blocked by Run IAM.

Why both?

Cloud Run must be allow unauthenticated for LB ➜ Serverless NEG.

But that alone would expose the direct Run URL, unless you also restrict ingress to LB only.

So the secure pair is:

ingress=internal-and-cloud-load-balancing

allUsers: run.invoker

Drop-in patch for your script

This adds an opt-in flag MANAGE_RUN_SETTINGS=1 and safely asserts both settings for prod + staging. It refuses to grant allUsers if the service ingress is all (to avoid accidental public exposure).

--- a/tools/expose_staging_via_lb.sh
+++ b/tools/expose_staging_via_lb.sh
@@ -19,6 +19,12 @@
 BE_STG="${BE_STG:-cwe-chatbot-staging-be}"
 ARMOR_POLICY="${ARMOR_POLICY:-cwe-chatbot-armor}"         # reuse prod policy by default
 BE_PROD="${BE_PROD:-cwe-chatbot-be}"
 HARDEN_ARMOR_ALLOW_BASELINES="${HARDEN_ARMOR_ALLOW_BASELINES:-1}"
+# Manage Cloud Run ingress/IAM (safe defaults for LB)
+# Set to 1 to enable; default off to avoid surprises
+MANAGE_RUN_SETTINGS="${MANAGE_RUN_SETTINGS:-0}"
+# Cloud Run service names
+SERVICE_PROD="${SERVICE_PROD:-cwe-chatbot}"
+SERVICE_STG="${SERVICE_STG:-$SERVICE}"

@@ -34,6 +40,58 @@
 err(){ echo -e "${RED}✗${NC} $*"; }

 gcloud config set project "$PROJECT" --quiet >/dev/null

+# --- helpers: Cloud Run ingress/IAM assertion (safe for LB) ---
+ensure_run_settings() {
+  local svc="$1"
+  local region="$2"
+
+  # 1) Ensure ingress is internal-and-cloud-load-balancing
+  local curr_ingress
+  curr_ingress="$(gcloud run services describe "$svc" --region="$region" \
+      --format="value(spec.template.metadata.annotations['run.googleapis.com/ingress'])" 2>/dev/null || true)"
+  if [[ "$curr_ingress" != "internal-and-cloud-load-balancing" ]]; then
+    gcloud run services update "$svc" --region="$region" \
+      --ingress=internal-and-cloud-load-balancing --quiet
+    ok "Cloud Run [$svc]: ingress set to internal-and-cloud-load-balancing"
+  else
+    ok "Cloud Run [$svc]: ingress already internal-and-cloud-load-balancing"
+  fi
+
+  # 2) Ensure allUsers has roles/run.invoker (only if ingress is LB-only)
+  curr_ingress="$(gcloud run services describe "$svc" --region="$region" \
+      --format="value(spec.template.metadata.annotations['run.googleapis.com/ingress'])" 2>/dev/null || true)"
+  if [[ "$curr_ingress" != "internal-and-cloud-load-balancing" ]]; then
+    warn "Cloud Run [$svc]: ingress is not LB-only; refusing to grant allUsers:run.invoker to avoid public exposure."
+    return 0
+  fi
+
+  # Check IAM binding
+  if gcloud run services get-iam-policy "$svc" --region="$region" \
+      --format=json | jq -e '.bindings[]? | select(.role=="roles/run.invoker") | .members[]? | select(.=="allUsers")' >/dev/null 2>&1; then
+    ok "Cloud Run [$svc]: IAM already includes allUsers: roles/run.invoker"
+  else
+    gcloud run services add-iam-policy-binding "$svc" --region="$region" \
+      --member="allUsers" --role="roles/run.invoker" --quiet
+    ok "Cloud Run [$svc]: granted allUsers: roles/run.invoker (LB can call it)"
+  fi
+}
+
+if [[ "$MANAGE_RUN_SETTINGS" == "1" ]]; then
+  # Verify services exist before touching them
+  for SVC in "$SERVICE_PROD" "$SERVICE_STG"; do
+    if gcloud run services describe "$SVC" --region="$REGION" >/dev/null 2>&1; then
+      ensure_run_settings "$SVC" "$REGION"
+    else
+      warn "Cloud Run service [$SVC] not found in region [$REGION]; skipping."
+    fi
+  done
+fi
+
 # 0) Pre-flight checks
 if ! gcloud compute url-maps describe "$URLMAP" --quiet >/dev/null 2>&1; then
   err "URL map '$URLMAP' not found. Aborting."

How to use it
chmod +x tools/expose_staging_via_lb.sh

# Run with auto-assert enabled
PROJECT=cwechatbot \
REGION=us-central1 \
SERVICE=cwe-chatbot-staging \
SERVICE_PROD=cwe-chatbot \
URLMAP=cwe-chatbot-urlmap \
PROXY=cwe-chatbot-https-proxy \
DOMAIN_STG=staging-cwe.crashedmind.com \
ARMOR_POLICY=cwe-chatbot-armor \
MANAGE_RUN_SETTINGS=1 \
./tools/expose_staging_via_lb.sh

What it guarantees (idempotently)

Prod + Staging Cloud Run

ingress=internal-and-cloud-load-balancing

allUsers: roles/run.invoker only if ingress is LB-only

You can still override service names via SERVICE_PROD / SERVICE_STG.

It won’t break if a service is missing; it just skips with a warning.

Safety notes

If you intentionally test via the direct Cloud Run URL, temporarily set:

ingress=all and remove allUsers or keep allUsers (public) if you’re okay with exposure.

The helper won’t grant allUsers while ingress is all (to prevent accidental public access).

With LB in front + OAuth-only in the app + Cloud Armor default-deny, this is a solid defense-in-depth posture.

You said:
ok but I ran the expose_staging_via_lb.sh script already.
so is it better to have a new script to make the changes
ChatGPT said:
Thought for 13s

Yep — at this point it’s cleaner to add a small, separate “hardening” script rather than re-running the big wiring script. This keeps responsibilities split:

expose_staging_via_lb.sh → creates/updates NEG, backend, cert, URL-map host rule.

harden_lb_and_run.sh (new) → asserts security posture: URL-map default→prod, WAF rules, Cloud Run ingress/IAM.

Here’s a drop-in, idempotent hardening script you can run anytime after wiring.

tools/harden_lb_and_run.sh
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
if ! gcloud compute url-maps describe "$URLMAP" --format='value(hostRules[].hosts)' | tr ';,' '\n' | grep -qx "$DOMAIN_STG"; then
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
           --expression="request.method in ['GET','HEAD'] && re.match('/($|api/health|favicon\\.ico$)', request.path)" --quiet
    ok "Armor: allow GET/HEAD root & health (p100)"

    gcloud compute security-policies rules describe 110 --security-policy="$ARMOR_POLICY" >/dev/null 2>&1 \
      || gcloud compute security-policies rules create 110 --security-policy="$ARMOR_POLICY" \
           --action=allow --description="Allow JSON API <=10MB" \
           --expression="request.method == 'POST' && starts_with(request.path, '/api/') && has(request.headers['content-type']) && request.headers['content-type'].lower().startsWith('application/json') && int(request.headers['content-length']?:'0') <= 10485760" --quiet
    ok "Armor: allow JSON API <=10MB (p110)"
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

How to run
chmod +x tools/harden_lb_and_run.sh

# usually these defaults are fine:
PROJECT=cwechatbot \
REGION=us-central1 \
URLMAP=cwe-chatbot-urlmap \
PROXY=cwe-chatbot-https-proxy \
BE_PROD=cwe-chatbot-be \
BE_STG=cwe-chatbot-staging-be \
SERVICE_PROD=cwe-chatbot \
SERVICE_STG=cwe-chatbot-staging \
DOMAIN_PROD=cwe.crashedmind.com \
DOMAIN_STG=staging-cwe.crashedmind.com \
ARMOR_POLICY=cwe-chatbot-armor \
HARDEN_ARMOR_ALLOW_BASELINES=1 \
MANAGE_RUN_SETTINGS=1 \
tools/harden_lb_and_run.sh

What it does (safely, idempotently)

Pins URL-map default to prod backend (prevents * from drifting to staging).

Adds explicit WS allow rules for prod & staging origins; keeps everything else blocked by your existing WS denies.

(Optionally) allows GET/HEAD basics and JSON API <=10MB; flips final rule to default-deny.

Ensures Cloud Run ingress = internal-and-cloud-load-balancing and allUsers:run.invoker (only when ingress is LB-only) for both services.

This keeps your earlier wiring intact and just “locks down” posture, without re-creating NEGs/backends/certs.