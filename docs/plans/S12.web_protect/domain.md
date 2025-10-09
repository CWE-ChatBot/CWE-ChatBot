Here’s exactly how to put **cwe.crashedmind.com** in front of your Cloud Run Chainlit app with HTTPS, TLS, and the right headers. You don’t need a Cloud Run “custom domain mapping” when you use the External HTTPS Load Balancer—TLS terminates at the LB.

---

# Quick prerequisites

* Cloud project set (`gcloud config set project YOUR_PROJECT`).
* Your Cloud Run service (e.g. `cwe-chatbot`) is deployed and working on its default URL.
* You’re okay to host DNS either at your registrar or in **Cloud DNS** (both paths below).

I’ll use these variables (copy/paste the block and adjust if needed):

```bash
export PROJECT_ID="$(gcloud config get-value project)"
export REGION="us-central1"
export SERVICE="cwe-chatbot"          # your Cloud Run service name
export DOMAIN="cwe.crashedmind.com"   # the new host you want
export BACKEND_TIMEOUT="60"
```

---

# A) Create the HTTPS Load Balancer in front of Cloud Run

## 1) Serverless NEG → Backend Service

```bash
gcloud compute network-endpoint-groups create ${SERVICE}-neg \
  --region=$REGION \
  --network-endpoint-type=serverless \
  --cloud-run-service=$SERVICE

gcloud compute backend-services create ${SERVICE}-be \
  --global \
  --protocol=HTTPS \
  --timeout=${BACKEND_TIMEOUT}s

gcloud compute backend-services add-backend ${SERVICE}-be \
  --global \
  --network-endpoint-group=${SERVICE}-neg \
  --network-endpoint-group-region=$REGION
```

## 2) (Recommended) Security headers at the edge

```bash
gcloud compute response-headers-policies create ${SERVICE}-headers \
  --description="Security headers for Chainlit" \
  --custom-response-headers="Content-Security-Policy: default-src 'self'; connect-src 'self' https://${DOMAIN} wss://${DOMAIN}; img-src 'self' data: https:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'" \
  --custom-response-headers="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" \
  --custom-response-headers="X-Content-Type-Options: nosniff" \
  --custom-response-headers="X-Frame-Options: DENY" \
  --custom-response-headers="Referrer-Policy: no-referrer" \
  --custom-response-headers="Cross-Origin-Resource-Policy: same-origin" \
  --custom-response-headers="Cross-Origin-Embedder-Policy: require-corp" \
  --custom-response-headers="Cross-Origin-Opener-Policy: same-origin"
```

## 3) URL map, certificate, HTTPS proxy, forwarding rule

```bash
# URL map
gcloud compute url-maps create ${SERVICE}-urlmap \
  --default-service=${SERVICE}-be

# Attach response headers
gcloud compute url-maps update ${SERVICE}-urlmap \
  --default-route-action=response-headers-policy=${SERVICE}-headers

# Google-managed cert for your host
gcloud compute ssl-certificates create ${SERVICE}-cert \
  --domains=${DOMAIN}

# HTTPS proxy
gcloud compute target-https-proxies create ${SERVICE}-https-proxy \
  --ssl-certificates=${SERVICE}-cert \
  --url-map=${SERVICE}-urlmap

# Global forwarding rule on 443 → get LB IP
gcloud compute forwarding-rules create ${SERVICE}-fr \
  --global \
  --target-https-proxy=${SERVICE}-https-proxy \
  --ports=443

# Save the IP to use in DNS
LB_IP=$(gcloud compute forwarding-rules list --global --filter="name=${SERVICE}-fr" --format="value(IPAddress)")
echo "Load Balancer IP: $LB_IP"
```

> The Google-managed cert will become **ACTIVE** after DNS is set and SNI resolves correctly (step B). It’s normal to see it pending until DNS propagates.

---

# B) Point DNS for **cwe.crashedmind.com** at the load balancer

You have two choices:

## Option 1 — Use your registrar’s DNS (fastest if you don’t want Cloud DNS)

Create an **A record** at your registrar:

* **Name**: `cwe`
* **Type**: `A`
* **Value**: `LB_IP` (from the command above)
* **TTL**: 300 (5 minutes) is fine

(Optional) If your registrar supports AAAA, you can skip it; Google LB IPv6 is automatic only when using Cloud DNS with IPv6 FR. Keeping just IPv4 is OK.

## Option 2 — Use Cloud DNS (if you prefer managing DNS in GCP)

```bash
# Create a public zone for crashedmind.com (do this once per domain)
gcloud dns managed-zones create crashedmind-zone \
  --dns-name="crashedmind.com." \
  --description="Public zone for crashedmind.com"

# Add A record for cwe.crashedmind.com → LB_IP
gcloud dns record-sets transaction start --zone=crashedmind-zone

gcloud dns record-sets transaction add $LB_IP \
  --zone=crashedmind-zone \
  --name="${DOMAIN}." \
  --type="A" \
  --ttl=300

gcloud dns record-sets transaction execute --zone=crashedmind-zone
```

> If you just created the zone, you must update **NS** records at your registrar to point to the Cloud DNS nameservers shown by:
>
> `gcloud dns managed-zones describe crashedmind-zone --format='value(nameServers)'`

---

# C) Lock Cloud Run ingress & set app origin

```bash
gcloud run services update ${SERVICE} \
  --region=$REGION \
  --ingress internal-and-cloud-load-balancing \
  --set-env-vars="PUBLIC_ORIGIN=https://${DOMAIN},CSP_MODE=compatible,HSTS_MAX_AGE=31536000"
```

* `PUBLIC_ORIGIN` lets your app build absolute URLs & enforce same-origin checks.
* With ingress locked, the direct Cloud Run URL won’t be reachable—traffic must come via the LB.

---

# D) Update OAuth redirect URIs (important)

In your Google/GitHub OAuth app configs, add:

* `https://cwe.crashedmind.com/auth/callback/google`
* `https://cwe.crashedmind.com/auth/callback/github`

(And ensure your app reads `PUBLIC_ORIGIN` when constructing redirect URIs.)

---

# E) Verify everything

**Watch the cert:**

```bash
gcloud compute ssl-certificates list --filter="name=${SERVICE}-cert"
# Wait for status: ACTIVE
```

**DNS:**

```bash
dig +short ${DOMAIN}            # should show LB_IP
```

**HTTPS & headers:**

```bash
curl -I https://${DOMAIN}/ | grep -E "HTTP/|Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options"
```

**WebSocket (basic handshake check):**

```bash
# If you have websocat installed locally:
websocat -v wss://${DOMAIN}/ws || true
# (Your app may require auth; you just want to see it resolves and attempts to handshake)
```

**App env sanity (from your logs):**

* Confirm `PUBLIC_ORIGIN=https://cwe.crashedmind.com` is visible in app env.
* Confirm your middleware logs (if any) show requests with the expected Host/Origin.

---

# F) Common gotchas & fixes

* **Cert stuck “PROVISIONING”**: Usually DNS not pointing to the LB yet, or propagation not finished. Use `dig` until it resolves globally.
* **Mixed content / CSP errors**: Ensure your app uses `wss://${DOMAIN}` for WebSocket and your CSP `connect-src` allows it (edge and app headers above do).
* **403s at LB** (if you later add Cloud Armor): check rule order (lowest priority number wins), and that `Origin`/`Host` headers match exactly.
* **Direct Cloud Run access blocked**: that’s expected after ingress is restricted—always go through `https://cwe.crashedmind.com`.

---

# G) Minimal app-side changes to recognize the new host

* Set `PUBLIC_ORIGIN` as shown.
* Keep (or add) your **security middleware** and **CSRF** pieces we discussed earlier; they’ll now see the correct `Origin`/`Host`.

---

That’s it. Once DNS propagates and the certificate turns **ACTIVE**, your app will be live at **[https://cwe.crashedmind.com](https://cwe.crashedmind.com)** with proper TLS, security headers, and origin pinning support.
