# Phase A: HTTPS Load Balancer - Implementation Complete

**Date**: 2025-10-09
**Status**: ✅ COMPLETE
**Based on**: [docs/plans/domain.md](./domain.md) Phase A + [docs/plans/ip.md](./ip.md)

---

## Summary

Successfully created External HTTPS Load Balancer infrastructure with **static IP** for `cwe.crashedmind.com`.

---

## Infrastructure Created

### 1. Static IPv4 Address
```bash
Resource: cwe-chatbot-ipv4
IP Address: 34.49.0.7
Type: Global Static External IPv4
Cost: Free (while attached to forwarding rule)
```

**Command Used**:
```bash
gcloud compute addresses create cwe-chatbot-ipv4 \
  --ip-version=IPV4 \
  --global
```

**Benefits**:
- ✅ IP won't change if load balancer is recreated
- ✅ DNS records remain stable
- ✅ TLS certificate validation won't be interrupted
- ✅ Safe to rebuild URL maps, proxies, backend services

### 2. Serverless Network Endpoint Group (NEG)
```bash
Resource: cwe-chatbot-neg
Region: us-central1
Type: Serverless
Target: Cloud Run service "cwe-chatbot"
```

**Command Used**:
```bash
gcloud compute network-endpoint-groups create cwe-chatbot-neg \
  --region=us-central1 \
  --network-endpoint-type=serverless \
  --cloud-run-service=cwe-chatbot
```

### 3. Backend Service
```bash
Resource: cwe-chatbot-be
Scope: Global
Load Balancing Scheme: EXTERNAL_MANAGED
Protocol: HTTP (auto-converted from HTTPS)
Timeout: 60 seconds
```

**Commands Used**:
```bash
# Note: Had to use EXTERNAL_MANAGED scheme to avoid port_name conflict
gcloud compute backend-services create cwe-chatbot-be \
  --global \
  --load-balancing-scheme=EXTERNAL_MANAGED

gcloud compute backend-services add-backend cwe-chatbot-be \
  --global \
  --network-endpoint-group=cwe-chatbot-neg \
  --network-endpoint-group-region=us-central1
```

**Issue Encountered & Resolution**:
- Initial attempt with `--protocol=HTTPS` auto-set `port_name=https`
- Serverless NEGs don't support port names
- Solution: Use `EXTERNAL_MANAGED` scheme which handles this correctly

### 4. URL Map
```bash
Resource: cwe-chatbot-urlmap
Default Service: cwe-chatbot-be
```

**Command Used**:
```bash
gcloud compute url-maps create cwe-chatbot-urlmap \
  --default-service=cwe-chatbot-be
```

### 5. SSL Certificate
```bash
Resource: cwe-chatbot-cert
Type: Google-managed
Domain: cwe.crashedmind.com
Status: PROVISIONING → will become ACTIVE after DNS
```

**Command Used**:
```bash
gcloud compute ssl-certificates create cwe-chatbot-cert \
  --domains=cwe.crashedmind.com
```

**Check Status**:
```bash
gcloud compute ssl-certificates list --filter='name=cwe-chatbot-cert'
```

### 6. HTTPS Proxy
```bash
Resource: cwe-chatbot-https-proxy
SSL Certificate: cwe-chatbot-cert
URL Map: cwe-chatbot-urlmap
```

**Command Used**:
```bash
gcloud compute target-https-proxies create cwe-chatbot-https-proxy \
  --ssl-certificates=cwe-chatbot-cert \
  --url-map=cwe-chatbot-urlmap
```

### 7. Global Forwarding Rule
```bash
Resource: cwe-chatbot-fr
Scope: Global
Static IP: cwe-chatbot-ipv4 (34.49.0.7)
Target: cwe-chatbot-https-proxy
Port: 443 (HTTPS)
```

**Commands Used**:
```bash
# First created with ephemeral IP, then recreated with static IP
gcloud compute forwarding-rules delete cwe-chatbot-fr --global --quiet

gcloud compute forwarding-rules create cwe-chatbot-fr \
  --global \
  --address=cwe-chatbot-ipv4 \
  --target-https-proxy=cwe-chatbot-https-proxy \
  --ports=443
```

---

## Response Headers Policy (Skipped)

**Note**: The `gcloud compute response-headers-policies` command is not available in the current gcloud SDK version.

**Mitigation**: Security headers will be added via application middleware as documented in:
- [Story S-12](../stories/S-12.CSRF-and-WebSocket-Security-Hardening.md)
- [S-12 Implementation Guide](./S-12-implementation-ready.md)

The application middleware will set:
- Content-Security-Policy
- Strict-Transport-Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Cross-Origin-* policies (COOP, COEP, CORP)

---

## Architecture Diagram

```
Internet (cwe.crashedmind.com)
         ↓
    34.49.0.7 (Static IP)
         ↓
Global Forwarding Rule (cwe-chatbot-fr)
    Port 443
         ↓
HTTPS Proxy (cwe-chatbot-https-proxy)
    ├─ SSL Certificate (cwe-chatbot-cert)
    └─ URL Map (cwe-chatbot-urlmap)
              ↓
      Backend Service (cwe-chatbot-be)
              ↓
      Serverless NEG (cwe-chatbot-neg)
         Region: us-central1
              ↓
      Cloud Run Service (cwe-chatbot)
```

---

## Verification Commands

### Check All Resources
```bash
# Static IP
gcloud compute addresses describe cwe-chatbot-ipv4 --global

# NEG
gcloud compute network-endpoint-groups describe cwe-chatbot-neg --region=us-central1

# Backend Service
gcloud compute backend-services describe cwe-chatbot-be --global

# URL Map
gcloud compute url-maps describe cwe-chatbot-urlmap

# SSL Certificate
gcloud compute ssl-certificates describe cwe-chatbot-cert

# HTTPS Proxy
gcloud compute target-https-proxies describe cwe-chatbot-https-proxy

# Forwarding Rule
gcloud compute forwarding-rules describe cwe-chatbot-fr --global
```

### Quick Status Check
```bash
export SERVICE="cwe-chatbot"

echo "=== Load Balancer Status ==="
echo ""
echo "Static IP:"
gcloud compute addresses list --global --filter="name=${SERVICE}-ipv4" \
  --format="table(name,address,status)"

echo ""
echo "SSL Certificate:"
gcloud compute ssl-certificates list --filter="name=${SERVICE}-cert" \
  --format="table(name,managed.status,managed.domainStatus)"

echo ""
echo "Forwarding Rule:"
gcloud compute forwarding-rules list --global --filter="name=${SERVICE}-fr" \
  --format="table(name,IPAddress,target)"
```

---

## Next Steps (Phases B-E)

### Phase B: DNS Configuration

**Required**: Create DNS A record pointing to the static IP

**Option 1 - At Your Registrar**:
```
Name: cwe.crashedmind.com
Type: A
Value: 34.49.0.7
TTL: 300
```

**Option 2 - Cloud DNS**:
```bash
# Create zone (if not exists)
gcloud dns managed-zones create crashedmind-zone \
  --dns-name="crashedmind.com." \
  --description="Public zone for crashedmind.com"

# Add A record
gcloud dns record-sets transaction start --zone=crashedmind-zone

gcloud dns record-sets transaction add 34.49.0.7 \
  --zone=crashedmind-zone \
  --name="cwe.crashedmind.com." \
  --type="A" \
  --ttl=300

gcloud dns record-sets transaction execute --zone=crashedmind-zone
```

**Verify DNS Propagation**:
```bash
dig +short cwe.crashedmind.com
# Should return: 34.49.0.7
```

### Phase C: Lock Cloud Run Ingress & Set PUBLIC_ORIGIN

**After DNS is propagated and certificate is ACTIVE**:

```bash
gcloud run services update cwe-chatbot \
  --region=us-central1 \
  --ingress internal-and-cloud-load-balancing \
  --set-env-vars="PUBLIC_ORIGIN=https://cwe.crashedmind.com,CSP_MODE=compatible,HSTS_MAX_AGE=31536000"
```

**What this does**:
- Blocks direct access to `*.run.app` URL (traffic must go through LB)
- Sets `PUBLIC_ORIGIN` for app to build correct URLs
- Configures CSP and HSTS settings

### Phase D: Update OAuth Redirect URIs

**In Google OAuth Console**:
- Add: `https://cwe.crashedmind.com/auth/callback/google`

**In GitHub OAuth App**:
- Add: `https://cwe.crashedmind.com/auth/callback/github`

**Ensure app reads `PUBLIC_ORIGIN`** for constructing redirect URIs.

### Phase E: Verify Deployment

**1. Wait for Certificate**:
```bash
# Check every few minutes until ACTIVE
watch -n 60 'gcloud compute ssl-certificates list --filter="name=cwe-chatbot-cert"'
```

**2. Test HTTPS Endpoint**:
```bash
curl -I https://cwe.crashedmind.com/
# Expect: 200 OK

# Check security headers (will be present after app middleware deployed)
curl -I https://cwe.crashedmind.com/ | grep -E "Content-Security-Policy|Strict-Transport-Security"
```

**3. Test DNS**:
```bash
dig +short cwe.crashedmind.com
# Should return: 34.49.0.7

nslookup cwe.crashedmind.com
# Should show IP: 34.49.0.7
```

**4. Test OAuth Flow**:
- Navigate to `https://cwe.crashedmind.com`
- Click "Sign in with Google" or "Sign in with GitHub"
- Verify successful authentication

---

## Troubleshooting

### Certificate Stuck in PROVISIONING

**Problem**: SSL certificate shows `PROVISIONING` for more than 1 hour

**Causes**:
- DNS not pointing to load balancer IP yet
- DNS propagation not complete globally

**Solution**:
```bash
# Verify DNS is resolving
dig +short cwe.crashedmind.com

# Check from multiple locations
# Use: https://dnschecker.org/

# Check certificate status details
gcloud compute ssl-certificates describe cwe-chatbot-cert \
  --format="yaml(managed)"
```

### Direct Cloud Run URL Still Accessible

**Problem**: Can still access `https://cwe-chatbot-*.run.app` directly

**Cause**: Cloud Run ingress not yet restricted

**Solution**: Only restrict ingress in Phase C, after DNS and certificate are working

### 403 Forbidden from Load Balancer

**Possible Causes**:
1. Cloud Armor rules not yet configured (this is OK for Phase A)
2. Backend service unhealthy

**Check Backend Health**:
```bash
gcloud compute backend-services get-health cwe-chatbot-be --global
```

### Static IP Not in Use

**Problem**: Forwarding rule created but static IP shows "RESERVED" not "IN_USE"

**Check**:
```bash
gcloud compute addresses list --global --filter="name=cwe-chatbot-ipv4"
```

**Solution**: Ensure forwarding rule is using `--address=cwe-chatbot-ipv4` parameter

---

## Cost Breakdown

| Resource | Cost | Notes |
|----------|------|-------|
| Static IPv4 Address | **$0/month** | Free while attached to forwarding rule |
| Load Balancer | ~$18/month | First 5 forwarding rules |
| SSL Certificate | **$0/month** | Google-managed certs are free |
| Serverless NEG | **$0/month** | Free with Cloud Run |
| Backend Service | Included in LB | No separate charge |

**Estimated Monthly Cost**: ~$18 (just for the load balancer itself)

---

## Related Documentation

- **Phase A Source**: [docs/plans/domain.md](./domain.md#a-create-the-https-load-balancer-in-front-of-cloud-run)
- **Static IP Rationale**: [docs/plans/ip.md](./ip.md)
- **Story S-12**: [docs/stories/S-12.CSRF-and-WebSocket-Security-Hardening.md](../stories/S-12.CSRF-and-WebSocket-Security-Hardening.md)
- **Implementation Guide**: [docs/plans/S-12-implementation-ready.md](./S-12-implementation-ready.md)

---

## Change Log

| Date | Action | Resource | Notes |
|------|--------|----------|-------|
| 2025-10-09 | Created | cwe-chatbot-ipv4 | Static IPv4: 34.49.0.7 |
| 2025-10-09 | Created | cwe-chatbot-neg | Serverless NEG in us-central1 |
| 2025-10-09 | Created | cwe-chatbot-be | Backend service with EXTERNAL_MANAGED |
| 2025-10-09 | Created | cwe-chatbot-urlmap | URL map with default backend |
| 2025-10-09 | Created | cwe-chatbot-cert | SSL cert for cwe.crashedmind.com (PROVISIONING) |
| 2025-10-09 | Created | cwe-chatbot-https-proxy | HTTPS proxy with SSL cert |
| 2025-10-09 | Created | cwe-chatbot-fr | Forwarding rule on port 443 using static IP |
| 2025-10-09 | Deleted | cwe-chatbot-fr | Removed ephemeral forwarding rule |
| 2025-10-09 | Recreated | cwe-chatbot-fr | With static IP (34.49.0.7) |

---

## Summary

✅ Phase A Complete - HTTPS Load Balancer infrastructure created with static IP
⏭️ Ready for Phase B - DNS Configuration

**Load Balancer IP**: `34.49.0.7` (permanent, won't change)

**Next Action**: Create DNS A record for `cwe.crashedmind.com` → `34.49.0.7`
