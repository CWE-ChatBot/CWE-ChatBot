the HTTPS Load Balancer can allocate an ephemeral anycast IP.
But for production you should reserve a global static IP so your DNS (and TLS certs) don’t break if you recreate the LB.

Why a static IP is recommended

Stable DNS: Your cwe.crashedmind.com A/AAAA records point to a fixed address.

TLS cert continuity: Google-managed certs validate via DNS; changing IP during rebuilds can delay/interrupt issuance.

Rebuild safety: You can recreate URL maps/proxies without changing the public IP.

Cost: A global static external IP is free while attached to a forwarding rule (charged only if reserved and unused).

What uses the IP

The global forwarding rule(s) on the External HTTPS LB use the IP. The Serverless NEG itself doesn’t need or have an IP.

Recommended setup (IPv4, optional IPv6)
# Reserve a GLOBAL STATIC IPv4 address for the LB
gcloud compute addresses create cwe-chatbot-ipv4 \
  --ip-version=IPV4 \
  --global

# (Optional) Reserve a GLOBAL STATIC IPv6 address too
gcloud compute addresses create cwe-chatbot-ipv6 \
  --ip-version=IPV6 \
  --global

# Get the addresses
gcloud compute addresses describe cwe-chatbot-ipv4 --global --format="value(address)"
gcloud compute addresses describe cwe-chatbot-ipv6 --global --format="value(address)"


When you create the forwarding rules, pin them to the static IP(s):

# HTTPS (443) forwarding rule using the static IPv4
gcloud compute forwarding-rules create cwe-chatbot-fr-https \
  --global \
  --address=cwe-chatbot-ipv4 \
  --target-https-proxy=cwe-chatbot-https-proxy \
  --ports=443

# (Optional) HTTP (80) for redirect to HTTPS using the SAME IPv4
gcloud compute forwarding-rules create cwe-chatbot-fr-http \
  --global \
  --address=cwe-chatbot-ipv4 \
  --target-http-proxy=cwe-chatbot-http-proxy \
  --ports=80

# (Optional) dual-stack: add IPv6 forwarding rules
gcloud compute forwarding-rules create cwe-chatbot-fr-https-v6 \
  --global \
  --address=cwe-chatbot-ipv6 \
  --target-https-proxy=cwe-chatbot-https-proxy \
  --ports=443

gcloud compute forwarding-rules create cwe-chatbot-fr-http-v6 \
  --global \
  --address=cwe-chatbot-ipv6 \
  --target-http-proxy=cwe-chatbot-http-proxy \
  --ports=80


Then point DNS at those IPs:

A record for cwe.crashedmind.com → your IPv4

(optional) AAAA record → your IPv6

Note: If you ever rebuild the LB, just reattach these forwarding rules (or recreate them) using the same static IP names, and your public IP(s) won’t change.

When a static IP is not needed

If you use the native Cloud Run domain mapping (no external LB), Google manages DNS/TLS for you and there’s no IP to manage.

For temporary test stacks, an ephemeral IP is fine—just expect to update DNS if you tear down/recreate the LB.

Bottom line: It works without a static IP, but for your custom domain and WAF/LB setup, reserving a global static IP is the right move.