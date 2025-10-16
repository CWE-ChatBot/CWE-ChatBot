#!/usr/bin/env bash
# Fix load balancer routing to separate production and staging traffic
#
# Current problem:
# - URL map routes ALL traffic (*) to staging backend
# - Production domain (cwe.crashedmind.com) goes to staging backend
#
# Solution:
# - Add production path matcher pointing to production backend
# - Route cwe.crashedmind.com → production backend
# - Route staging-cwe.crashedmind.com → staging backend
# - Remove wildcard (*) routing

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok() { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC}  $1"; }

PROJECT="${PROJECT:-cwechatbot}"
URL_MAP="cwe-chatbot-urlmap"
PROD_BACKEND="cwe-chatbot-be"
STAGING_BACKEND="cwe-chatbot-staging-be"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Fix Load Balancer Routing"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "This script will:"
echo "  1. Export current URL map configuration"
echo "  2. Add production path matcher (pm-production → $PROD_BACKEND)"
echo "  3. Update host rules:"
echo "     - cwe.crashedmind.com → pm-production"
echo "     - staging-cwe.crashedmind.com → pm-staging"
echo "  4. Remove wildcard (*) routing"
echo "  5. Update URL map"
echo ""
warn "This will route cwe.crashedmind.com to production backend"
echo ""
read -p "Continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted"
    exit 1
fi

# Set project
gcloud config set project "$PROJECT" --quiet

echo ""
echo "Step 1: Export current URL map"
gcloud compute url-maps export "$URL_MAP" \
    --destination=/tmp/urlmap-backup.yaml \
    --quiet
ok "Backed up to /tmp/urlmap-backup.yaml"

echo ""
echo "Step 2: Create updated URL map configuration"

cat > /tmp/urlmap-updated.yaml <<'EOF'
name: cwe-chatbot-urlmap
defaultService: https://www.googleapis.com/compute/v1/projects/cwechatbot/global/backendServices/cwe-chatbot-be
hostRules:
- hosts:
  - cwe.crashedmind.com
  pathMatcher: pm-production
- hosts:
  - staging-cwe.crashedmind.com
  pathMatcher: pm-staging
pathMatchers:
- name: pm-production
  defaultService: https://www.googleapis.com/compute/v1/projects/cwechatbot/global/backendServices/cwe-chatbot-be
- name: pm-staging
  defaultService: https://www.googleapis.com/compute/v1/projects/cwechatbot/global/backendServices/cwe-chatbot-staging-be
EOF

ok "Created /tmp/urlmap-updated.yaml"

echo ""
echo "Step 3: Update URL map"
gcloud compute url-maps import "$URL_MAP" \
    --source=/tmp/urlmap-updated.yaml \
    --quiet
ok "Updated URL map"

echo ""
echo "Step 4: Verify configuration"
echo ""
echo "Production domain (cwe.crashedmind.com):"
gcloud compute url-maps describe "$URL_MAP" --format=json | \
    jq -r '.hostRules[] | select(.hosts[] | contains("cwe.crashedmind.com")) | "  Hosts: \(.hosts | join(", "))\n  Path Matcher: \(.pathMatcher)"'

echo ""
echo "Staging domain (staging-cwe.crashedmind.com):"
gcloud compute url-maps describe "$URL_MAP" --format=json | \
    jq -r '.hostRules[] | select(.hosts[] | contains("staging-cwe.crashedmind.com")) | "  Hosts: \(.hosts | join(", "))\n  Path Matcher: \(.pathMatcher)"'

echo ""
echo "Path Matchers:"
gcloud compute url-maps describe "$URL_MAP" --format=json | \
    jq -r '.pathMatchers[] | "  \(.name) → \(.defaultService | split("/")[-1])"'

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Update Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "Production traffic now routes to production backend"
ok "Staging traffic now routes to staging backend"
echo ""
echo "Test the fix:"
echo "  curl -I https://cwe.crashedmind.com/"
echo "  curl -I https://staging-cwe.crashedmind.com/"
echo ""
echo "Rollback if needed:"
echo "  gcloud compute url-maps import $URL_MAP --source=/tmp/urlmap-backup.yaml"
echo ""
