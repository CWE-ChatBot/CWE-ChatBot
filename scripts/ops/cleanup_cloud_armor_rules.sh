#!/usr/bin/env bash
set -euo pipefail

# Cleanup redundant Cloud Armor rules
# Removes exact-match WebSocket rules (995, 996) which are redundant with regex rule (1000)

PROJECT="${PROJECT:-cwechatbot}"
ARMOR_POLICY="${ARMOR_POLICY:-cwe-chatbot-armor}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok(){ echo -e "${GREEN}✓${NC} $*"; }
warn(){ echo -e "${YELLOW}⚠${NC} $*"; }
err(){ echo -e "${RED}✗${NC} $*"; }

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Cloud Armor Rules Cleanup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "This script will:"
echo "  1. Remove rule 900 (per-user rate limit - unused, no X-User-Id injection)"
echo "  2. Remove rule 995 (WS prod origin - redundant)"
echo "  3. Remove rule 996 (WS staging origin - redundant)"
echo "  4. Update rule 1000 description (clarify it covers both)"
echo ""
warn "Rule 1000 (regex match) already covers both prod and staging origins"
echo ""
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

gcloud config set project "$PROJECT" --quiet >/dev/null

# Check if policy exists
if ! gcloud compute security-policies describe "$ARMOR_POLICY" >/dev/null 2>&1; then
    err "Security policy '$ARMOR_POLICY' not found"
    exit 1
fi

echo ""
echo "Step 1: Remove rule 900 (per-user rate limit)"
if gcloud compute security-policies rules describe 900 --security-policy="$ARMOR_POLICY" >/dev/null 2>&1; then
    gcloud compute security-policies rules delete 900 \
        --security-policy="$ARMOR_POLICY" \
        --quiet
    ok "Removed rule 900 (unused - application doesn't inject X-User-Id)"
else
    warn "Rule 900 not found (already removed)"
fi

echo ""
echo "Step 2: Remove rule 995 (WebSocket prod origin)"
if gcloud compute security-policies rules describe 995 --security-policy="$ARMOR_POLICY" >/dev/null 2>&1; then
    gcloud compute security-policies rules delete 995 \
        --security-policy="$ARMOR_POLICY" \
        --quiet
    ok "Removed rule 995"
else
    warn "Rule 995 not found (already removed?)"
fi

echo ""
echo "Step 2: Remove rule 996 (WebSocket staging origin)"
if gcloud compute security-policies rules describe 996 --security-policy="$ARMOR_POLICY" >/dev/null 2>&1; then
    gcloud compute security-policies rules delete 996 \
        --security-policy="$ARMOR_POLICY" \
        --quiet
    ok "Removed rule 996"
else
    warn "Rule 996 not found (already removed?)"
fi

echo ""
echo "Step 3: Update rule 1000 description"
gcloud compute security-policies rules update 1000 \
    --security-policy="$ARMOR_POLICY" \
    --description="Allow WebSocket from prod and staging origins (*.cwe.crashedmind.com)" \
    --project="$PROJECT" \
    --quiet
ok "Updated rule 1000 description"

echo ""
echo "Step 4: Update rule 900 description"
if gcloud compute security-policies rules describe 900 --security-policy="$ARMOR_POLICY" >/dev/null 2>&1; then
    gcloud compute security-policies rules update 900 \
        --security-policy="$ARMOR_POLICY" \
        --description="Per-user rate limiting (60 req/min, ban at 120/min for x-user-id)" \
        --project="$PROJECT" \
        --quiet
    ok "Updated rule 900 description"
else
    warn "Rule 900 not found (skipping)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Cleanup Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "Redundant rules removed (995, 996)"
ok "Descriptions updated (900, 1000)"
echo ""
echo "Verify changes:"
echo "  gcloud compute security-policies describe $ARMOR_POLICY --project=$PROJECT"
echo ""
