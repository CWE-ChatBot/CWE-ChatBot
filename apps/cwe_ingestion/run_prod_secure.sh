#!/bin/bash
set -euo pipefail

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${BLUE}🔒 CWE Ingestion - Secure Production Operations${NC}"
echo "=================================================="

# Config
PROJECT_ID="cwechatbot"
CLOUD_SQL_INSTANCE="cwechatbot:us-central1:cwe-postgres-prod"
PROXY_PORT=5433
DATABASE_NAME="postgres"   # TODO: migrate to cwe_prod
ENV_CONTEXT=production

# Proxy binary detection (prefer official name)
PROXY_BIN="./cloud-sql-proxy"
[[ -x "$PROXY_BIN" ]] || PROXY_BIN="./cloud-sql-proxy-v2"

usage(){
  cat <<USAGE
Usage: $0 [--test-connection|--ingest-corpus|--import-policy|--performance-test|--health-check|--start-proxy-only|--stop-proxy] [options]

Security features:
  ✅ ADC (no SA keys) with SA impersonation
  ✅ Proxy --auto-iam-authn (no manual tokens)
  ✅ Secret Manager for API keys
  ✅ Private connectivity ready
USAGE
}

OP=""; EMBEDDER_TYPE="gemini"; STORAGE_MODE="--chunked"; TARGET_CWES=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --test-connection|--ingest-corpus|--import-policy|--performance-test|--health-check|--start-proxy-only|--stop-proxy)
      OP=${1#--}; shift;;
    --embedder-type) EMBEDDER_TYPE="$2"; shift 2;;
    --chunked) STORAGE_MODE="--chunked"; shift;;
    --single) STORAGE_MODE="--single"; shift;;
    --target-cwes) TARGET_CWES="$2"; shift 2;;
    --help) usage; exit 0;;
    *) echo -e "${RED}❌ Unknown option: $1${NC}"; usage; exit 1;;
  esac
done
[[ -n "$OP" ]] || { echo -e "${RED}❌ No operation specified${NC}"; usage; exit 1; }

# Prechecks
command -v poetry >/dev/null || { echo -e "${RED}❌ Poetry not found${NC}"; exit 1; }
command -v gcloud >/dev/null || { echo -e "${RED}❌ gcloud not found${NC}"; exit 1; }

# Verify ADC present (no guarantee of SA identity, that is okay; DB will tell us current_user)
echo -e "${BLUE}🔐 Verifying Application Default Credentials...${NC}"
if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
  echo -e "${RED}❌ ADC not configured${NC}"
  echo -e "${YELLOW}   Run: gcloud auth application-default login --impersonate-service-account=cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com${NC}"
  exit 1
fi

echo -e "${GREEN}✅ ADC available${NC}"

# Optional: Secret Manager for API key
get_gemini_api_key(){
  echo -e "${BLUE}🔑 Fetching Gemini API key from Secret Manager...${NC}"
  if GEMINI_API_KEY=$(gcloud secrets versions access latest --secret="gemini-api-key" --project="$PROJECT_ID" 2>/dev/null); then
    export GEMINI_API_KEY; echo -e "${GREEN}✅ API key loaded from Secret Manager${NC}"; return 0
  fi
  [[ -n "${GEMINI_API_KEY:-}" ]] && { echo -e "${YELLOW}⚠️ Using GEMINI_API_KEY from environment${NC}"; return 0; }
  echo -e "${YELLOW}⚠️ No Gemini key found; continuing (only required for embedding ops)${NC}"
}

get_gemini_api_key || true

# Connection URL (no password; proxy injects IAM token)
export PROD_DATABASE_URL="postgresql://cwe-postgres-sa%40cwechatbot.iam@127.0.0.1:${PROXY_PORT}/${DATABASE_NAME}"

# Start/stop proxy (PID-based)
PROXY_PID=""
start_proxy(){
  echo -e "${BLUE}🔄 Starting Cloud SQL Auth Proxy...${NC}"
  [[ -x "$PROXY_BIN" ]] || { echo -e "${RED}❌ $PROXY_BIN not found${NC}"; exit 1; }

  # Start proxy and capture any immediate errors
  "$PROXY_BIN" --auto-iam-authn "$CLOUD_SQL_INSTANCE" --port="$PROXY_PORT" &
  PROXY_PID=$!

  # Wait for proxy to start or fail
  for i in {1..30}; do
    sleep 1
    # Check if process is still running
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
      echo -e "${RED}❌ Proxy process died during startup${NC}"
      echo -e "${YELLOW}   This likely indicates IAM authentication issues${NC}"
      echo -e "${YELLOW}   Check: gcloud auth application-default login --impersonate-service-account=cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com${NC}"
      exit 1
    fi
    # Check if port is available
    if nc -z 127.0.0.1 "$PROXY_PORT" 2>/dev/null; then
      echo -e "${GREEN}✅ Proxy ready on :$PROXY_PORT${NC}"
      return 0
    fi
  done
  echo -e "${RED}❌ Proxy failed to start within 30 seconds${NC}"; exit 1
}
stop_proxy(){
  [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
  sleep 1
  echo -e "${GREEN}✅ Proxy stopped${NC}"
}

# Ops
test_connection(){
  echo -e "${CYAN}🔍 Testing secure production DB connection${NC}"
  poetry run python - <<'PY'
import os, psycopg
url=os.environ['PROD_DATABASE_URL']
print('Connecting with proxy auto-iam-authn...')
with psycopg.connect(url) as conn:
  with conn.cursor() as cur:
    cur.execute('SELECT current_user, version();')
    print(cur.fetchone())
    cur.execute("SELECT extname FROM pg_extension WHERE extname IN ('vector','pgaudit','pg_trgm') ORDER BY 1;")
    print('Extensions:', [r[0] for r in cur.fetchall()])
PY
}

ingest_corpus(){
  echo -e "${CYAN}📊 Running CWE corpus ingestion${NC}"
  CMD="poetry run python cli.py ingest --embedder-type $EMBEDDER_TYPE $STORAGE_MODE"
  if [[ -n "$TARGET_CWES" ]]; then
    IFS=',' read -ra A <<< "$TARGET_CWES"; for c in "${A[@]}"; do CMD+=" -c CWE-$c"; done
  fi
  DATABASE_URL="$PROD_DATABASE_URL" eval "$CMD"
}

import_policy(){
  echo -e "${CYAN}📋 Importing CWE policy labels${NC}"
  DATABASE_URL="$PROD_DATABASE_URL" poetry run python scripts/import_policy_from_xml.py \
    --url https://cwe.mitre.org/data/xml/cwec_latest.xml.zip \
    --infer-by-abstraction
}

performance_test(){
  echo -e "${CYAN}⚡ Performance tests${NC}"
  DATABASE_URL="$PROD_DATABASE_URL" poetry run python scripts/test_retrieval_performance.py
}

health_check(){
  echo -e "${CYAN}🩺 Health check${NC}"
  DATABASE_URL="$PROD_DATABASE_URL" poetry run python cli.py stats --chunked
}

case "$OP" in
  stop-proxy) stop_proxy ;;
  start-proxy-only)
    start_proxy
    echo -e "${BLUE}Proxy on 127.0.0.1:$PROXY_PORT (Ctrl+C to stop)${NC}"
    trap 'stop_proxy; exit 0' INT TERM
    while sleep 30; do nc -z 127.0.0.1 "$PROXY_PORT" || { echo -e "${RED}Proxy down${NC}"; break; }; done
    ;;
  test-connection|ingest-corpus|import-policy|performance-test|health-check)
    trap 'stop_proxy; exit 1' INT TERM ERR
    start_proxy
    case "$OP" in
      test-connection) test_connection ;;
      ingest-corpus)   test_connection; ingest_corpus ;;
      import-policy)   test_connection; import_policy ;;
      performance-test)test_connection; performance_test ;;
      health-check)    test_connection; health_check ;;
    esac
    stop_proxy
    ;;
  *) echo -e "${RED}Unknown op${NC}"; usage; exit 1 ;;

esac

echo -e "${GREEN}🎉 Secure operation '$OP' completed${NC}"