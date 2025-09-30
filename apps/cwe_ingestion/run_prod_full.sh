#!/bin/bash
#
# CWE Ingestion - Production Cloud Operations Runner
# Runs CWE ingestion operations against Google Cloud SQL production database
#
# Database Environment:
# - PRODUCTION: Cloud SQL via proxy (IAM auth@localhost:5433/cwe)
#
# This script handles:
# - Cloud SQL Auth Proxy management
# - IAM authentication verification
# - CWE corpus ingestion to production
# - Policy label import from CWE XML
# - Performance testing and validation
#
# Prerequisites:
# - gcloud CLI authenticated with service account
# - GEMINI_API_KEY in environment or ~/work/env/.env_cwe_chatbot
# - cloud-sql-proxy-v2 binary in current directory
#

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Production Cloud SQL settings (per Network Architecture Diagram)
CLOUD_SQL_INSTANCE="cwechatbot:us-central1:cwe-postgres-prod"
PROXY_PORT=5433
DATABASE_NAME="postgres"
SERVICE_ACCOUNT="cwe-postgres-sa@cwechatbot.iam"

echo -e "${BLUE}🚀 CWE Ingestion - Production Cloud Operations${NC}"
echo "=============================================="

# Function to print usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Production Cloud Operations:"
    echo "  --test-connection         Test Cloud SQL connection via proxy"
    echo "  --ingest-corpus          Run full CWE corpus ingestion (969 CWEs)"
    echo "  --import-policy          Import CWE policy labels from MITRE XML"
    echo "  --performance-test       Run retrieval performance tests"
    echo "  --health-check           Database health and statistics check"
    echo "  --start-proxy-only       Start Cloud SQL proxy and leave running"
    echo "  --stop-proxy             Stop any running Cloud SQL proxy"
    echo ""
    echo "Options:"
    echo "  --embedder-type TYPE     Embedding provider: gemini (default)"
    echo "  --chunked               Use chunked storage (recommended, default)"
    echo "  --single                Use single-row storage"
    echo "  --target-cwes LIST      Comma-separated CWE IDs (e.g., 79,89,22)"
    echo "  --help                  Show this help message"
    echo ""
    echo "Environment Variables (will be loaded from ~/work/env/.env_cwe_chatbot if available):"
    echo "  GEMINI_API_KEY          Your Gemini API key for embeddings (REQUIRED)"
    echo ""
    echo "Examples:"
    echo "  $0 --test-connection                    # Test production database"
    echo "  $0 --ingest-corpus                     # Full CWE corpus ingestion"
    echo "  $0 --import-policy                     # Import policy labels"
    echo "  $0 --ingest-corpus --target-cwes 79,89 # Specific CWEs only"
    echo "  $0 --performance-test                  # Test query performance"
    echo "  $0 --health-check                      # Database statistics"
}

# Parse command line arguments
OPERATION=""
EMBEDDER_TYPE="gemini"
STORAGE_MODE="--chunked"
TARGET_CWES=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --test-connection)
            OPERATION="test-connection"
            shift
            ;;
        --ingest-corpus)
            OPERATION="ingest-corpus"
            shift
            ;;
        --import-policy)
            OPERATION="import-policy"
            shift
            ;;
        --performance-test)
            OPERATION="performance-test"
            shift
            ;;
        --health-check)
            OPERATION="health-check"
            shift
            ;;
        --start-proxy-only)
            OPERATION="start-proxy-only"
            shift
            ;;
        --stop-proxy)
            OPERATION="stop-proxy"
            shift
            ;;
        --embedder-type)
            EMBEDDER_TYPE="$2"
            shift 2
            ;;
        --chunked)
            STORAGE_MODE="--chunked"
            shift
            ;;
        --single)
            STORAGE_MODE="--single"
            shift
            ;;
        --target-cwes)
            TARGET_CWES="$2"
            shift 2
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            usage
            exit 1
            ;;
    esac
done

if [[ -z "$OPERATION" ]]; then
    echo -e "${RED}❌ No operation specified${NC}"
    usage
    exit 1
fi

# Change to CWE ingestion directory
echo -e "${BLUE}📁 Changing to CWE ingestion directory...${NC}"
cd "$SCRIPT_DIR"

# Check if poetry is available
if ! command -v poetry &> /dev/null; then
    echo -e "${RED}❌ Poetry not found. Please install Poetry first.${NC}"
    exit 1
fi

# Check if gcloud is available and authenticated
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}❌ gcloud CLI not found. Please install Google Cloud CLI.${NC}"
    exit 1
fi

# Verify gcloud authentication
echo -e "${BLUE}🔐 Verifying Google Cloud authentication...${NC}"
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
    echo -e "${RED}❌ No active Google Cloud authentication found${NC}"
    echo "   Run: gcloud auth login"
    exit 1
fi

ACTIVE_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)")
echo -e "${GREEN}✅ Authenticated as: $ACTIVE_ACCOUNT${NC}"

# Load environment variables
USER_ENV_FILE="$HOME/work/env/.env_cwe_chatbot"
if [[ -f "$USER_ENV_FILE" ]]; then
    echo -e "${BLUE}🔧 Loading environment from $USER_ENV_FILE...${NC}"
    set -a
    source "$USER_ENV_FILE"
    set +a
    echo -e "${GREEN}✅ Environment loaded${NC}"
fi

# Set production environment context
export ENV_CONTEXT=production

# Ensure we're using the service account for authentication
echo -e "${BLUE}🔐 Switching to service account for IAM authentication...${NC}"
gcloud config set account cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com

# Generate SQL login token for IAM authentication
echo -e "${BLUE}🎫 Generating SQL login token...${NC}"
SQL_TOKEN=$(gcloud sql generate-login-token)
if [[ -z "$SQL_TOKEN" ]]; then
    echo -e "${RED}❌ Failed to generate SQL login token${NC}"
    exit 1
fi

# Use Cloud SQL Auth Proxy connection format with proper IAM authentication
export PROD_DATABASE_URL="postgresql://cwe-postgres-sa%40cwechatbot.iam:${SQL_TOKEN}@127.0.0.1:${PROXY_PORT}/${DATABASE_NAME}"

# Function to start Cloud SQL Auth Proxy
start_cloud_sql_proxy() {
    echo -e "${BLUE}🔄 Starting Cloud SQL Auth Proxy...${NC}"

    # Check if Cloud SQL Proxy binary exists
    if [[ ! -f "./cloud-sql-proxy-v2" ]]; then
        echo -e "${RED}❌ cloud-sql-proxy-v2 binary not found in current directory${NC}"
        echo "   Download from: https://cloud.google.com/sql/docs/postgres/sql-proxy"
        exit 1
    fi

    # Kill any existing proxy processes
    pkill -f "cloud-sql-proxy" || true
    sleep 2

    # Start Cloud SQL Auth Proxy in background
    echo -e "${BLUE}Starting proxy for instance: $CLOUD_SQL_INSTANCE${NC}"
    ./cloud-sql-proxy-v2 "$CLOUD_SQL_INSTANCE" --port="$PROXY_PORT" &
    PROXY_PID=$!

    # Wait for proxy to be ready
    echo -e "${BLUE}Waiting for proxy to be ready...${NC}"
    for i in {1..30}; do
        if nc -z 127.0.0.1 "$PROXY_PORT" 2>/dev/null; then
            echo -e "${GREEN}✅ Cloud SQL Auth Proxy ready on port $PROXY_PORT${NC}"
            return 0
        fi
        sleep 1
    done

    echo -e "${RED}❌ Cloud SQL Auth Proxy failed to start within 30 seconds${NC}"
    exit 1
}

# Function to stop Cloud SQL Auth Proxy
stop_cloud_sql_proxy() {
    echo -e "${BLUE}🛑 Stopping Cloud SQL Auth Proxy...${NC}"
    pkill -f "cloud-sql-proxy" || true
    sleep 2
    echo -e "${GREEN}✅ Cloud SQL Auth Proxy stopped${NC}"
}

# Function to test database connection
test_database_connection() {
    echo -e "${CYAN}🔍 Testing Production Database Connection${NC}"
    echo "======================================"

    # Test connection using Python script
    if poetry run python -c "
import psycopg
import os

try:
    conn_url = os.getenv('PROD_DATABASE_URL')
    print(f'Connecting via Cloud SQL Auth Proxy with IAM authentication...')
    print(f'Using service account: cwe-postgres-sa@cwechatbot.iam.gserviceaccount.com')

    conn = psycopg.connect(conn_url)
    print('✅ PRODUCTION DATABASE CONNECTION SUCCESSFUL!')

    with conn.cursor() as cur:
        cur.execute('SELECT version();')
        version = cur.fetchone()[0]
        print(f'✓ PostgreSQL version: {version[:60]}...')

        cur.execute('SELECT current_user;')
        user = cur.fetchone()[0]
        print(f'✓ Connected as: {user}')

        # Test pgvector extension
        cur.execute(\"SELECT * FROM pg_extension WHERE extname='vector';\")
        if cur.fetchone():
            print('✓ pgvector extension available')
        else:
            print('❌ pgvector extension not found')

        # Check for existing tables
        cur.execute(\"SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'cwe_chunks';\")
        cwe_chunks_exists = cur.fetchone()[0] > 0

        cur.execute(\"SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'cwe_policy_labels';\")
        policy_exists = cur.fetchone()[0] > 0

        print(f'✓ cwe_chunks table: {\"exists\" if cwe_chunks_exists else \"not found\"}')
        print(f'✓ cwe_policy_labels table: {\"exists\" if policy_exists else \"not found\"}')

        if cwe_chunks_exists:
            cur.execute('SELECT COUNT(*) FROM cwe_chunks;')
            chunk_count = cur.fetchone()[0]
            print(f'✓ CWE chunks in database: {chunk_count:,}')

    conn.close()
    print('✅ Connection test completed successfully')
except Exception as e:
    print(f'❌ Connection test failed: {e}')
    exit(1)
"; then
        echo -e "${GREEN}🎉 Production database connection verified!${NC}"
    else
        echo -e "${RED}❌ Production database connection failed${NC}"
        exit 1
    fi
}

# Function to run CWE corpus ingestion
run_corpus_ingestion() {
    echo -e "${CYAN}📊 Running CWE Corpus Ingestion${NC}"
    echo "================================="

    # Build ingestion command
    CMD="poetry run python cli.py ingest --embedder-type $EMBEDDER_TYPE $STORAGE_MODE"

    # Add target CWEs if specified
    if [[ -n "$TARGET_CWES" ]]; then
        IFS=',' read -ra CWE_ARRAY <<< "$TARGET_CWES"
        for cwe in "${CWE_ARRAY[@]}"; do
            CMD="$CMD -c CWE-$cwe"
        done
        echo -e "${BLUE}Targeting specific CWEs: $TARGET_CWES${NC}"
    else
        echo -e "${BLUE}Ingesting full CWE corpus (969 CWEs)${NC}"
    fi

    echo -e "${BLUE}Executing: $CMD${NC}"

    # Set production database URL for ingestion
    export DATABASE_URL="$PROD_DATABASE_URL"

    if eval "$CMD"; then
        echo -e "${GREEN}✅ CWE corpus ingestion completed successfully${NC}"
    else
        echo -e "${RED}❌ CWE corpus ingestion failed${NC}"
        exit 1
    fi
}

# Function to import policy labels
import_policy_labels() {
    echo -e "${CYAN}📋 Importing CWE Policy Labels${NC}"
    echo "==============================="

    echo -e "${BLUE}Downloading and importing CWE policy labels from MITRE XML...${NC}"

    # Set production database URL for policy import
    export DATABASE_URL="$PROD_DATABASE_URL"

    if poetry run python scripts/import_policy_from_xml.py \
        --url https://cwe.mitre.org/data/xml/cwec_latest.xml.zip \
        --infer-by-abstraction; then
        echo -e "${GREEN}✅ CWE policy labels imported successfully${NC}"
    else
        echo -e "${RED}❌ CWE policy labels import failed${NC}"
        exit 1
    fi
}

# Function to run performance tests
run_performance_tests() {
    echo -e "${CYAN}⚡ Running Performance Tests${NC}"
    echo "============================"

    echo -e "${BLUE}Testing retrieval performance with production database...${NC}"

    # Set production database URL for performance tests
    export DATABASE_URL="$PROD_DATABASE_URL"

    if poetry run python scripts/test_retrieval_performance.py; then
        echo -e "${GREEN}✅ Performance tests completed${NC}"
    else
        echo -e "${RED}❌ Performance tests failed${NC}"
        exit 1
    fi
}

# Function to run health check
run_health_check() {
    echo -e "${CYAN}🩺 Database Health Check${NC}"
    echo "========================"

    # Set production database URL for health check
    export DATABASE_URL="$PROD_DATABASE_URL"

    if poetry run python cli.py stats --chunked; then
        echo -e "${GREEN}✅ Health check completed${NC}"
    else
        echo -e "${RED}❌ Health check failed${NC}"
        exit 1
    fi
}

# Main execution logic
case $OPERATION in
    "stop-proxy")
        stop_cloud_sql_proxy
        echo -e "${GREEN}🎉 Cloud SQL Auth Proxy stopped${NC}"
        ;;
    "start-proxy-only")
        start_cloud_sql_proxy
        echo -e "${GREEN}🎉 Cloud SQL Auth Proxy started and running${NC}"
        echo -e "${BLUE}Proxy will run until manually stopped with --stop-proxy${NC}"
        echo -e "${BLUE}Connection available at: 127.0.0.1:$PROXY_PORT${NC}"
        echo -e "${BLUE}Press Ctrl+C to stop or run: $0 --stop-proxy${NC}"

        # Keep script running
        trap 'stop_cloud_sql_proxy; exit 0' INT TERM
        while true; do
            sleep 30
            if ! nc -z 127.0.0.1 "$PROXY_PORT" 2>/dev/null; then
                echo -e "${RED}❌ Proxy connection lost${NC}"
                exit 1
            fi
        done
        ;;
    *)
        # For all other operations, start proxy, run operation, then stop proxy
        start_cloud_sql_proxy

        trap 'stop_cloud_sql_proxy; exit 1' INT TERM ERR

        case $OPERATION in
            "test-connection")
                test_database_connection
                ;;
            "ingest-corpus")
                test_database_connection
                run_corpus_ingestion
                ;;
            "import-policy")
                test_database_connection
                import_policy_labels
                ;;
            "performance-test")
                test_database_connection
                run_performance_tests
                ;;
            "health-check")
                test_database_connection
                run_health_check
                ;;
        esac

        stop_cloud_sql_proxy
        ;;
esac

echo ""
echo -e "${GREEN}🎉 Operation '$OPERATION' completed successfully!${NC}"
echo -e "${BLUE}Production database: $CLOUD_SQL_INSTANCE${NC}"
echo -e "${BLUE}Database name: $DATABASE_NAME${NC}"
echo -e "${BLUE}Service account: $SERVICE_ACCOUNT${NC}"