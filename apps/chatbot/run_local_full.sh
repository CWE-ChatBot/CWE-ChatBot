#!/bin/bash
#
# CWE ChatBot - Local Full Functionality Runner
# Sets up and runs the chatbot with complete RAG retrieval and local database
#
# Database Environments:
# - LOCAL DEV: Docker PostgreSQL (postgres:postgres@localhost:5432/cwe)
# - PRODUCTION: Cloud SQL via proxy (IAM auth@localhost:5433/cwe_chatbot)
#
# This script is for LOCAL DEVELOPMENT with Docker PostgreSQL
#
# Prerequisites:
# - Docker and docker-compose available
# - GEMINI_API_KEY in environment or ~/work/env/.env_cwe_chatbot
# - CWE data will be ingested automatically with --setup-db
#

set -e  # Exit on any error

ps aux | rg -i 'chainlit|apps/chatbot/main.py' | rg -v rg || true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
DEFAULT_PORT=8080
DEFAULT_HOST="localhost"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo -e "${BLUE}🚀 CWE ChatBot - Local Full Functionality Setup${NC}"
echo "=================================================="

# Function to print usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -p, --port PORT        Port to run the server on (default: $DEFAULT_PORT)"
    echo "  -h, --host HOST        Host to bind to (default: $DEFAULT_HOST)"
    echo "  --headless            Run without opening browser"
    echo "  --setup-db            Set up local database and run CWE ingestion"
    echo "  --ingest-only         Only run CWE ingestion (database must exist)"
    echo "  --help                Show this help message"
    echo ""
    echo "Environment Variables (will be loaded from ~/work/env/.env_cwe_chatbot if available):"
    echo "  GEMINI_API_KEY        Your Gemini API key for embeddings (REQUIRED)"
    echo "  PROVIDER              LLM provider: google | vertex (default: google)"
    echo ""
    echo "Database Configuration (Local Docker PostgreSQL):"
    echo "  POSTGRES_HOST         PostgreSQL host (default: localhost)"
    echo "  POSTGRES_PORT         PostgreSQL port (default: 5432)"
    echo "  POSTGRES_DATABASE     PostgreSQL database name (default: cwe)"
    echo "  POSTGRES_USER         PostgreSQL username (default: postgres)"
    echo "  POSTGRES_PASSWORD     PostgreSQL password (default: postgres)"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Start with existing database"
    echo "  $0 --setup-db                       # Setup database and ingest CWE data"
    echo "  $0 --ingest-only                    # Only run CWE data ingestion"
    echo "  $0 --port 8090 --headless          # Custom port, headless"
}

# Parse command line arguments
PORT=$DEFAULT_PORT
HOST=$DEFAULT_HOST
HEADLESS_FLAG=""
SETUP_DATABASE=false
INGEST_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -h|--host)
            HOST="$2"
            shift 2
            ;;
        --headless)
            HEADLESS_FLAG="--headless"
            shift
            ;;
        --setup-db)
            SETUP_DATABASE=true
            shift
            ;;
        --ingest-only)
            INGEST_ONLY=true
            shift
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

# Change to chatbot directory
echo -e "${BLUE}📁 Changing to chatbot directory...${NC}"
cd "$SCRIPT_DIR"

# Check if poetry is available
if ! command -v poetry &> /dev/null; then
    echo -e "${RED}❌ Poetry not found. Please install Poetry first.${NC}"
    exit 1
fi

# Load environment variables from chatbot-specific env file
USER_ENV_FILE="$HOME/work/env/.env_cwe_chatbot"

# Helper to load a single key from the user env file if unset
load_env_key() {
    local key="$1"
    local current_val="${!key:-}"
    if [[ -z "$current_val" && -f "$USER_ENV_FILE" ]]; then
        local line
        line=$(grep -E "^${key}=" "$USER_ENV_FILE" | tail -n 1 || true)
        if [[ -n "$line" ]]; then
            local val
            val=$(echo "$line" | sed -E "s/^${key}=//; s/^\"(.*)\"$/\1/; s/^'(.*)'$/\1/")
            if [[ -n "$val" ]]; then
                export "$key"="$val"
                echo -e "${GREEN}✅ Loaded ${key} from ${USER_ENV_FILE}${NC}"
            fi
        fi
    fi
}

echo -e "${BLUE}🔧 Loading environment configuration...${NC}"

# Load all required environment variables
for KEY in \
    GEMINI_API_KEY \
    POSTGRES_HOST \
    POSTGRES_PORT \
    POSTGRES_DATABASE \
    POSTGRES_USER \
    POSTGRES_PASSWORD
do
    load_env_key "$KEY"
done

# Set defaults for missing values (Local Docker PostgreSQL)
export POSTGRES_HOST=${POSTGRES_HOST:-localhost}
export POSTGRES_PORT=${POSTGRES_PORT:-5432}
export POSTGRES_DATABASE=${POSTGRES_DATABASE:-cwe}
export POSTGRES_USER=${POSTGRES_USER:-postgres}
export POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-postgres}

# Required: CWE ingestion path
export CWE_INGESTION_PATH="$PROJECT_ROOT/apps/cwe_ingestion"
echo -e "${GREEN}✅ CWE_INGESTION_PATH=${CWE_INGESTION_PATH}${NC}"

# Verify CWE ingestion directory exists
if [[ ! -d "$CWE_INGESTION_PATH" ]]; then
    echo -e "${RED}❌ CWE ingestion directory not found: $CWE_INGESTION_PATH${NC}"
    exit 1
fi

# Validate required environment variables
echo -e "${BLUE}🔍 Validating configuration...${NC}"

if [[ -z "$GEMINI_API_KEY" ]]; then
    echo -e "${RED}❌ GEMINI_API_KEY not set${NC}"
    echo "   Set it in ~/work/env/.env_cwe_chatbot: GEMINI_API_KEY=your-api-key"
    exit 1
fi

if [[ -z "$POSTGRES_USER" ]] || [[ -z "$POSTGRES_PASSWORD" ]]; then
    echo -e "${RED}❌ PostgreSQL credentials not configured${NC}"
    echo "   Using defaults: postgres/postgres for local Docker PostgreSQL"
    echo "   Or set POSTGRES_USER and POSTGRES_PASSWORD in ~/work/env/.env_cwe_chatbot"
fi

# Build local database URL
LOCAL_DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DATABASE}"
export LOCAL_DATABASE_URL

echo -e "${GREEN}✅ GEMINI_API_KEY configured${NC}"
echo -e "${GREEN}✅ LOCAL_DATABASE_URL configured${NC}"

# Database setup and ingestion
if [[ "$SETUP_DATABASE" == true ]] || [[ "$INGEST_ONLY" == true ]]; then
    echo -e "${CYAN}🗄️  Database and CWE Ingestion Setup${NC}"

    if [[ "$SETUP_DATABASE" == true ]]; then
        echo -e "${BLUE}Setting up local PostgreSQL database...${NC}"

        # Check if Docker PostgreSQL is running
        if ! pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" >/dev/null 2>&1; then
            echo -e "${YELLOW}⚠️  PostgreSQL not accessible, attempting to start Docker container...${NC}"

            # Try to start the Docker PostgreSQL container
            cd "$CWE_INGESTION_PATH"
            if [[ -f "docker-compose.yml" ]]; then
                docker compose up -d
                echo -e "${BLUE}Waiting for PostgreSQL to be ready...${NC}"
                sleep 10

                # Check again
                if ! pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" >/dev/null 2>&1; then
                    echo -e "${RED}❌ PostgreSQL still not accessible after Docker startup${NC}"
                    echo "   Manually start PostgreSQL: cd $CWE_INGESTION_PATH && docker compose up -d"
                    exit 1
                fi
                echo -e "${GREEN}✅ PostgreSQL Docker container started successfully${NC}"
            else
                echo -e "${RED}❌ PostgreSQL is not running and docker-compose.yml not found${NC}"
                echo "   Start PostgreSQL manually or ensure Docker is available"
                exit 1
            fi
            cd "$SCRIPT_DIR"
        fi

        # Create database if it doesn't exist
        echo -e "${BLUE}Creating database if it doesn't exist...${NC}"
        PGPASSWORD="$POSTGRES_PASSWORD" createdb -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" "$POSTGRES_DATABASE" 2>/dev/null || true

        # Install pgvector extension
        echo -e "${BLUE}Installing pgvector extension...${NC}"
        PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE" -c "CREATE EXTENSION IF NOT EXISTS vector;" >/dev/null

        echo -e "${GREEN}✅ Database setup completed${NC}"
    fi

    echo -e "${BLUE}Running CWE data ingestion...${NC}"
    cd "$CWE_INGESTION_PATH"

    # Check if CWE data needs to be ingested
    poetry run python cli.py ingest --embedder-type gemini

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✅ CWE data ingestion completed${NC}"
    else
        echo -e "${RED}❌ CWE data ingestion failed${NC}"
        exit 1
    fi

    cd "$SCRIPT_DIR"

    if [[ "$INGEST_ONLY" == true ]]; then
        echo -e "${GREEN}🎉 CWE data ingestion completed successfully${NC}"
        exit 0
    fi
fi

# Test database connection
echo -e "${BLUE}🔍 Testing database connection...${NC}"
if ! PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE" -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'cwe_chunks';" >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Cannot connect to database or cwe_chunks table not found${NC}"
    echo "   Run with --setup-db to initialize the database and ingest CWE data"
fi

# Check if port is available
if command -v netstat &> /dev/null; then
    if netstat -tuln 2>/dev/null | grep -q ":$PORT "; then
        echo -e "${YELLOW}⚠️  Port $PORT appears to be in use${NC}"
        echo "   Use --port to specify a different port"
    fi
fi

# Display startup configuration
echo ""
echo -e "${BLUE}🔍 Startup Configuration:${NC}"
echo "  Server: http://$HOST:$PORT"
echo "  Database: $POSTGRES_HOST:$POSTGRES_PORT/$POSTGRES_DATABASE"
echo "  Gemini API: Configured"
echo "  Headless: $([ -n "$HEADLESS_FLAG" ] && echo "Yes" || echo "No")"
echo "  Full RAG: Enabled"
echo ""

# Start the application (run from project root to pick up root .chainlit config)
echo -e "${GREEN}🚀 Starting CWE ChatBot with full functionality...${NC}"
echo "   Features enabled: RAG retrieval, vector search, local database"
echo "   Stop with Ctrl+C"
echo ""

# Build the command
CMD="poetry run chainlit run apps/chatbot/main.py --host $HOST --port $PORT"
if [[ -n "$HEADLESS_FLAG" ]]; then
    CMD="$CMD $HEADLESS_FLAG"
fi

echo -e "${BLUE}Executing (from project root): $CMD${NC}"
echo ""

# Execute the command from project root so Chainlit loads .chainlit/config.toml there
cd "$PROJECT_ROOT"
exec $CMD
