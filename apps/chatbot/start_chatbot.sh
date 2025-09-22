#!/bin/bash
#
# CWE ChatBot Startup Script
# Starts the Chainlit application with proper environment configuration
#

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
DEFAULT_PORT=8080
DEFAULT_HOST="localhost"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo -e "${BLUE}🚀 CWE ChatBot Startup Script${NC}"
echo "======================================"

# Function to print usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -p, --port PORT        Port to run the server on (default: $DEFAULT_PORT)"
    echo "  -h, --host HOST        Host to bind to (default: $DEFAULT_HOST)"
    echo "  --headless            Run without opening browser"
    echo "  --with-db             Start with database configuration"
    echo "  --production          Use production database settings"
    echo "  --help                Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  GEMINI_API_KEY        Your Gemini API key for embeddings"
    echo "  DATABASE_URL          Full database connection string"
    echo "  LOCAL_DATABASE_URL    Local database connection string"
    echo "  POSTGRES_HOST         PostgreSQL host (default: localhost)"
    echo "  POSTGRES_PORT         PostgreSQL port (default: 5432)"
    echo "  POSTGRES_DATABASE     PostgreSQL database name (default: cwe_chatbot)"
    echo "  POSTGRES_USER         PostgreSQL username"
    echo "  POSTGRES_PASSWORD     PostgreSQL password"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Basic startup"
    echo "  $0 --port 8090 --headless           # Custom port, headless"
    echo "  $0 --with-db                        # With local database"
    echo "  $0 --production                     # Production mode"
}

# Parse command line arguments
PORT=$DEFAULT_PORT
HOST=$DEFAULT_HOST
HEADLESS_FLAG=""
WITH_DATABASE=false
PRODUCTION_MODE=false

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
        --with-db)
            WITH_DATABASE=true
            shift
            ;;
        --production)
            PRODUCTION_MODE=true
            WITH_DATABASE=true
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

# Set required environment variables
echo -e "${BLUE}🔧 Setting up environment...${NC}"

# Required: CWE ingestion path
export CWE_INGESTION_PATH="$PROJECT_ROOT/apps/cwe_ingestion"
echo -e "${GREEN}✅ CWE_INGESTION_PATH=${CWE_INGESTION_PATH}${NC}"

# Load common environment variables from user env file if not already set
USER_ENV_FILE="$HOME/work/env/.env"

# Helper to load a single key from the user env file if unset
load_env_key() {
  local key="$1"
  local current_val="${!key:-}"
  if [[ -z "$current_val" && -f "$USER_ENV_FILE" ]]; then
    # Extract key=value with support for quoted strings
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

# Keys to attempt loading (won't overwrite existing env)
for KEY in \
  GEMINI_API_KEY \
  OPENAI_API_KEY \
  DATABASE_URL \
  LOCAL_DATABASE_URL \
  PROD_DATABASE_URL \
  POSTGRES_HOST \
  POSTGRES_PORT \
  POSTGRES_DATABASE \
  POSTGRES_USER \
  POSTGRES_PASSWORD
do
  load_env_key "$KEY"
done

# Verify CWE ingestion directory exists
if [[ ! -d "$CWE_INGESTION_PATH" ]]; then
    echo -e "${RED}❌ CWE ingestion directory not found: $CWE_INGESTION_PATH${NC}"
    exit 1
fi

# Database configuration
if [[ "$WITH_DATABASE" == true ]]; then
    echo -e "${YELLOW}🗄️  Setting up database configuration...${NC}"

    if [[ "$PRODUCTION_MODE" == true ]]; then
        echo -e "${BLUE}🏭 Production mode enabled${NC}"

        # Check for production database URL
        if [[ -z "$DATABASE_URL" ]]; then
            echo -e "${RED}❌ DATABASE_URL environment variable required for production mode${NC}"
            echo "   Set it like: export DATABASE_URL='postgresql://user:pass@host:port/db'"
            exit 1
        fi
        echo -e "${GREEN}✅ Using production DATABASE_URL${NC}"

    else
        echo -e "${BLUE}🏠 Local development mode${NC}"

        # Set up local database URL if not provided
        if [[ -z "$LOCAL_DATABASE_URL" ]] && [[ -z "$DATABASE_URL" ]]; then
            POSTGRES_HOST=${POSTGRES_HOST:-localhost}
            POSTGRES_PORT=${POSTGRES_PORT:-5432}
            POSTGRES_DATABASE=${POSTGRES_DATABASE:-cwe_chatbot}

            if [[ -z "$POSTGRES_USER" ]] || [[ -z "$POSTGRES_PASSWORD" ]]; then
                echo -e "${YELLOW}⚠️  Database credentials not fully configured${NC}"
                echo "   Set POSTGRES_USER and POSTGRES_PASSWORD, or provide LOCAL_DATABASE_URL"
                echo "   The app will start but database features will be limited"
            else
                export LOCAL_DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DATABASE}"
                echo -e "${GREEN}✅ LOCAL_DATABASE_URL configured${NC}"
            fi
        else
            echo -e "${GREEN}✅ Database URL already configured${NC}"
        fi
    fi

    # Check for Gemini API key
    if [[ -z "$GEMINI_API_KEY" ]]; then
        echo -e "${YELLOW}⚠️  GEMINI_API_KEY not set${NC}"
        echo "   Set it for full embedding functionality: export GEMINI_API_KEY='your-key'"
        echo "   The app will start but AI features will be limited"
    else
        echo -e "${GREEN}✅ GEMINI_API_KEY configured${NC}"
    fi
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
echo "  Mode: $([ "$PRODUCTION_MODE" == true ] && echo "Production" || echo "Development")"
echo "  Database: $([ "$WITH_DATABASE" == true ] && echo "Enabled" || echo "Disabled")"
echo "  Headless: $([ -n "$HEADLESS_FLAG" ] && echo "Yes" || echo "No")"
echo ""

# Start the application
echo -e "${GREEN}🚀 Starting CWE ChatBot...${NC}"
echo "   Stop with Ctrl+C"
echo ""

# Build the command
CMD="poetry run chainlit run main.py --host $HOST --port $PORT"
if [[ -n "$HEADLESS_FLAG" ]]; then
    CMD="$CMD $HEADLESS_FLAG"
fi

echo -e "${BLUE}Executing: $CMD${NC}"
echo ""

# Execute the command
exec $CMD
