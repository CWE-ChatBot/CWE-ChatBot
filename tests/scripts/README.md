# Test Scripts Directory

This directory contains standalone test scripts for various security and functionality verification.

## Security Test Scripts

### Core Security Verification
- **`test_command_injection_fix.py`** - Verifies the CRI-002 command injection vulnerability fix
  - Tests secure subprocess.run() implementation
  - Validates elimination of vulnerable os.system() usage
  - Confirms command structure security
  - **Usage**: `python3 tests/scripts/test_command_injection_fix.py`

- **`test_container_security_fix.py`** - Verifies the MED-001 container image pinning fix
  - Validates SHA256-pinned Docker base images
  - Confirms supply chain attack prevention
  - Tests immutable image references
  - **Usage**: `python3 tests/scripts/test_container_security_fix.py`

- **`test_sql_injection_prevention_simple.py`** - SQL injection prevention verification
  - Tests SecureQueryBuilder implementation
  - Validates psycopg2.sql.Identifier() usage
  - Confirms parameterized query protection
  - **Usage**: `python3 tests/scripts/test_sql_injection_prevention_simple.py`

## Infrastructure Test Scripts

### Test Infrastructure Setup
- **`docker-compose.test.yml`** - Docker Compose configuration for test environment
  - Sets up PostgreSQL with pgvector extension
  - Configures test database with proper networking
  - Used for integration and database testing
  - **Usage**: `docker-compose -f tests/scripts/docker-compose.test.yml up -d`

- **`setup_database.py`** - Database initialization and setup script
  - Creates test database schema
  - Initializes pgvector extension
  - Sets up required tables for testing
  - **Usage**: `python3 tests/scripts/setup_database.py`

### Database and API Testing
- **`test_database_simple.py`** - Basic PostgreSQL connection testing
  - Verifies database connectivity
  - Tests pgvector extension availability
  - **Usage**: `python3 tests/scripts/test_database_simple.py`

- **`test_openai_api.py`** - OpenAI API integration testing
  - Tests embedding service connectivity
  - Validates API key configuration
  - Confirms text-embedding-3-small model access
  - **Usage**: `python3 tests/scripts/test_openai_api.py`

### Configuration Testing
- **`test_env_config.py`** - Environment configuration validation
  - Tests environment variable loading
  - Validates configuration completeness
  - Confirms security settings
  - **Usage**: `python3 tests/scripts/test_env_config.py`

## Usage Notes

### Running Individual Tests
```bash
# From project root directory
python3 tests/scripts/[test_name].py
```

### Setting Up Test Environment
```bash
# Start test database
docker-compose -f tests/scripts/docker-compose.test.yml up -d

# Initialize database schema
python3 tests/scripts/setup_database.py

# Verify database connection
python3 tests/scripts/test_database_simple.py
```

### Running All Security Tests
```bash
# Command injection security
python3 tests/scripts/test_command_injection_fix.py

# Container security
python3 tests/scripts/test_container_security_fix.py

# SQL injection prevention
python3 tests/scripts/test_sql_injection_prevention_simple.py
```

### Test Dependencies
- Most tests are standalone with minimal dependencies
- Some tests require specific environment variables (documented in individual test files)
- Database tests require PostgreSQL connection
- API tests require valid OpenAI API keys

### Security Test Standards
- All security tests must pass for production deployment
- Tests are designed to fail loudly if security issues are detected
- Each test provides detailed output for debugging
- Critical vulnerabilities cause immediate test failure

## Test Organization

```
tests/
├── scripts/              # Standalone test scripts (this directory)
├── unit/                # Unit tests for individual components
├── integration/         # Integration tests for component interaction
└── security/           # Comprehensive security test suites
```

## Contributing

When adding new test scripts:
1. Follow the naming convention `test_[feature]_[type].py`
2. Include clear docstrings and usage instructions
3. Add appropriate error handling and detailed output
4. Update this README with script documentation
5. Ensure tests can be run from project root directory