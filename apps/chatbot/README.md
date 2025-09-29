# CWE ChatBot - Conversational Interface

AI-powered conversational assistant for MITRE Common Weakness Enumeration (CWE) analysis and cybersecurity guidance. Built with Chainlit for intuitive chat-based interactions.

## Overview

The CWE ChatBot provides a natural language interface for cybersecurity professionals to interact with the complete MITRE CWE corpus. Using Retrieval Augmented Generation (RAG) with PostgreSQL + pgvector, it delivers accurate, role-based responses grounded in official CWE documentation.

## 🎯 Key Features

### 🔧 Role-Based Personas
- **PSIRT Member** 🛡️ - Security incident response and advisory creation
- **Developer** 💻 - Secure coding practices and remediation steps
- **Academic Researcher** 🎓 - Comprehensive analysis and CWE relationships
- **Bug Bounty Hunter** 🔍 - Vulnerability discovery and exploitation patterns
- **Product Manager** 📊 - Business impact and prevention strategies
- **CWE Analyzer** 🔬 - CVE-to-CWE mapping with confidence scoring
- **CVE Creator** 📝 - Structured vulnerability descriptions

### 🧠 Advanced AI Capabilities
- **RAG-powered Search**: Semantic search across 969 CWEs with 7,913 chunks
- **Hybrid Retrieval**: Vector similarity + full-text search + alias matching
- **Hallucination Prevention**: All responses grounded in official CWE documentation
- **Context Preservation**: Multi-turn conversations with memory
- **Confidence Scoring**: Clear indicators of response reliability

### 🎛️ Interactive Features
- **Progressive Disclosure**: Adjustable detail levels to prevent information overload
- **Action Buttons**: Interactive elements for follow-up questions and analysis
- **File Upload**: Attach vulnerability reports for analysis (PDF, text, JSON, markdown)
- **Settings Panel**: Customize detail level, examples, and mitigation guidance
- **Real-time Streaming**: Token-by-token response generation

### 🔒 Security & Safety
- **Input Sanitization**: Application-level protection against prompt injection and malicious inputs
- **Session Isolation**: Secure per-user context management within the application
- **Security-First Design**: Off-topic queries are gently redirected
- **Infrastructure Security**: Rate limiting, CSRF protection, and DoS mitigation handled by deployment infrastructure
- **Defense in Depth**: Multi-layer security approach combining application and infrastructure controls

### ♿ Accessibility
- **WCAG 2.1 AA Compliance**: Accessible to users with disabilities
- **Keyboard Navigation**: Full functionality without mouse
- **Screen Reader Support**: Semantic HTML and ARIA labels
- **Responsive Design**: Works on desktop, tablet, and mobile devices

## 🏗️ Architecture

### Core Components
- **main.py** - Chainlit application entry point and event handlers
- **src/conversation.py** - Conversation flow and session state management
- **src/processing/pipeline.py** - End-to-end RAG processing pipeline
- **src/processing/analyzer_handler.py** - CWE Analyzer persona state machine
- **src/query_handler.py** - CWE corpus search and retrieval
- **src/response_generator.py** - LLM response generation with personas
- **src/input_security.py** - Input validation and sanitization

### Security Layer
- **src/security/secure_logging.py** - Production-safe error handling
- **src/input_security.py** - Multi-layer input validation
- **src/security/csrf_protection.py** - CSRF token management
- **src/security/rate_limiting.py** - DoS protection mechanisms

### UI Components
- **src/ui/messaging.py** - Chainlit UI element creation and management
- **public/custom.css** - Custom styling and theme
- **chainlit.md** - Application welcome message and help content

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Poetry for dependency management
- PostgreSQL with pgvector extension
- Gemini API key for embeddings and LLM

### Installation

1. **Navigate to chatbot directory**:
   ```bash
   cd apps/chatbot
   ```

2. **Install dependencies**:
   ```bash
   poetry install
   ```

3. **Set up environment variables**:
   ```bash
   # Copy environment template
   cp .env.example .env

   # Edit .env with your configuration
   export POSTGRES_HOST=localhost
   export POSTGRES_PORT=5432
   export POSTGRES_DATABASE=cwe
   export POSTGRES_USER=postgres
   export POSTGRES_PASSWORD=your_password
   export GEMINI_API_KEY=your_gemini_api_key
   ```

4. **Start the application**:
   ```bash
   # Run from project root to pick up configuration
   cd ../..
   poetry run chainlit run apps/chatbot/main.py
   ```

### Using the Run Script

For development, use the provided run script:
```bash
# From project root
./apps/chatbot/run_local_full.sh
```

This script:
- Sets up all required environment variables
- Starts the Chainlit application with proper configuration
- Includes health checks and error handling

## 📚 Usage Examples

### Basic Queries
```
"What is CWE-79?"
"How do I prevent SQL injection?"
"Show me examples of buffer overflow vulnerabilities"
```

### CWE Analyzer Mode
```
"I found a vulnerability where user input isn't validated before being used in a SQL query"
# Follow-up: "What are the CVSS implications?"
# Follow-up: "How severe is this for a web application?"
```

### File Analysis
1. Click the paperclip icon or "Attach Evidence" action
2. Upload vulnerability report (PDF, text, JSON, markdown)
3. Ask questions about the uploaded content

### Persona-Specific Queries
- **Developer**: "Show me secure coding examples for XSS prevention"
- **PSIRT**: "What's the business impact of CWE-89?"
- **Bug Bounty**: "What are common exploitation techniques for path traversal?"

## ⚙️ Configuration

### Environment Variables
- `POSTGRES_HOST` - Database host (default: localhost)
- `POSTGRES_PORT` - Database port (default: 5432)
- `POSTGRES_DATABASE` - Database name (default: cwe)
- `POSTGRES_USER` - Database username
- `POSTGRES_PASSWORD` - Database password
- `GEMINI_API_KEY` - Google Gemini API key for embeddings/LLM
- `MAX_INPUT_LENGTH` - Maximum input length (default: 1000)
- `MAX_OUTPUT_TOKENS` - Maximum response tokens (default: 4096)
- `ENABLE_STRICT_SANITIZATION` - Enable strict input sanitization (default: true)

### Chainlit Configuration
The application uses `.chainlit/config.toml` for UI customization:
- Custom CSS theming
- File upload settings
- Audio recording configuration
- UI behavior preferences

### Persona Settings
Users can customize their experience through the settings panel:
- **Detail Level**: Basic, Standard, Detailed
- **Include Examples**: Show/hide code examples
- **Include Mitigations**: Show/hide prevention guidance
- **Response Length**: Control response verbosity

## 🧪 Testing

### Unit Tests
```bash
# Run all unit tests
poetry run pytest tests/unit/ -v

# Test specific components
poetry run pytest tests/unit/test_conversation.py -v
poetry run pytest tests/unit/test_input_security.py -v
```

### Integration Tests
```bash
# Test full pipeline integration
poetry run pytest tests/integration/ -v

# Test Chainlit server functionality
poetry run pytest tests/integration/test_chainlit_server.py -v
```

### End-to-End Tests
```bash
# Test complete user workflows
poetry run pytest tests/e2e/ -v

# Test specific features
poetry run pytest tests/e2e/test_retrieval_full.py -v
poetry run pytest tests/e2e/test_comprehensive_ui_flows.py -v
```

### Security Tests
```bash
# Run security validation
poetry run pytest tests/unit/test_security_comprehensive.py -v
poetry run pytest tests/unit/test_input_security.py -v
```

## 🔐 Security Features

### Application-Level Security

#### Input Validation
- **Pattern Detection**: SQL injection, XSS, command injection patterns
- **Unicode Normalization**: Prevents encoding-based attacks
- **Length Limits**: Configurable maximum input sizes
- **Content Filtering**: Blocks potentially malicious content

#### Session Security
- **Isolation**: Per-user context with contamination detection
- **Timeout Management**: Configurable session timeouts
- **State Validation**: Prevents session manipulation attacks

### Infrastructure-Level Security

#### Network & Transport
- **HTTPS/TLS**: Encryption in transit handled by load balancer/ingress
- **Cloud Security**: Google Cloud Platform security controls and compliance
- **Network Isolation**: VPC and firewall rules managed at infrastructure level

#### Rate Limiting & DoS Protection
- **Message Limiting**: 30 messages per minute per user (infrastructure enforced)
- **Action Limiting**: 10 actions per minute per user (infrastructure enforced)
- **Sliding Window**: Advanced rate limiting algorithms via reverse proxy
- **DDoS Mitigation**: Cloud-level protection against distributed attacks

#### CSRF & Authentication
- **Token Management**: CSRF tokens handled by infrastructure middleware
- **OAuth Integration**: Authentication flow managed by cloud identity services
- **Session Management**: Secure session handling via infrastructure components

## 🎨 UI Customization

### Custom Styling
The application includes comprehensive CSS customization:
- **Theme Consistency**: Unified color palette and typography
- **Responsive Design**: Mobile-first approach
- **Accessibility**: High contrast ratios and keyboard navigation
- **Brand Identity**: CWE ChatBot specific styling

### Interactive Elements
- **Action Buttons**: Context-aware interactive buttons
- **Progress Indicators**: Real-time feedback during processing
- **File Upload UI**: Drag-and-drop file upload interface
- **Settings Panel**: Intuitive configuration interface

## 📊 Performance

### Response Times
- **Local Development**: <200ms p95 for most queries
- **Production Target**: <500ms p95 end-to-end response time
- **Streaming**: Real-time token-by-token response delivery

### Scalability
- **Session Management**: Efficient per-user state handling
- **Database Connection**: Connection pooling and optimization
- **Caching**: Intelligent caching for repeated queries
- **Resource Management**: Memory and CPU optimization

## 🚀 Deployment

### Local Development
```bash
# Start with hot reload
poetry run chainlit run apps/chatbot/main.py -w
```

### Production Deployment
```bash
# Build Docker image
docker build -t cwe-chatbot-app .

# Run container
docker run -p 8080:8080 \
  -e POSTGRES_HOST=your_db_host \
  -e GEMINI_API_KEY=your_key \
  cwe-chatbot-app
```

### Cloud Run Deployment
The application is designed for Google Cloud Run deployment:
- **Dockerfile.secure** - Production-ready container
- **Health checks** - Built-in health monitoring
- **Environment configuration** - Cloud-native configuration
- **Scalability** - Auto-scaling capabilities

## 📝 Development

### Code Quality
- **Formatting**: Black (line length: 88)
- **Linting**: Ruff with security rules
- **Type Checking**: MyPy for type safety
- **Testing**: Pytest with comprehensive coverage

### Contributing
1. Follow TDD principles - write tests first
2. Maintain security-first mindset
3. Add comprehensive documentation
4. Ensure accessibility compliance
5. Test across all personas and features

### Architecture Principles
- **Separation of Concerns**: Clear module boundaries
- **Security by Design**: Security integrated at every layer
- **Testability**: Comprehensive test coverage
- **Maintainability**: Clean, documented code
- **Performance**: Optimized for production use

## 📋 Known Limitations

### Current Constraints
- **English Only**: Currently supports English language queries
- **File Size Limits**: 500MB maximum file upload size
- **Session Timeout**: 1-hour session timeout for security
- **Concurrent Users**: Optimized for moderate concurrent usage

### Future Enhancements
- **Multi-language Support**: Planned internationalization
- **Advanced Analytics**: User behavior and query analytics
- **Custom Integrations**: API endpoints for external systems
- **Enhanced Personalization**: Learning user preferences

## 📖 Documentation

### Additional Resources
- **Main Project README**: `../../README.md` - Project overview and setup
- **CWE Ingestion README**: `../cwe_ingestion/README.md` - Data pipeline documentation
- **Architecture Documentation**: `../../docs/architecture/` - Technical specifications
- **Security Documentation**: `../../docs/security/` - Security analysis and testing

### API Documentation
- **REST API Spec**: `../../docs/architecture/rest-api-spec.md`
- **Database Schema**: `../../docs/architecture/database-schema.md`
- **Deployment Guide**: `../../docs/architecture/development-workflow.md`

## 🆘 Troubleshooting

### Common Issues

**Application won't start**:
```bash
# Check environment variables
env | grep -E "(POSTGRES|GEMINI)"

# Verify database connection
poetry run python -c "import psycopg; print('DB connection OK')"

# Check Chainlit installation
poetry run chainlit --version
```

**Slow responses**:
- Verify database connection performance
- Check Gemini API key and quota
- Review network connectivity to services
- Monitor system resource usage

**Authentication errors**:
- Verify Gemini API key is valid and has quota
- Check database credentials and permissions
- Ensure environment variables are properly set

### Health Checks
```bash
# Application health
curl http://localhost:8000/health

# Database health
poetry run python healthcheck.py
```

## 📄 License

This project is part of the CWE ChatBot BMad implementation, for **defensive security** use only.

---

**Ready to explore CWE security patterns?** Start the application and begin your cybersecurity analysis journey!