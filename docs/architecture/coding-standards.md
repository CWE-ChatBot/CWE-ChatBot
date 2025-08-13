# Coding Standards

This section defines the mandatory security requirements for AI and human developers, focusing on implementation-specific rules, referencing security tools from the Tech Stack, and defining clear patterns for common scenarios. These rules directly impact code generation.

## Core Standards

  * **Languages & Runtimes:** Python 3.10+ is the primary development language.
  * **Style & Linting:**
      * **Code Formatting:** [Black](https://github.com/psf/black) for uncompromising code formatting.
      * **Linting:** [Ruff](https://astral.sh/ruff) for fast static code analysis and adherence to style conventions, acting as a linter and formatter.
      * **Type Checking:** [MyPy](https://mypy-lang.org/) for static type checking across the entire codebase.
  * **Automation:** All formatting, linting (**specifically Ruff**), and type checking tools will be integrated into pre-commit hooks (e.g., via `pre-commit.com`), **code generation hooks**, and continuously run as part of the CI/CD pipeline (NFR47, NFR48).

## Naming Conventions

Consistent naming is crucial for code readability and maintainability.

| Element | Convention | Example |
| :--- | :--- | :--- |
| **Modules/Files** | `snake_case` | `user_config_service.py` |
| **Classes** | `PascalCase` | `UserConfigService` |
| **Functions/Methods** | `snake_case` | `get_user_preferences` |
| **Variables** | `snake_case` | `user_data`, `cwe_id` |
| **Constants** | `UPPER_SNAKE_CASE` | `DEFAULT_TIMEOUT_SECONDS` |

## Critical Rules

These are non-negotiable rules specifically highlighted to prevent common pitfalls and enforce architectural principles for both human and AI developers:

  * **Secret Handling:** **NEVER hardcode secrets** (API keys, credentials, sensitive configuration values). Always retrieve them securely from environment variables, dedicated secret management services (e.g., Google Secret Manager), or Chainlit's secure configuration mechanisms (NFR33, NFR31).
  * **Direct Database Access:** All direct database interactions (e.g., raw SQL queries, ORM calls) MUST be encapsulated within the **Repository Pattern** (as defined in NFR5). Business logic services should interact only with these repositories, not directly with database clients or ORMs.
  * **Error Handling:** All external API calls and critical business logic paths MUST include robust error handling (e.g., `try-except` blocks, custom exceptions), ensuring graceful degradation (NFR38) and clear user feedback (FR17, FR26).
  * **LLM Prompt Management:** All LLM prompts used for generating responses MUST be version-controlled (NFR31). Sensitive user data (PII or confidential code) MUST be stripped or anonymized before being sent to external LLMs (NFR33).
  * **Data Validation:** All incoming data, especially from external sources (API requests, user messages, file uploads), MUST be rigorously validated at the earliest possible entry point to prevent injection attacks and ensure data integrity (NFR8).
  * **Logging:** Consistent and structured logging (NFR11, NFR40) must be applied across all services. Critical log messages (WARNING, ERROR, CRITICAL) MUST include sufficient context (correlation IDs, user/session IDs) for effective debugging and auditing.
  * **Code Duplication:** Developers should actively strive to minimize code duplication by abstracting common logic into reusable functions, classes, or shared packages (NFR48). Automated tools will flag high duplication.
  * **Documentation:** Key interfaces, complex functions, and architectural decisions must have clear docstrings and supporting READMEs (NFR49). This aligns with the "documentation as contracts" principle.

## Language-Specific Guidelines (Python)

  * **Type Hinting:** Mandatory for all function signatures, class attributes, and complex data structures (`mypy` will enforce this).
  * **Asynchronous Programming:** Use `async/await` syntax with `asyncio` for all I/O-bound operations (e.g., database calls, external HTTP requests, file I/O) to ensure non-blocking execution and optimize performance.
  * **Dependency Injection:** Favor explicit dependency injection over global variables or direct instantiations within services to improve testability and modularity.
