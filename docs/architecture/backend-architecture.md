# Backend Architecture

This section provides specific architectural details for the backend components of the CWE ChatBot, focusing on service organization, database interaction, and the implementation of authentication and authorization.

## Service Architecture

We will adhere to a **Serverless-first approach** where feasible, primarily utilizing Google Cloud Run for containerized services and potentially Cloud Functions for event-driven processing. This structure supports modularity, independent scalability, and aligns with our cost-efficiency goals (NFR2).

  * **Function/Service Organization:** Within the monorepo, logical services will be organized into distinct Python modules or packages, fostering clear separation of concerns.
      * `apps/chatbot/`: Contains the main Chainlit application, which orchestrates calls to other logical services.
      * `services/nlp_ai/`: Encapsulates NLP/AI processing logic, RAG implementation, and LLM interactions. This could be deployed as part of the main Chainlit app initially or as a separate Cloud Run service for dedicated scaling.
      * `services/cwe_ingestion/`: Houses the data ingestion pipeline, deployed as a Cloud Function for scheduled runs or a separate Cloud Run service for on-demand processing.
      * `services/user_auth/`: Manages user authentication and authorization logic, integrated via Chainlit hooks or as a dedicated internal microservice.
      * `packages/shared/`: Contains common data models (e.g., User, Conversation), utilities, and API interface definitions to be shared across all services.
  * **Function/Service Template (Conceptual Python Module):** This illustrates how a reusable backend service module might be structured, demonstrating its independence from the main Chainlit app's direct request handling.
    ```python
    # Example: services/nlp_ai/processing.py
    from typing import List, Dict
    # Assume imports for vector_db_client, llm_client, cwe_data_model

    async def get_cwe_embedding(text: str) -> List[float]:
        """Generates a vector embedding for the given text."""
        # Call LLM_Embedding Model (BYO/External) to get embedding
        pass

    async def search_cwe_corpus(embedding: List[float], top_k: int = 5) -> List[Dict]:
        """Searches the vector database for relevant CWEs."""
        # Call VectorDB to perform similarity search
        pass

    async def generate_rag_response(query: str, relevant_cwe_data: List[Dict], llm_model_config: Dict) -> str:
        """Generates a contextual response using RAG."""
        # Formulate prompt using query and cwe_data, call LLM
        pass
    ```

## Database Architecture

Our strategy involves a hybrid approach, combining a traditional relational database for structured application data with a specialized vector database for efficient semantic search of the CWE corpus.

  * **Schema Design:** The detailed SQL DDL for PostgreSQL (`users`, `conversations`, `messages` tables) and the conceptual schema for the Vector Database (CWE embeddings) are defined in the dedicated [Database Schema](https://www.google.com/search?q=%23database-schema) section.
  * **Data Access Layer (Repository Pattern):** All direct database interactions will be abstracted behind a Repository Pattern (NFR5). This provides a clean interface for services, promotes testability, and allows for potential future changes in the underlying database technology with minimal impact on business logic.
    ```python
    # Example: packages/shared/data_access/cwe_repository.py
    from typing import List, Dict
    # Assume imports for vector_db_client, TraditionalDB_Session

    class CweRepository:
        def __init__(self, vector_db_client, traditional_db_session):
            self.vector_db_client = vector_db_client
            self.traditional_db_session = traditional_db_session

        async def get_cwe_metadata(self, cwe_id: str) -> Dict:
            """Retrieves structured CWE metadata from the traditional DB."""
            # Use self.traditional_db_session to query PostgreSQL
            pass

        async def search_cwe_embeddings(self, query_embedding: List[float], limit: int) -> List[str]:
            """Performs vector search for CWE IDs."""
            # Use self.vector_db_client to query VectorDB
            pass
    ```

## Authentication and Authorization Architecture

Authentication will be **passwordless** using OAuth 2.0 / OpenID Connect. Authorization will be role-based, ensuring secure access control (NFR34).

  * **Auth Flow Diagram (Mermaid):** This sequence illustrates the user authentication flow via an external OAuth provider.
    ```mermaid
    sequenceDiagram
        participant U as User
        participant UI as Chatbot UI
        participant IDP as OAuth Provider e.g. Google
        participant CA as Chatbot Application
        participant UM as User Management Service/DB

        U->>UI: 1. Clicks "Sign In"
        UI->>IDP: 2. Redirects for Authorization Request
        IDP->>U: 3. Displays Login/Consent Screen
        U->>IDP: 4. Grants Consent
        IDP->>UI: 5. Redirects with Authorization Code
        UI->>CA: 6. Exchanges Code for Access Token
        activate CA
        CA->>IDP: 7. Validate Code & Request Token
        IDP-->>CA: 8. Returns Access Token & ID Token
        CA->>UM: 9. Validate/Create User Record & Role NFR34
        activate UM
        UM-->>CA: 10. User ID & Role Confirmed/Created
        deactivate UM
        CA-->>UI: 11. Stores Session/Token & Redirects to Chat
        deactivate CA
        UI->>CA: 12. Subsequent Authenticated Requests with Token
    ```
  * **Middleware/Guards:** Authentication and authorization checks will be enforced at the API entry points of relevant services. Chainlit's built-in authentication hooks will be utilized to protect conversational endpoints. For separately deployed microservices (if applicable), standard Python web framework middleware will apply.
    ```python
    # Example: Conceptual Authentication Middleware/Decorator
    from functools import wraps
    from fastapi import Request, HTTPException, Depends
    # Assume imports for token_validation_util, user_repo, UserRole

    def require_role(allowed_roles: List[str]):
        def decorator(func):
            @wraps(func)
            async def wrapper(request: Request, *args, **kwargs):
                auth_header = request.headers.get("Authorization")
                if not auth_header or not auth_header.startswith("Bearer "):
                    raise HTTPException(status_code=401, detail="Bearer token missing or invalid")
                token = auth_header.split(" ")[1]
                
                try:
                    payload = token_validation_util.verify_oauth_jwt(token) # Verifies JWT and returns payload
                    user_email = payload.get("email")
                    if not user_email:
                        raise HTTPException(status_code=403, detail="Invalid token payload: missing email")
                    
                    user = await user_repo.get_user_by_email(user_email) # Fetch user from our DB
                    if not user or user.role not in allowed_roles:
                        raise HTTPException(status_code=403, detail="Insufficient privileges")
                    
                    # Store user in request state or pass to function
                    request.state.user = user
                    return await func(request, *args, **kwargs)
                except Exception as e:
                    print(f"Auth/AuthZ Error: {e}")
                    raise HTTPException(status_code=401, detail="Invalid token or access denied")
            return wrapper
        return decorator

    # Usage in a protected endpoint (e.g., in a separate microservice)
    # @app.get("/admin/dashboard")
    # @require_role(["Admin"])
    # async def get_admin_dashboard(request: Request):
    #     user = request.state.user # Access user object from state
    #     return {"message": f"Welcome Admin {user.email}"}
    ```
