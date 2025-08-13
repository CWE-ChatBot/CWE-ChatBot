# Database Schema

This section translates the conceptual data models into concrete database schemas, considering the selected database types (PostgreSQL for structured data and a Vector Database for embeddings). It includes definitions for tables, indexes, constraints, and relationships.

## Traditional Database Schema (PostgreSQL DDL)

The following SQL DDL (Data Definition Language) defines the schema for the PostgreSQL database, which will store user data, conversation history, and configuration.

```sql
-- Table: public.users
CREATE TABLE IF NOT EXISTS public.users
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    oauth_provider_type VARCHAR(50),
    oauth_provider_user_id VARCHAR(255),
    role VARCHAR(50) NOT NULL, -- e.g., 'Developer', 'PSIRT Member', 'Admin' (FR4)
    preferences JSONB DEFAULT '{}'::jsonb, -- User-specific settings (JSONB for flexibility)
    llm_api_key_id UUID, -- Reference to a securely stored API key (if internal management is implemented)
    llm_model_config JSONB, -- Config for BYO self-hosted LLM (FR29)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE public.users IS 'Stores user accounts, preferences, and BYO LLM configurations.';
COMMENT ON COLUMN public.users.llm_api_key_id IS 'Foreign key or identifier for securely stored LLM API keys.';
COMMENT ON COLUMN public.users.llm_model_config IS 'JSONB configuration for Bring Your Own self-hosted LLM models.';

-- Optional: Add index on oauth_provider_user_id for faster lookups if frequently used for authentication
CREATE INDEX IF NOT EXISTS idx_users_oauth_id ON public.users (oauth_provider_user_id);


-- Table: public.conversations
CREATE TABLE IF NOT EXISTS public.conversations
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    session_id UUID UNIQUE NOT NULL, -- Unique identifier for a continuous chat session (NFR35)
    start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP WITH TIME ZONE,
    current_context JSONB, -- Summary of conversational context (NFR35)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE public.conversations IS 'Stores high-level conversation history and session context.';
CREATE INDEX IF NOT EXISTS idx_conversations_user_id ON public.conversations (user_id);
CREATE INDEX IF NOT EXISTS idx_conversations_session_id ON public.conversations (session_id);


-- Table: public.messages
CREATE TABLE IF NOT EXISTS public.messages
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES public.conversations(id) ON DELETE CASCADE,
    sender VARCHAR(10) NOT NULL, -- 'user' or 'chatbot'
    content TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_feedback_eligible BOOLEAN DEFAULT FALSE, -- Indicates if this bot response can receive feedback (FR27)
    feedback_provided BOOLEAN DEFAULT FALSE, -- True if user has given feedback for this response
    cwe_ids_suggested VARCHAR(50)[], -- Array of CWE IDs suggested in this message (for traceability)
    llm_model_used VARCHAR(255) -- Name or ID of the LLM model used for this message
);

COMMENT ON TABLE public.messages IS 'Stores individual messages within a conversation.';
CREATE INDEX IF NOT EXISTS idx_messages_conversation_id ON public.messages (conversation_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON public.messages (timestamp);
```

**Rationale for Traditional Database Schema:**

  * **UUIDs for IDs:** Provides globally unique identifiers, suitable for distributed systems and potential future microservice expansion.
  * **`ON DELETE CASCADE`:** Ensures referential integrity by automatically deleting related conversations and messages if a user is removed.
  * **`JSONB` for flexible data:** `preferences` and `current_context` are `JSONB` to allow flexible, schemaless storage of varying user settings and conversational context summaries.
  * **Indexing:** Basic indexes are added for common lookup fields (`user_id`, `session_id`, `conversation_id`, `timestamp`) to optimize query performance.
  * **Traceability:** `cwe_ids_suggested` and `llm_model_used` attributes support tracking chatbot performance and BYO LLM usage.

## Vector Database Conceptual Schema (e.g., Pinecone)

For the Vector Database, the structure is optimized for high-dimensional vector search. The exact implementation will depend on the chosen provider (e.g., Pinecone, Weaviate, Qdrant), but the conceptual model for each stored item (`vector` or `record`) will typically include:

  * **Index Definition:** An index will be configured with a specific vector `dimension` (matching the output size of our chosen embedding model), and a `metric type` (e.g., cosine similarity for text embeddings).
  * **Vector Object Structure (per CWE entry):**
      * `id`: String (e.g., 'CWE-79', 'CWE-123'), serving as a unique identifier for the CWE entry in the vector database.
      * `values`: `float[]` (the actual numerical vector embedding of the CWE text). This is the core data for similarity search.
      * `metadata`: `JSONB` (or equivalent schema-less object) containing crucial CWE attributes for filtering and retrieval, enabling post-query filtering and enriching LLM prompts. This metadata will include:
          * `cwe_id`: String (Official CWE ID)
          * `name`: String (Official CWE Name)
          * `short_description`: String (Concise summary)
          * `full_text`: String (The original or pre-processed full text of the CWE entry from which the embedding was derived; used for RAG context)
          * `version`: String (CWE version from MITRE this embedding corresponds to, NFR18)
          * `last_updated`: Timestamp (When this specific CWE entry was last updated in our database)

**Rationale for Vector Database Schema:**

  * **Optimized for Search:** Focuses on the core components needed for efficient vector similarity search.
  * **RAG Support:** The `full_text` in metadata is crucial for passing relevant context to the LLM during RAG.
  * **Metadata Richness:** Including metadata allows for filtering results before sending to the LLM (e.g., only show CWEs related to web applications) and provides additional context for response generation.

**Security Considerations:**

* **CRITICAL:** The Vector Database, which provides context for the RAG process, **MUST** only be populated with public, non-sensitive data (e.g., the official CWE corpus). This is a fundamental control to prevent the leakage of confidential information to user-configured BYO LLM endpoints, as identified in threat **I-4**.
