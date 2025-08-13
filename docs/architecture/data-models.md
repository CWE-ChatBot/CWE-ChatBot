# Data Models

This section defines the core data models and entities that will underpin the CWE ChatBot application. These models describe the structure of the information managed by the system, including user data, conversational history, and the representation of the CWE corpus.

## User

  * **Purpose:** To manage user accounts, preferences, and authentication details for both centrally-hosted and self-hosted deployments. It also securely stores configurations for "Bring Your Own" (BYO) LLM API keys and models (FR28, FR29).
  * **Key Attributes:**
      * `id`: UUID, Primary Key (Unique identifier for the user)
      * `email`: String, Unique (User's primary email address)
      * `oauth_provider_type`: String, Nullable (e.g., 'google', 'microsoft', 'github' - Identifies the OAuth provider)
      * `oauth_provider_user_id`: String, Nullable (The unique user ID provided by the OAuth provider)
      * `role`: String (e.g., 'PSIRT Member', 'Developer', 'Academic Researcher', 'Bug Bounty Hunter', 'Product Manager', 'Admin') - supports FR4
      * `preferences`: JSONB/Text (Stores user-specific settings, e.g., preferred response verbosity)
      * `llm_api_key_id`: UUID, Nullable (Reference to a securely stored LLM API key record for FR28)
      * `llm_model_config`: JSONB, Nullable (Configuration details for BYO self-hosted LLM model for FR29)
      * `created_at`: Timestamp (Record creation time)
      * `updated_at`: Timestamp (Last update time)
  * **Relationships:** One-to-many with Conversation.
  * **TypeScript Interface:**
    ```typescript
    interface User {
      id: string;
      email: string;
      // Fields for passwordless OAuth
      oauthProviderType?: string; // e.g., 'google', 'microsoft', 'github'
      oauthProviderUserId?: string; // User ID from the OAuth provider
      role: 'PSIRT Member' | 'Developer' | 'Academic Researcher' | 'Bug Bounty Hunter' | 'Product Manager' | 'Admin';
      preferences?: { [key: string]: any };
      llmApiKeyId?: string; // Reference to securely stored API key record (for FR28)
      llmModelConfig?: { // For FR29
        type: 'api' | 'self-hosted'; // Specifies if it's an API endpoint or a self-hosted instance
        endpoint?: string; // URL for API or self-hosted model
        modelName?: string; // Name of the model (e.g., "llama-3-8b")
        // Additional configuration parameters as needed by the model
      };
      createdAt: string;
      updatedAt: string;
    }
    ```

## Conversation

  * **Purpose:** To store the history of interactions between a specific user and the chatbot, enabling context preservation across turns and sessions (NFR35). This data can be used for feedback loops and analysis.
  * **Key Attributes:**
      * `id`: UUID, Primary Key (Unique identifier for the conversation)
      * `user_id`: UUID, Foreign Key to User (Links to the user who had the conversation)
      * `session_id`: UUID, Unique (A transient ID to group related messages within a continuous interaction, can expire after inactivity)
      * `start_time`: Timestamp (When the conversation began)
      * `end_time`: Timestamp, Nullable (When the conversation ended or became inactive)
      * `current_context`: JSONB/Text (Stores a summary or key elements of the current conversational context to aid continuity)
      * `created_at`: Timestamp (Record creation time)
  * **Relationships:** One-to-many with Message.
  * **TypeScript Interface:**
    ```typescript
    interface Conversation {
      id: string;
      userId: string;
      sessionId: string;
      startTime: string;
      endTime?: string;
      currentContext?: { [key: string]: any }; // Summary or key elements of context (for NFR35)
      createdAt: string;
    }
    ```

## Message

  * **Purpose:** To store individual chat messages, including both user queries and chatbot responses, as part of a larger conversation. This forms the granular record of interaction.
  * **Key Attributes:**
      * `id`: UUID, Primary Key (Unique identifier for the message)
      * `conversation_id`: UUID, Foreign Key to Conversation (Links message to its parent conversation)
      * `sender`: String ('user', 'chatbot') (Indicates who sent the message)
      * `content`: Text (The actual message text)
      * `timestamp`: Timestamp (When the message was sent/received)
      * `is_feedback_eligible`: Boolean, Default FALSE (Indicates if this specific chatbot response is eligible for user feedback, FR27)
      * `feedback_provided`: Boolean, Default FALSE (True if user has given feedback for this response)
      * `cwe_ids_suggested`: VARCHAR(50)[], Nullable (Array of CWE IDs suggested/discussed in this message, for traceability)
      * `llm_model_used`: VARCHAR(255), Nullable (ID or name of the LLM model used to generate this specific response, useful for auditing BYO models)
  * **Relationships:** Many-to-one with Conversation.
  * **TypeScript Interface:**
    ```typescript
    interface Message {
      id: string;
      conversationId: string;
      sender: 'user' | 'chatbot';
      content: string;
      timestamp: string;
      isFeedbackEligible?: boolean; // For FR27
      feedbackProvided?: boolean;
      cweIdsSuggested?: string[]; // For traceability
      llmModelUsed?: string; // For auditing BYO models (FR28, FR29)
    }
    ```

## CWE\_Embedding (Conceptual model for Vector Database)

  * **Purpose:** To store the vector embeddings and essential metadata of CWE entries, optimized for semantic search and Retrieval Augmented Generation (RAG). This is the core knowledge base for the chatbot's intelligence.
  * **Key Attributes:**
      * `cwe_id`: String (e.g., 'CWE-79'), Primary Key / Unique ID (Reference to the official CWE)
      * `embedding`: Vector (float[]) (The numerical representation of the CWE text, for similarity search)
      * `name`: String (Official CWE Name)
      * `short_description`: Text (Concise summary of the CWE)
      * `full_text`: Text (The original or pre-processed full text of the CWE entry from which the embedding was derived; used for RAG context)
      * `version`: String (CWE version from MITRE this embedding corresponds to, NFR18)
      * `last_updated`: Timestamp (When this specific CWE entry was last updated in our database)
  * **Relationships:** None directly in the Vector Database itself, but linked conceptually to messages via `cwe_ids_suggested`.
  * **TypeScript Interface:**
    ```typescript
    interface CweEmbedding {
      cweId: string;
      embedding: number[];
      name: string;
      shortDescription: string;
      fullText: string;
      version: string;
      lastUpdated: string;
    }
    ```
