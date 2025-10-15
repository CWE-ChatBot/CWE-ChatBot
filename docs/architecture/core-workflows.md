# Core Workflows

This section illustrates key system workflows using sequence diagrams, highlighting the interactions between components and the flow of data. These diagrams clarify architectural decisions and complex interactions.

## User Query and RAG-based Response Generation

  * **Purpose:** To detail the full interaction flow from a user submitting a query to the ChatBot generating an intelligent, context-aware response using the Retrieval Augmented Generation (RAG) process.
  * **Key Components Involved:** User, Chatbot Application (Chainlit Core), NLP/AI Service, PostgreSQL (pgvector), LLM/Embedding Model.
  * **Clarifies Architectural Decisions:** This flow demonstrates the interaction between the core Chainlit app, the logical NLP/AI service, the vector database for retrieval, and the LLM for generation. It also highlights the RAG pattern.

### Sequence Diagram

```mermaid
sequenceDiagram
    participant U as User
    participant CA as Chatbot Application Chainlit Core
    participant NAI as NLP/AI Service
    participant PG as PostgreSQL (pgvector)
    participant LLM as LLM/Embedding Model

    U->>CA: 1. Enters Query e.g. How to prevent XSS?
    activate CA
    CA->>NAI: 2. Send Query for NLU & Embedding FR1
    activate NAI
    NAI->>LLM: 3. Request Query Embedding
    activate LLM
    LLM-->>NAI: 4. Provide Query Embedding
    deactivate LLM
    NAI->>PG: 5. Search pgvector for relevant CWEs FR2
    activate PG
    PG-->>NAI: 6. Return Top N relevant CWE chunks
    deactivate PG
    NAI->>LLM: 7. Formulate Prompt Query + Relevant CWE Chunks for RAG
    activate LLM
    LLM-->>NAI: 8. Generate Contextual Response
    deactivate LLM
    NAI-->>CA: 9. Send Generated Response
    deactivate NAI
    CA->>U: 10. Display Response to User FR5
    deactivate CA
```

**Rationale for Sequence Diagram:** This diagram clearly visualizes the multi-step process of an AI-powered conversational response. It maps how the user's query travels through the system, gets enriched with relevant data from pgvector in PostgreSQL (RAG), interacts with the LLM, and finally delivers a tailored answer back to the user. It explicitly ties into the FRs and NFRs related to NLU, retrieval, response generation, and hallucination mitigation.
