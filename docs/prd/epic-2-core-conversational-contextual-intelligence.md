# Epic 2: Core Conversational & Contextual Intelligence

**Epic Goal:** Implement robust NLU and the **core Retrieval Augmented Generation (RAG) process**, including advanced information retrieval/synthesis and initial role-based context awareness, to provide accurate and tailored CWE responses. This epic focuses on building the core AI intelligence and minimizing hallucination (FR1-FR6, FR12-FR17).

## Story 2.1: Implement Core NLU & Initial CWE Query Matching

**As a** chatbot user,
**I want** the system to understand my natural language questions about CWEs,
**so that** I can find relevant information without needing specific CWE IDs.

### Acceptance Criteria

1.  **AC1:** The Chainlit application successfully receives and processes natural language input from the user.
2.  **AC2:** Basic Natural Language Understanding (NLU) capabilities are integrated (e.g., leveraging an underlying LLM for intent recognition and entity extraction related to security concepts).
3.  **AC3:** The system can reliably identify direct mentions of specific CWE IDs (e.g., "Tell me about CWE-79") within user queries.
4.  **AC4:** For identified CWE IDs, the system retrieves and displays the basic name and a concise short description from the vector database (using data ingested in Story 1.3), **verifiable by sending a test query via a local script or the Chainlit UI.**
5.  **AC5:** The system gracefully handles unrecognized or out-of-scope queries by responding with a polite message indicating it doesn't understand or cannot fulfill the request (FR17), **verifiable via sending diverse test queries locally.**

## Story 2.2: Contextual Retrieval & Basic Follow-up Questions

**As a** chatbot user,
**I want** the system to provide contextually relevant CWE information and allow simple follow-up questions,
**so that** I can explore related details more deeply.

### Acceptance Criteria

1.  **AC1:** When a CWE is successfully identified from a query, the system retrieves and presents comprehensive information (e.g., full description, common consequences, relationships to other CWEs or categories) from the vector database (NFR19), **verifiable by local queries that return expected structured data.**
2.  **AC2:** The system can understand and respond accurately to simple follow-up questions that are directly related to the previously discussed CWE context (e.g., "What are its common consequences?", "Give me an example", "How does this relate to X?"), **verifiable through interactive local testing in the Chainlit UI.**
3.  **AC3:** Responses to follow-up questions are extracted or synthesized directly from the detailed, stored CWE metadata, ensuring factual accuracy, **verifiable by comparing chatbot output against raw CWE data locally.**
4.  **AC4:** The ChatBot can respond to queries asking for "similar CWEs" by retrieving and listing related CWEs identified within the corpus (FR6).
5.  **AC5:** For detailed information, the ChatBot initially provides a concise answer or summary, with an explicit option or prompt for the user to request more in-depth details (FR5, NFR21).

## Story 2.3: Role-Based Context Awareness & Hallucination Mitigation

**As a** PSIRT member or developer,
**I want** the chatbot to tailor its CWE information based on my role, and I need to trust that the information is accurate,
**so that** I can get actionable and reliable advice.

### Acceptance Criteria

1.  **AC1:** The ChatBot explicitly prompts the user to select their role (e.g., PSIRT member, Developer, Academic Researcher, Bug Bounty Hunter, Product Manager) at the start of a new session, or provides a command/option to change role during a session (FR4).
2.  **AC2:** For a given CWE, the system can dynamically tailor its response content and emphasis based on the selected role (e.g., for Developers, prioritize code-level remediation steps; for PSIRT, focus on impact, advisory language, and risk assessment details) (FR4), **verifiable by testing different role selections in the Chainlit UI and observing response variations.**
3.  **AC3:** Core AI mechanisms are implemented to actively minimize AI hallucination, such as directly citing specific passages from the CWE corpus for critical information or indicating when information is derived rather than directly quoted (NFR6, FR12), **verifiable by local automated tests that flag unexpected or uncited responses for known queries.**
4.  **AC4:** The system displays a confidence score or a prioritization order alongside its CWE suggestions or answers (FR15).
5.  **AC5:** When the system's confidence in a mapping or a response is low or information is insufficient, it clearly states this limitation and suggests ways the user can refine their query to get a better result (FR17, NFR26), **verifiable through local tests using ambiguous inputs.**
