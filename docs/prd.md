# CWE ChatBot Product Requirements Document (PRD)

## Goals and Background Context

### Goals

  * Revolutionize interaction with the CWE corpus by shifting to a dynamic, interactive conversational interface.
  * Enable PSIRT members to efficiently create vulnerability advisories.
  * Contribute to a 20% decrease in the average Mean Time To Remediate (MTTR) for vulnerabilities linked to CWEs for developers by providing faster and more effective access to remediation information within 18 months of launch.
  * Support a 50% increase in the proactive identification of common CWE patterns across product lines by Product Managers through enhanced interactive analysis capabilities within 24 months, leading to actionable prevention strategies.
  * Achieve high user satisfaction with the ChatBot's clarity and actionability.

### Background Context

The current methods for engaging with the extensive Common Weakness Enumeration (CWE) corpus are largely static, relying on search and browse functions. While comprehensive, this approach creates significant friction for various cybersecurity professionals who require immediate, contextual, and actionable insights to perform their tasks under tight deadlines or for strategic planning. The CWE ChatBot project directly addresses this gap by leveraging conversational AI to provide tailored, dynamic interactions, ultimately enhancing the efficiency and accuracy of vulnerability management and prevention.

### Change Log

| Date         | Version | Description                 | Author      |
| :----------- | :------ | :-------------------------- | :---------- |
| July 18, 2025 | 1.0     | Initial PRD draft based on Project Brief | John (PM)   |
| July 18, 2025 | 1.1     | Incorporated detailed User Stories and Non-User Requirements with linkable IDs; Revised Business Objectives for clearer accountability; Clarified NFR grouping. | John (PM)   |
| July 18, 2025 | 1.2     | Clarified FR19, NFR33, NFR34, NFR41 for dual-hosting model; Added FR28, FR29 for BYO LLM/Key. | John (PM) |
| July 18, 2025 | 1.3     | Ensured all NFRs consistently use the "NFRx: Category - Subcategory (Optional) - Description" format. | John (PM) |

## Requirements

### Functional

1.  **FR1:** The ChatBot shall accurately interpret natural language queries related to CWEs, vulnerabilities, and security best practices.
2.  **FR2:** The ChatBot shall retrieve and synthesize relevant information from the CWE corpus based on user queries.
3.  **FR3:** The ChatBot shall support basic conversational turns, allowing users to ask follow-up questions to refine information.
4.  **FR4:** The ChatBot shall adapt response content and detail based on the user's specified or inferred role (e.g., PSIRT member, Developer).
5.  **FR5:** The ChatBot shall provide both concise summaries and detailed explanations of CWEs upon user request.
6.  **FR6:** The ChatBot shall automatically suggest related CWEs, common attack patterns (e.g., OWASP Top 10), or relevant mitigation strategies based on the conversation context.
7.  \<a id="USR\_PSIRT\_INPUT"\>\</a\>**FR7: USR\_PSIRT\_INPUT** As a PSIRT member, the ChatBot MUST enable input of bug reports and issue summaries to quickly receive prioritized CWE recommendations under high time pressure.
8.  \<a id="USR\_DEV\_SOURCE\_CODE"\>\</a\>**FR8: USR\_DEV\_SOURCE\_CODE** As a developer, the ChatBot MUST support submission of source code and patch details to accurately identify correct CWE mappings without delaying bug fixes.
9.  \<a id="USR\_ACADEMIC\_ANALYSIS"\>\</a\>**FR9: USR\_ACADEMIC\_ANALYSIS** As an academic researcher, the ChatBot SHOULD enable exploration of CWE mappings with limited code context for effective analysis of vulnerability trends and detection techniques.
10. \<a id="USR\_BUG\_BOUNTY\_MAPPING"\>\</a\>**FR10: USR\_BUG\_BOUNTY\_MAPPING** As a bug bounty hunter, the ChatBot SHOULD support mapping vulnerabilities based on exploit information to ensure accurate and credible CWE reporting.
11. \<a id="USR\_PM\_RESOURCE\_ALLOCATION"\>\</a\>**FR11: USR\_PM\_RESOURCE\_ALLOCATION** As a product manager, the ChatBot SHOULD enable analysis of common weaknesses at scale to effectively allocate resources and implement preventive measures.
12. \<a id="USR\_CHATBOT\_ACCURACY"\>\</a\>**FR12: USR\_CHATBOT\_ACCURACY** As a user, the ChatBot MUST provide correct CWE IDs and names without hallucination to trust chatbot recommendations.
13. \<a id="USR\_CHATBOT\_ID\_INPUT"\>\</a\>**FR13: USR\_CHATBOT\_ID\_INPUT** As a user, the ChatBot MUST accurately accept and interpret input CWE IDs without confusing similar IDs (e.g., CWE-79 vs. CWE-89).
14. \<a id="USR\_CHATBOT\_CWE\_UPDATES"\>\</a\>**FR14: USR\_CHATBOT\_CWE\_UPDATES** As a user, the ChatBot MUST remain up-to-date with the latest CWE versions to ensure mappings reflect current standards.
15. \<a id="USR\_CHATBOT\_PRIORITY\_CONFIDENCE"\>\</a\>**FR15: USR\_CHATBOT\_PRIORITY\_CONFIDENCE** As a user, the ChatBot MUST receive prioritized and confidence-annotated CWE suggestions (limited in number) to efficiently focus on relevant mappings.
16. \<a id="USR\_CHATBOT\_REASONING"\>\</a\>**FR16: USR\_CHATBOT\_REASONING** As a user, the ChatBot SHOULD explain its reasoning (e.g., quoting mapping notes) to understand CWE recommendations.
17. \<a id="USR\_CHATBOT\_INSUFFICIENT\_INFO"\>\</a\>**FR17: USR\_CHATBOT\_INSUFFICIENT\_INFO** As a user, the ChatBot MUST gracefully handle insufficient information (e.g., indicate "not enough information") to avoid misleading confidence.
18. \<a id="USR\_CHATBOT\_FEEDBACK\_LEARNING"\>\</a\>**FR18: USR\_CHATBOT\_FEEDBACK\_LEARNING** As a user, the ChatBot SHOULD learn and continuously update its responses based on user feedback, interactions, and logs.
19. \<a id="USR\_CHATBOT\_CONFIDENTIALITY"\>\</a\>**FR19: USR\_CHATBOT\_CONFIDENTIALITY** As a user, I MUST have confidence in the ChatBot's handling of confidential information; specifically, for **self-hosted deployments**, the ChatBot MUST guarantee that internal confidential information never leaves the user's defined domain or company. For **centrally-hosted deployments**, the ChatBot SHALL ensure robust data encryption, strict access controls, and adherence to contractual data privacy agreements, preventing unauthorized access by third parties (including chatbot creators).
20. \<a id="FR\_CONFIDENCE\_HANDLING"\>\</a\>**FR20: User Confidence Handling** The ChatBot shall handle and display different confidence levels for CWE mapping recommendations.
21. \<a id="FR\_EXPLANATION\_LEVEL"\>\</a\>**FR21: User Explanation Level** The ChatBot shall provide explanations for CWE mapping recommendations adaptable to the user's desired level of detail.
22. \<a id="FR\_MAPPING\_HISTORY"\>\</a\>**FR22: Mapping History Management** The ChatBot SHOULD allow users to save or export their CWE mapping history.
23. \<a id="FR\_BATCH\_PROCESSING"\>\</a\>**FR23: Processing Scope** The ChatBot SHOULD provide options for single vulnerability analysis and consider batch processing for future phases.
24. \<a id="FR\_COLLABORATION"\>\</a\>**FR24: Collaboration & Sharing** The ChatBot SHOULD provide functionality for users to collaborate or share CWE mappings with team members.
25. \<a id="FR\_FILE\_FORMAT\_SUPPORT"\>\</a\>**FR25: Input File Format Support** The ChatBot shall support specified file formats for vulnerability descriptions and code snippets.
26. \<a id="FR\_AMBIGUOUS\_INFO"\>\</a\>**FR26: Ambiguous Information Handling** The ChatBot shall gracefully handle incomplete or ambiguous vulnerability information by seeking clarification or indicating insufficient data.
27. \<a id="FR\_REPORT\_INCORRECT\_MAPPING"\>\</a\>**FR27: Incorrect Mapping Feedback** The ChatBot SHALL provide a mechanism for users to report incorrect mappings or provide feedback.
28. \<a id="FR\_BYO\_LLM\_KEY"\>\</a\>**FR28: Bring Your Own LLM API Key** As a user, I MUST be able to configure the ChatBot to use my own Large Language Model (LLM) API key, so that I can utilize my preferred or licensed LLM services.
29. \<a id="FR\_BYO\_LLM\_MODEL"\>\</a\>**FR29: Bring Your Own Self-Hosted LLM Model** As a user, I MUST be able to configure the ChatBot to use my own self-hosted LLM model, so that I can leverage private or custom models within my own infrastructure.

### Non Functional

1.  \<a id="NFR\_PERFORMANCE\_LATENCY"\>\</a\>**NFR1: Performance - Latency** The ChatBot shall deliver responses with an average latency of less than 500ms for typical queries.
2.  \<a id="NFR\_SCALABILITY\_AUTO\_SCALING"\>\</a\>**NFR2: Scalability - Automatic Scaling** The underlying infrastructure and backend services shall be designed for automatic scalability to accommodate varying user loads.
3.  \<a id="NFR\_AVAILABILITY\_UPTIME"\>\</a\>**NFR3: Availability - Uptime** The system shall aim for 99.9% availability, minimizing unplanned downtime.
4.  \<a id="NFR\_SECURITY\_COMMUNICATION"\>\</a\>**NFR4: Security & Privacy - Secure Communication** All communication between the frontend and backend services shall be secured using HTTPS/TLS protocols.
5.  \<a id="NFR\_MAINTAINABILITY\_CODEBASE"\>\</a\>**NFR5: Maintainability & Code Quality - Codebase Adherence** The codebase shall adhere to defined clean architecture principles and coding standards to ensure long-term maintainability and readability for AI agents and human developers.
6.  \<a id="NFR\_ACCURACY\_HALLUCINATION"\>\</a\>**NFR6: Accuracy & Correctness - Hallucination Minimization** The ChatBot shall minimize instances of AI hallucination, striving for a high degree of factual accuracy and relevance in all provided information.
7.  \<a id="NFR\_SECURITY\_DATA\_LEAK"\>\</a\>**NFR7: Security & Privacy - Data Leakage Prevention** The chatbot shall not leak private user data or vulnerability details provided in-session.
8.  \<a id="NFR\_SECURITY\_RESTRICTIONS"\>\</a\>**NFR8: Security & Privacy - Function Restrictions & Abuse Prevention** It shall be restricted to CWE mapping functions and prevent abuse (e.g., code/prompt injection, SSRF).
9.  \<a id="NFR\_SECURITY\_CONFIDENTIALITY"\>\</a\>**NFR9: Security & Privacy - System Confidentiality** The system prompt and long-term memory must remain confidential; user context should be session-scoped.
10. \<a id="NFR\_SECURITY\_QUOTAS"\>\</a\>**NFR10: Security & Privacy - Quotas & Rate Limits** Implement quotas and rate limits to prevent resource exhaustion and billing abuse.
11. \<a id="NFR\_SECURITY\_LOGGING"\>\</a\>**NFR11: Security & Privacy - Logging, Auditing & Reporting** Provide logging, auditing, and abuse reporting mechanisms.
12. \<a id="NFR\_EASE\_INSTALL"\>\</a\>**NFR12: Ease of Access & Openness - Installation & Access** The solution should be easy to install and access (minimal setup for users).
13. \<a id="NFR\_EASE\_REGISTRATION"\>\</a\>**NFR13: Ease of Access & Openness - Registration Models** Registration can be required; support open or invite-only access models.
14. \<a id="NFR\_EASE\_ADMIN\_ACCESS"\>\</a\>**NFR14: Ease of Access & Openness - Admin Control** Administrators must be able to disable or throttle access per user.
15. \<a id="NFR\_EASE\_TOKEN\_LIMITS"\>\</a\>**NFR15: Ease of Access & Openness - Token Management** Define input/output token limits to balance performance and cost.
16. \<a id="NFR\_EASE\_COSTS"\>\</a\>**NFR16: Ease of Access & Openness - Operational Costs** Ensure predictable operational costs for hosting entities.
17. \<a id="NFR\_ACCURACY\_ID\_VALIDATION"\>\</a\>**NFR17: Accuracy & Correctness - ID Validation** The ChatBot shall not hallucinate CWE IDs and names; it shall validate inputs (e.g., CWE-79 vs. CWE-89) and avoid made-up IDs.
18. \<a id="NFR\_ACCURACY\_CWE\_UPDATES"\>\</a\>**NFR18: Accuracy & Correctness - CWE Updates** The ChatBot shall have a simple process to update to new CWE versions and always reflect the latest standard.
19. \<a id="NFR\_ACCURACY\_KNOWLEDGE\_BASE"\>\</a\>**NFR19: Accuracy & Correctness - Knowledge Base Content** The ChatBot's knowledge base shall include Mapping Notes, Alternate Terms, Previous Entry Names, and Relationship/Terminology Notes.
20. \<a id="NFR\_ACCURACY\_CONCEPT\_CLARITY"\>\</a\>**NFR20: Accuracy & Correctness - Concept Clarity** The ChatBot shall educate users on commonly misunderstood terms (e.g., authentication vs. authorization).
21. \<a id="NFR\_ACCURACY\_DEEP\_DIVE"\>\</a\>**NFR21: Accuracy & Correctness - Deep-Dive Mode** The ChatBot shall support deep-dive mode with adjustable token budgets for detailed explanations.
22. \<a id="NFR\_MAPPING\_PRIORITIZED"\>\</a\>**NFR22: Mapping & Suggestions - Prioritization & Confidence** The ChatBot shall present a concise list of prioritized CWE recommendations with confidence scores.
23. \<a id="NFR\_MAPPING\_LIMITS"\>\</a\>**NFR23: Mapping & Suggestions - Suggestion Limits** The ChatBot shall limit the number of suggestions and avoid recommending Prohibited or Discouraged CWEs.
24. \<a id="NFR\_MAPPING\_REASONING"\>\</a\>**NFR24: Mapping & Suggestions - Explanation of Reasoning** The ChatBot shall offer explanations and mapping reasoning from CWE descriptions or notes.
25. \<a id="NFR\_MAPPING\_CHAINING"\>\</a\>**NFR25: Mapping & Suggestions - Chaining Relationships** The ChatBot shall allow chaining relationships (e.g., parent/child CWEs) when relevant.
26. \<a id="NFR\_MAPPING\_REFINE"\>\</a\>**NFR26: Mapping & Suggestions - Input Refinement Guidance** The ChatBot shall provide guidance for users to refine inputs when suggestions lack confidence.
27. \<a id="NFR\_GUIDING\_PATTERNS"\>\</a\>**NFR27: User Guidance & Interaction - Input Patterns** The ChatBot shall support common input patterns such as pasting vulnerability descriptions, CVE advisories, and tool outputs.
28. \<a id="NFR\_GUIDING\_INQUIRIES"\>\</a\>**NFR28: User Guidance & Interaction - Inquiry Types** The ChatBot shall enable inquiries like "issues similar to CWE-XXX" or alternative proposals.
29. \<a id="NFR\_GUIDING\_ADAPTIVE"\>\</a\>**NFR29: User Guidance & Interaction - Adaptive Explanations** The ChatBot shall adapt explanations to varying user expertise and clarify confusing concepts.
30. \<a id="NFR\_AIML\_MODEL\_SELECTION"\>\</a\>**NFR30: AI/ML Engine - Model Selection & Documentation** The foundational AI model(s) used shall be selected and documented (e.g., open-source vs. commercial).
31. \<a id="NFR\_AIML\_SAFETY"\>\</a\>**NFR31: AI/ML Engine - Prompt & Safety Mechanisms** Prompt templates and safety mechanisms shall guard against misuse.
32. \<a id="NFR\_DATA\_HANDLING\_SIZE\_LIMITS"\>\</a\>**NFR32: Data Handling - Input Size Limits** The system shall define and enforce size limits on submitted code or documentation.
33. \<a id="NFR\_SECURITY\_SENSITIVE\_CODE\_HANDLING"\>\</a\>**NFR33: Security & Privacy - Sensitive Information Handling** The system shall ensure secure handling and isolation of proprietary or sensitive code submissions.
34. \<a id="NFR\_SECURITY\_AUTHN\_AUTHZ"\>\</a\>**NFR34: Security & Privacy - Authentication & Authorization** The system shall implement authentication and authorization mechanisms for user access control.
35. \<a id="NFR\_USER\_EXPERIENCE\_CONTEXT\_PRESERVATION"\>\</a\>**NFR35: User Guidance & Interaction - Session Context Preservation** The system shall preserve a user's conversational context across sessions.
36. \<a id="NFR\_MAINTAINABILITY\_FEEDBACK\_LOOP"\>\</a\>**NFR36: Maintainability & Code Quality - Continuous Improvement Feedback Loop** The system shall have a defined process for incorporating user feedback into continuous system improvement.
37. \<a id="NFR\_INTEGRATION\_API\_ACCESS"\>\</a\>**NFR37: Architecture & Integration - API Accessibility** The ChatBot shall be accessible via a web browser and consider an API for programmatic access in post-MVP phases.
38. \<a id="NFR\_AVAILABILITY\_RESILIENCE"\>\</a\>**NFR38: Availability - Resilience & Auto-Fallover** The system shall implement resilience mechanisms, including auto-fallover, if an underlying AI model becomes inaccessible.
39. \<a id="NFR\_SECURITY\_DATA\_RETENTION\_POLICIES"\>\</a\>**NFR39: Security & Privacy - Data Retention Policies** The system shall adhere to defined data retention policies for submitted code and vulnerability information.
40. \<a id="NFR\_SECURITY\_AUDIT\_LOGGING"\>\</a\>**NFR40: Security & Privacy - Audit Logging** The system shall implement detailed logging for audit and abuse reporting purposes.
41. \<a id="NFR\_ARCHITECTURE\_STANDALONE"\>\</a\>**NFR41: Architecture & Integration - Standalone Tool / Self-Hostable** The system shall be architected as a standalone, deployable application, explicitly designed to support **self-hosting within a user's private infrastructure**. It shall also provide clear interfaces for future integration into existing security platforms.
42. \<a id="NFR\_RELIABILITY\_BACKUP\_RECOVERY"\>\</a\>**NFR42: Reliability & Operations - Backup & Recovery** The system shall implement robust backup and recovery mechanisms for all critical data and services.
43. \<a id="NFR\_INTEGRATION\_FUTURE\_TOOL\_PLANNING"\>\</a\>**NFR43: Architecture & Integration - Future Tool Integration Planning** The system should identify and plan for integration with key existing security tools in post-MVP phases.
44. \<a id="NFR\_INTEGRATION\_VCS"\>\</a\>**NFR44: Architecture & Integration - Version Control System Integration** The system shall define a strategy for potential future integration with version control systems.
45. \<a id="NFR\_DATA\_HANDLING\_EXPORT\_FORMATS"\>\</a\>**NFR45: Data Handling - Export Formats** The system SHOULD support various export formats for mapped CWEs and user history.
46. \<a id="NFR\_ACCURACY\_CONFLICT\_RESOLUTION"\>\</a\>**NFR46: Accuracy & Correctness - Conflict Resolution Guidance** The ChatBot shall provide mechanisms or guidance for resolving conflicts between multiple possible CWE mappings.

## User Interface Design Goals

This section captures the high-level UI/UX vision for the CWE ChatBot, guiding our design and frontend development efforts to ensure a cohesive and user-centered experience.

### Overall UX Vision

The overall UX vision for the CWE ChatBot is to provide an intuitive, efficient, and trustworthy conversational interface for accessing and understanding complex CWE information. The experience should feel like interacting with a knowledgeable and helpful expert, not a rigid database. Users should feel empowered to find answers quickly and confidently, with minimal friction.

### Key Interaction Paradigms

  * **Conversational Interface First:** The primary interaction will be via a chat window, allowing natural language input and output.
  * **Progressive Disclosure:** Information will be revealed incrementally, starting with concise answers and offering deeper dives upon request, to avoid overwhelming the user.
  * **Contextual Adaptability:** The UI will subtly adapt, or display indicators, based on the user's role (e.g., developer, PSIRT member) to tailor the presentation of information.
  * **Actionable Feedback:** Clear and immediate feedback will be provided for user actions, system processing, and confidence levels of responses.

### Core Screens and Views

From a product perspective, the most critical screens/views for delivering the ChatBot's value include:

  * **Main Chat Interface:** The central conversational window where users input queries and receive responses.
  * **Settings/Profile Page:** For managing user preferences, perhaps authentication details, and potentially viewing chat history.
  * **Feedback/Report Issue Module:** A discreet mechanism within the chat interface for users to report inaccuracies or provide suggestions.
  * **Onboarding/Introduction Screen:** A brief, guided tour for new users to understand the ChatBot's capabilities and best practices for interaction.

### Accessibility: WCAG AA

We will aim for **WCAG 2.1 AA compliance**. This includes considerations for:

  * **Keyboard Navigation:** Ensuring all interactive elements are reachable and operable via keyboard.
  * **Color Contrast:** Meeting minimum contrast ratios for text and graphical elements.
  * **Screen Reader Compatibility:** Providing proper semantic HTML and ARIA attributes for assistive technologies.
  * **Text Resizing:** Ensuring content is readable when text is scaled up to 200%.

### Branding

The ChatBot's visual identity should align with a professional, clean, and trustworthy aesthetic. It should evoke confidence and reliability, avoiding overly playful or distracting elements. Branding elements should facilitate clarity and ease of use, making complex information approachable. If existing organizational branding guidelines are available, they will take precedence.

### Target Device and Platforms: Web Responsive

The application will be developed as a **web-responsive** application, ensuring an optimal viewing and interaction experience across desktop browsers, tablets, and mobile devices without requiring separate native applications.

## Technical Assumptions

This section documents the initial technical decisions and assumptions that will guide the overall architecture and development of the CWE ChatBot, now incorporating **Chainlit** as a core component. These are critical choices that set constraints for the Architect and provide direction for the engineering team.

### Repository Structure: Monorepo

  * **Rationale:** A Monorepo structure (e.g., using Nx, Turborepo, or a simpler Python-centric monorepo structure) remains preferred. This will facilitate organizing the main Chainlit application, any separate Python services (e.g., for data ingestion or complex NLP pipelines), and shared components, ensuring unified tooling and streamlined dependency management.

### Service Architecture

  * **CRITICAL DECISION - High-Level Service Architecture:** We will adopt a **Python-based application leveraging Chainlit's framework** for the core conversational logic and its integrated web UI. This unified application will interact with other services as needed:
      * **Chainlit Application:** Handles the primary conversational flow, user interface, and directs interactions with other services.
      * **NLP/AI Processing (within/adjacent to Chainlit):** Python's robust AI/ML ecosystem will be leveraged directly by Chainlit for natural language understanding, embedding generation, and vector database interactions. Highly specialized or compute-intensive AI components may be exposed as separate microservices.
      * **CWE Data Ingestion/Retrieval Service:** Manages access and updates from the CWE corpus.
      * **Authentication/User Management Service:** If user accounts are implemented, either through Chainlit's capabilities or an external service.
  * **Rationale:** Chainlit provides a rapid development environment for AI chatbots with built-in UI, significantly simplifying the full-stack deployment and leveraging Python's strengths in AI/ML development.

### Testing Requirements

  * **CRITICAL DECISION - Testing Strategy:** We will implement a **Unit + Integration Testing** strategy for the MVP, aiming for comprehensive coverage of business logic and inter-service communication within the Python ecosystem. **End-to-End (E2E) testing** for critical user flows will utilize Chainlit's testing capabilities or compatible Python web testing frameworks (e.g., Playwright with Pytest).
  * **Rationale:** Ensures quality while optimizing for the Chainlit development paradigm and Python testing ecosystem.

### Primary Frontend/UI Technology

  * The user interface will be directly served and managed by **Chainlit**. Chainlit provides a pre-built, web-based conversational UI that integrates seamlessly with Python backend logic, eliminating the need for a separate frontend framework like React/Next.js for the core chatbot interface.
  * **Rationale:** Direct adoption of the specified tool, simplifying UI development, deployment, and maintaining a unified Python stack.

### Primary Backend Technology

  * **Python** will be the foundational language for the entire backend, encompassing the core chatbot logic, API services, and NLP/AI processing, orchestrated primarily through **Chainlit**. Any highly specialized or compute-intensive AI components may be developed as separate Python microservices and exposed via internal APIs.
  * **Rationale:** Aligns with Chainlit's Python-native ecosystem and leverages Python's strength and extensive libraries in AI/ML development.

### Cloud Provider

  * **Google Cloud Platform (GCP)** will be the primary cloud provider, utilizing services such as **Cloud Run** (for deploying containerized Chainlit apps), Cloud SQL (for PostgreSQL), and Vertex AI (for managed AI services) if needed, alongside a managed Vector Database solution.
  * **Rationale:** Chainlit applications can be easily containerized and deployed on serverless platforms like Cloud Run, aligning with our cost-efficiency, automatic scaling goals, and minimizing operational overhead.

### CWE Corpus Source

  * We assume the primary source for the CWE corpus will be the official MITRE XML/JSON feeds, and that methods for programmatic parsing and updates can be established (Ref. NFR18).

### Initial Authentication

  * For the MVP, authentication will focus on a simple, scalable mechanism (e.g., Chainlit's built-in authentication features, API keys, or integration with a managed identity service from GCP/AWS), deferring complex custom identity management. (Ref. NFR34)

## Epic List

This section outlines the high-level epics that represent significant, deployable increments of functionality for the CWE ChatBot. Each epic is designed to build upon the previous one, delivering tangible value as the project progresses.

  * **Epic 1: Foundation & Core Chatbot Infrastructure**
      * **Goal:** Establish the foundational project setup (monorepo structure), deploy the basic Chainlit application on GCP Cloud Run, and implement the initial pipeline for ingesting and preparing the CWE corpus data for conversational interaction. This epic aims to deliver a "hello world" chatbot that can respond with simple, static CWE information, validating the core technical stack.
  * **Epic 2: Core Conversational & Contextual Intelligence**
      * **Goal:** Implement robust NLU, advanced information retrieval/synthesis, and initial role-based context awareness to provide accurate and tailored CWE responses. This epic focuses on building the core AI intelligence, allowing the chatbot to provide accurate and relevant CWE responses and basic follow-up capabilities (FR1-FR6, FR12-FR17).
  * **Epic 3: Enhanced User Interaction & Feedback Loop**
      * **Goal:** Develop features for summarizing/detailing CWEs, suggesting related content, and enabling user feedback, improving the overall interactive experience and chatbot learning.






## Epic 1: Foundation & Core Chatbot Infrastructure

**Epic Goal:** Establish the foundational project setup (monorepo structure), deploy the basic Chainlit application on GCP Cloud Run, and implement the initial pipeline for ingesting and preparing the CWE corpus data **for effective Retrieval Augmented Generation (RAG)**. This epic aims to deliver a "hello world" chatbot that can respond with simple, static CWE information, validating the core technical stack.

### Story 1.1: Project Repository Setup & Initial Commit

**As a** developer,
**I want** a new project repository set up with a monorepo structure,
**so that** the team can begin organizing code and managing versions.

#### Acceptance Criteria

1.  **AC1:** The project repository is initialized on GitHub (or chosen VCS like GitLab/Bitbucket).
2.  **AC2:** A basic monorepo structure is established, including a root `pyproject.toml` (or equivalent for Python monorepo management) and an `apps/chatbot` directory for the main application.
3.  **AC3:** A `README.md` file is created at the repository root with an initial project description and basic setup instructions.
4.  **AC4:** An initial commit containing this foundational structure is pushed to the main branch.
5.  **AC5:** Standard `.gitignore` and `.env.example` files are present at the repository root to manage version control and environment variables.

### Story 1.2: Basic Chainlit Application Deployment to Cloud Run

**As an** administrator,
**I want** a basic Chainlit "Hello World" application deployed to Google Cloud Run,
**so that** we can validate our core deployment pipeline and infrastructure.

#### Acceptance Criteria

1.  **AC1:** A minimal Chainlit application is created within the `apps/chatbot` directory, configured to respond with a simple greeting (e.g., "Hello, welcome to CWE ChatBot!").
2.  **AC2:** The Chainlit application can be successfully containerized using a `Dockerfile` and built into a Docker image.
3.  **AC3:** A CI/CD pipeline (e.g., GitHub Actions, Google Cloud Build) is configured to automatically build the Docker image and deploy it to GCP Cloud Run upon changes to the `apps/chatbot` directory.
4.  **AC4:** The deployed Chainlit application is accessible via a public URL, and its basic functionality can be **verified via a simple HTTP request or browser interaction from a local machine**.
5.  **AC5:** Basic application logs from the Chainlit app (e.g., startup messages) are visible and accessible in Google Cloud Logging, **and can also be accessed locally during development.**

### Story 1.3: Initial CWE Data Ingestion Pipeline

**As a** data engineer,
**I want** an automated pipeline to ingest a small, curated subset of CWE data (e.g., 5-10 specific CWEs from MITRE's XML/JSON) into a vector database,
**so that** the chatbot can begin to retrieve basic information.

#### Acceptance Criteria

1.  **AC1:** A Python script or service is developed to download the latest public CWE XML/JSON data from the MITRE website.
2.  **AC2:** The script can parse and extract relevant information (ID, Name, Description, Relationships) for a small, pre-defined subset of CWEs (e.g., CWE-79, CWE-89, CWE-123).
3.  **AC3:** Embeddings are generated for this subset of CWEs using a selected embedding model (e.g., a local sentence transformer or an external API).
4.  **AC4:** The generated embeddings and corresponding CWE metadata (ID, Name) are successfully stored in the chosen vector database (e.g., Pinecone, Weaviate, or a simple in-memory vector store for MVP validation).
5.  **AC5:** The ingestion process is repeatable and can be manually triggered via a command-line interface or simple function call, **and produces a verifiable local output (e.g., confirmation log, sample data file, or queryable local vector store).**

---

## Epic 2: Core Conversational & Contextual Intelligence

**Epic Goal:** Implement robust NLU and the **core Retrieval Augmented Generation (RAG) process**, including advanced information retrieval/synthesis and initial role-based context awareness, to provide accurate and tailored CWE responses. This epic focuses on building the core AI intelligence and minimizing hallucination (FR1-FR6, FR12-FR17).

### Story 2.1: Implement Core NLU & Initial CWE Query Matching

**As a** chatbot user,
**I want** the system to understand my natural language questions about CWEs,
**so that** I can find relevant information without needing specific CWE IDs.

#### Acceptance Criteria

1.  **AC1:** The Chainlit application successfully receives and processes natural language input from the user.
2.  **AC2:** Basic Natural Language Understanding (NLU) capabilities are integrated (e.g., leveraging an underlying LLM for intent recognition and entity extraction related to security concepts).
3.  **AC3:** The system can reliably identify direct mentions of specific CWE IDs (e.g., "Tell me about CWE-79") within user queries.
4.  **AC4:** For identified CWE IDs, the system retrieves and displays the basic name and a concise short description from the vector database (using data ingested in Story 1.3), **verifiable by sending a test query via a local script or the Chainlit UI.**
5.  **AC5:** The system gracefully handles unrecognized or out-of-scope queries by responding with a polite message indicating it doesn't understand or cannot fulfill the request (FR17), **verifiable via sending diverse test queries locally.**

### Story 2.2: Contextual Retrieval & Basic Follow-up Questions

**As a** chatbot user,
**I want** the system to provide contextually relevant CWE information and allow simple follow-up questions,
**so that** I can explore related details more deeply.

#### Acceptance Criteria

1.  **AC1:** When a CWE is successfully identified from a query, the system retrieves and presents comprehensive information (e.g., full description, common consequences, relationships to other CWEs or categories) from the vector database (NFR19), **verifiable by local queries that return expected structured data.**
2.  **AC2:** The system can understand and respond accurately to simple follow-up questions that are directly related to the previously discussed CWE context (e.g., "What are its common consequences?", "Give me an example", "How does this relate to X?"), **verifiable through interactive local testing in the Chainlit UI.**
3.  **AC3:** Responses to follow-up questions are extracted or synthesized directly from the detailed, stored CWE metadata, ensuring factual accuracy, **verifiable by comparing chatbot output against raw CWE data locally.**
4.  **AC4:** The ChatBot can respond to queries asking for "similar CWEs" by retrieving and listing related CWEs identified within the corpus (FR6).
5.  **AC5:** For detailed information, the ChatBot initially provides a concise answer or summary, with an explicit option or prompt for the user to request more in-depth details (FR5, NFR21).

### Story 2.3: Role-Based Context Awareness & Hallucination Mitigation

**As a** PSIRT member or developer,
**I want** the chatbot to tailor its CWE information based on my role, and I need to trust that the information is accurate,
**so that** I can get actionable and reliable advice.

#### Acceptance Criteria

1.  **AC1:** The ChatBot explicitly prompts the user to select their role (e.g., PSIRT member, Developer, Academic Researcher, Bug Bounty Hunter, Product Manager) at the start of a new session, or provides a command/option to change role during a session (FR4).
2.  **AC2:** For a given CWE, the system can dynamically tailor its response content and emphasis based on the selected role (e.g., for Developers, prioritize code-level remediation steps; for PSIRT, focus on impact, advisory language, and risk assessment details) (FR4), **verifiable by testing different role selections in the Chainlit UI and observing response variations.**
3.  **AC3:** Core AI mechanisms are implemented to actively minimize AI hallucination, such as directly citing specific passages from the CWE corpus for critical information or indicating when information is derived rather than directly quoted (NFR6, FR12), **verifiable by local automated tests that flag unexpected or uncited responses for known queries.**
4.  **AC4:** The system displays a confidence score or a prioritization order alongside its CWE suggestions or answers (FR15).
5.  **AC5:** When the system's confidence in a mapping or a response is low or information is insufficient, it clearly states this limitation and suggests ways the user can refine their query to get a better result (FR17, NFR26), **verifiable through local tests using ambiguous inputs.**

---

## Epic 3: Enhanced User Interaction & Feedback Loop

**Epic Goal:** Develop features for summarizing/detailing CWEs, suggesting related content, and enabling user feedback, improving the overall interactive experience and chatbot learning.

### Story 3.1: Implement Advanced User Input & Context Preservation

**As a** cybersecurity professional,
**I want** to provide detailed vulnerability information to the chatbot using various formats, and have my conversational context preserved,
**so that** I can get accurate, ongoing analysis without re-entering data.

#### Acceptance Criteria

1.  **AC1:** The ChatBot supports common and flexible input patterns, including directly pasting vulnerability descriptions, CVE advisories, and tool outputs into the chat interface (NFR27), **verifiable by submitting various input types locally.**
2.  **AC2:** The ChatBot provides a secure mechanism for users to submit code snippets or documentation files for analysis (FR25), **verifiable through local file submission tests confirming secure handling and rejection of unsafe inputs.**
3.  **AC3:** The system guarantees that any internal confidential or sensitive information provided by the user (e.g., code snippets) never leaves the user's defined domain or company, ensuring data privacy and isolation (FR19, NFR33), **verifiable through network traffic analysis in self-hosted environments and data flow audits in centrally-hosted ones.**
4.  **AC4:** A user's conversational context (e.g., previously discussed CWEs, chosen role, follow-up questions) is preserved throughout a single session and, optionally, across multiple user sessions (NFR35), **verifiable through local session testing in the Chainlit UI.**
5.  **AC5:** The system defines and gracefully enforces size limits on submitted text and code to prevent abuse and manage performance (NFR32), **verifiable by attempting to submit oversized inputs locally.**

### Story 3.2: Refined Mapping Suggestions & Explanations

**As a** user,
**I want** precise and explained CWE mapping suggestions,
**so that** I can quickly understand the relevance and reasoning behind the recommendations.

#### Acceptance Criteria

1.  **AC1:** The ChatBot presents a concise list of prioritized CWE recommendations, each accompanied by a clear confidence score (NFR22), **verifiable through local test queries and inspecting the UI output.**
2.  **AC2:** The system intelligently limits the number of suggested CWEs to avoid information overload and explicitly avoids recommending Prohibited or Discouraged CWEs from the corpus (NFR23).
3.  **AC3:** The ChatBot provides clear, concise explanations for its mapping reasoning, ideally quoting relevant snippets from CWE descriptions, mapping notes, or related documentation (FR16, NFR24), **verifiable by reviewing chatbot explanations for a diverse set of queries locally.**
4.  **AC4:** The system allows users to explore CWE relationships (e.g., parent/child relationships, associations) directly within the conversation, enabling chaining of related concepts (NFR25), **verifiable through interactive local testing of relationship queries.**
5.  **AC5:** For low-confidence suggestions, the ChatBot proactively offers specific guidance to the user on how to refine their input or provide more detail to improve the accuracy of future recommendations (NFR26), **verifiable by submitting ambiguous inputs locally and checking the chatbot's response.**

### Story 3.3: User Feedback and Continuous Improvement Integration

**As a** user,
**I want** to easily provide feedback on chatbot responses, and I expect the system to improve over time,
**so that** the chatbot becomes more accurate and helpful for my tasks.

#### Acceptance Criteria

1.  **AC1:** A clear, intuitive, and easily accessible mechanism is implemented within the chatbot interface for users to report incorrect mappings, inaccurate information, or provide general suggestions and feedback on responses (FR27), **verifiable through local UI interaction to submit feedback.**
2.  **AC2:** All user feedback, interaction logs, and relevant conversational data are securely collected and stored for analysis and audit purposes (NFR11, NFR40), **verifiable by inspecting local storage/logs after submitting feedback.**
3.  **AC3:** A defined, automated, or semi-automated process exists for reviewing collected user feedback and systematically incorporating it into the chatbot's knowledge base, response logic, or underlying AI model for continuous improvement (FR18, NFR36).
4.  **AC4:** The system adheres to predefined data retention policies for all collected user data, feedback, and conversational history, ensuring compliance and privacy (NFR39).
5.  **AC5:** The ChatBot supports the export of mapped CWEs and user's conversational history in various common formats (e.g., Markdown, JSON) for external use or record-keeping (NFR45), **verifiable by locally triggering export functionality and confirming file format.**




## Appendices

## Overview

This document is a collation of inputs from:

1.  chatbot-requirements-draft-250219, Steve Coley
2.  RCM-WG-250129.pptx
3.  Other User Stories that capture requirements as they arose

## 1\. User Scenarios

### 1.1 PSIRT Member Writing a Vulnerability Advisory

  * **Available information:** Collection of bug reports and issue summaries; access to developers
  * **Background knowledge:** General vulnerability types, programming concepts
  * **Time pressure:** High
  * **Correctness vs. completeness:** Needs accurate CWE IDs; may prioritize speed when multiple weaknesses exist

### 1.2 Developer Fixing a Vulnerability

  * **Available information:** Source code, mistake and patch details, bug reports, tradeoff discussions, testing results, proof-of-concept code
  * **Background knowledge:** Programming languages, protocols, tech stacks, bug remediation
  * **Time pressure:** High
  * **Correctness importance:** Lower (primary focus on fixing bugs/features)
  * **Special consideration:** Developer may receive CWE IDs from external reports or tools

### 1.3 Academic Vulnerability Researcher

  * **Available information:** May lack source code or patch; research focus varies (single weakness class, technology-specific, detection methods)
  * **Background knowledge:** Varies with research orientation; deeper source understanding for exploit reliability
  * **Time pressure:** Low
  * **Correctness importance:** Moderate

### 1.4 Bug Bounty Hunter Reporting Vulnerabilities

  * **Available information:** May lack source code or patch; exploit writing may require deep technical insight
  * **Background knowledge:** Varies by attacker focus
  * **Time pressure:** Low
  * **Correctness importance:** Moderate

### 1.5 Product Manager Preventing Weaknesses at Scale

  * **Goal:** Identify common CWE patterns across products to guide large-scale remediation and prevention efforts
  * **Constraints:** Balances strategic planning with resource allocation

## 2\. User Stories

\<a id="USR\_PSIRT\_INPUT"\>\</a\>**USR\_PSIRT\_INPUT**: As a PSIRT member, I MUST be able to input bug reports and issue summaries to quickly receive prioritized CWE recommendations under high time pressure.

\<a id="USR\_DEV\_SOURCE\_CODE"\>\</a\>**USR\_DEV\_SOURCE\_CODE**: As a developer, I MUST be able to submit source code and patch details to accurately identify correct CWE mappings without delaying bug fixes.

\<a id="USR\_ACADEMIC\_ANALYSIS"\>\</a\>**USR\_ACADEMIC\_ANALYSIS**: As an academic researcher, I SHOULD be able to explore CWE mappings with limited code context for effective analysis of vulnerability trends and detection techniques.

\<a id="USR\_BUG\_BOUNTY\_MAPPING"\>\</a\>**USR\_BUG\_BOUNTY\_MAPPING**: As a bug bounty hunter, I SHOULD be able to map vulnerabilities based on exploit information to ensure accurate and credible CWE reporting.

\<a id="USR\_PM\_RESOURCE\_ALLOCATION"\>\</a\>**USR\_PM\_RESOURCE\_ALLOCATION**: As a product manager, I SHOULD be able to analyze common weaknesses at scale to effectively allocate resources and implement preventive measures.

\<a id="USR\_CHATBOT\_ACCURACY"\>\</a\>**USR\_CHATBOT\_ACCURACY**: As a user, I MUST receive correct CWE IDs and names without hallucination to trust chatbot recommendations.

\<a id="USR\_CHATBOT\_ID\_INPUT"\>\</a\>**USR\_CHATBOT\_ID\_INPUT**: As a user, I MUST have the chatbot accurately accept and interpret input CWE IDs without confusing similar IDs (e.g., CWE-79 vs. CWE-89).

\<a id="USR\_CHATBOT\_CWE\_UPDATES"\>\</a\>**USR\_CHATBOT\_CWE\_UPDATES**: As a user, I MUST have the chatbot remain up-to-date with the latest CWE versions to ensure mappings reflect current standards.

\<a id="USR\_CHATBOT\_PRIORITY\_CONFIDENCE"\>\</a\>**USR\_CHATBOT\_PRIORITY\_CONFIDENCE**: As a user, I MUST receive prioritized and confidence-annotated CWE suggestions (limited in number) to efficiently focus on relevant mappings.

\<a id="USR\_CHATBOT\_REASONING"\>\</a\>**USR\_CHATBOT\_REASONING**: As a user, I SHOULD have the chatbot explain its reasoning (e.g., quoting mapping notes) to understand CWE recommendations.

\<a id="USR\_CHATBOT\_INSUFFICIENT\_INFO"\>\</a\>**USR\_CHATBOT\_INSUFFICIENT\_INFO**: As a user, I MUST have the chatbot handle insufficient information gracefully (e.g., indicate "not enough information") to avoid misleading confidence.

\<a id="USR\_CHATBOT\_FEEDBACK\_LEARNING"\>\</a\>**USR\_CHATBOT\_FEEDBACK\_LEARNING**: As a user, I SHOULD have the chatbot learn and continuously update its responses based on user feedback, interactions, and logs.

\<a id="USR\_CHATBOT\_CONFIDENTIALITY"\>\</a\>**USR\_CHATBOT\_CONFIDENTIALITY**: As a user, I MUST be able to use the chatbot on internal confidential information with the guarantee that this information never leaves my domain or company.

## 3\. Non-User Requirements

### 3.1 Security & Privacy Requirements

  * The chatbot shall not leak private user data or vulnerability details provided in-session.
  * It shall be restricted to CWE mapping functions and prevent abuse (e.g., code/prompt injection, SSRF).
  * The system prompt and long-term memory must remain confidential; user context should be session-scoped.
  * Implement quotas and rate limits to prevent resource exhaustion and billing abuse.
  * Provide logging, auditing, and abuse reporting mechanisms.

### 3.2 Ease of Access & Openness

  * The solution should be easy to install and access (minimal setup for users).
  * Registration can be required; support open or invite-only access models.
  * Administrators must be able to disable or throttle access per user.
  * Define input/output token limits to balance performance and cost.
  * Ensure predictable operational costs for hosting entities.

### 3.3 Correctness

  * **CWE ID Handling:** No hallucinations; validate inputs (e.g., CWE-79 vs. CWE-89) and avoid made-up IDs.
  * **Recency:** Simple process to update to new CWE versions; always reflect the latest standard.
  * **Knowledge Base:** Include Mapping Notes, Alternate Terms, Previous Entry Names, Relationship Notes, Terminology Notes.
  * **Concept Clarity:** Educate users on commonly misunderstood terms (e.g., authentication vs. authorization).
  * Support deep-dive mode with adjustable token budgets for detailed explanations.

### 3.4 Mapping Suggestions

  * Present a concise list of prioritized CWE recommendations with confidence scores.
  * Limit the number of suggestions and avoid recommending Prohibited or Discouraged CWEs.
  * Offer explanations and mapping reasoning from CWE descriptions or notes.
  * Allow chaining relationships (e.g., parent/child CWEs) when relevant.
  * Provide guidance for users to refine inputs when suggestions lack confidence.

### 3.5 Guiding Users (Question/Response Flow)

  * Support common patterns: pasting vulnerability descriptions, CVE advisories, tool outputs.
  * Enable inquiries like "issues similar to CWE-XXX" or alternative proposals.
  * Adapt explanations to varying user expertise and clarify confusing concepts.

### 3.6 AI/ML Engine

  * Select and document the foundational model(s) used (e.g., open-source vs. commercial).
  * Ensure prompt templates and safety mechanisms guard against misuse.

## Annex RCMWG CWE Support and Mapping Tool discussion

This content is extracted RCM-WG-250129.pptx which will be available [https://github.com/Root-Cause-Mapping-Working-Group/RCM-WG/tree/main/meeting\_slides](https://github.com/Root-Cause-Mapping-Working-Group/RCM-WG/tree/main/meeting_slides)

-----

### Possible Use Cases for a “CWE Support” Tool

  * **Root cause mapping:** Helps users accurately map root causes to CWE entries.
  * **Learning assistance:** Guides users in understanding vulnerabilities and conducting root cause analysis.
  * **Weakness comprehension:** Provides explanations of CWE weaknesses, common consequences, and code examples.
  * **Navigational support:** Helps users explore CWE views, hierarchies, and relationships.

-----

### Context of a Root Cause Mapping Assistance Tool

  * Understanding **why** someone would use an LLM or mapping assistance tool.
  * **Factors influencing use:**
      * **Activity:** What the user is doing that requires CWE mapping.
      * **Available Information:** What data the user has for mapping decisions (Slack messages, emails, reports, etc.).
      * **Coding Knowledge:** Skill level and familiarity with vulnerabilities.
      * **Time Pressures:** Urgency of mapping decisions.
      * **Correctness Importance:** How crucial it is to get the mapping correct.
  * Information varies **person-to-person, role-to-role** (e.g., a PSIRT member vs. a developer).