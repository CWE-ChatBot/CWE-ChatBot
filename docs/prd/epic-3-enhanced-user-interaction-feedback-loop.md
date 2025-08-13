# Epic 3: Enhanced User Interaction & Feedback Loop

**Epic Goal:** Develop features for summarizing/detailing CWEs, suggesting related content, and enabling user feedback, improving the overall interactive experience and chatbot learning.

## Story 3.1: Implement Advanced User Input & Context Preservation

**As a** cybersecurity professional,
**I want** to provide detailed vulnerability information to the chatbot using various formats, and have my conversational context preserved,
**so that** I can get accurate, ongoing analysis without re-entering data.

### Acceptance Criteria

1.  **AC1:** The ChatBot supports common and flexible input patterns, including directly pasting vulnerability descriptions, CVE advisories, and tool outputs into the chat interface (NFR27), **verifiable by submitting various input types locally.**
2.  **AC2:** The ChatBot provides a secure mechanism for users to submit code snippets or documentation files for analysis (FR25), **verifiable through local file submission tests confirming secure handling and rejection of unsafe inputs.**
3.  **AC3:** The system guarantees that any internal confidential or sensitive information provided by the user (e.g., code snippets) never leaves the user's defined domain or company, ensuring data privacy and isolation (FR19, NFR33), **verifiable through network traffic analysis in self-hosted environments and data flow audits in centrally-hosted ones.**
4.  **AC4:** A user's conversational context (e.g., previously discussed CWEs, chosen role, follow-up questions) is preserved throughout a single session and, optionally, across multiple user sessions (NFR35), **verifiable through local session testing in the Chainlit UI.**
5.  **AC5:** The system defines and gracefully enforces size limits on submitted text and code to prevent abuse and manage performance (NFR32), **verifiable by attempting to submit oversized inputs locally.**

## Story 3.2: Refined Mapping Suggestions & Explanations

**As a** user,
**I want** precise and explained CWE mapping suggestions,
**so that** I can quickly understand the relevance and reasoning behind the recommendations.

### Acceptance Criteria

1.  **AC1:** The ChatBot presents a concise list of prioritized CWE recommendations, each accompanied by a clear confidence score (NFR22), **verifiable through local test queries and inspecting the UI output.**
2.  **AC2:** The system intelligently limits the number of suggested CWEs to avoid information overload and explicitly avoids recommending Prohibited or Discouraged CWEs from the corpus (NFR23).
3.  **AC3:** The ChatBot provides clear, concise explanations for its mapping reasoning, ideally quoting relevant snippets from CWE descriptions, mapping notes, or related documentation (FR16, NFR24), **verifiable by reviewing chatbot explanations for a diverse set of queries locally.**
4.  **AC4:** The system allows users to explore CWE relationships (e.g., parent/child relationships, associations) directly within the conversation, enabling chaining of related concepts (NFR25), **verifiable through interactive local testing of relationship queries.**
5.  **AC5:** For low-confidence suggestions, the ChatBot proactively offers specific guidance to the user on how to refine their input or provide more detail to improve the accuracy of future recommendations (NFR26), **verifiable by submitting ambiguous inputs locally and checking the chatbot's response.**

## Story 3.3: User Feedback and Continuous Improvement Integration

**As a** user,
**I want** to easily provide feedback on chatbot responses, and I expect the system to improve over time,
**so that** the chatbot becomes more accurate and helpful for my tasks.

### Acceptance Criteria

1.  **AC1:** A clear, intuitive, and easily accessible mechanism is implemented within the chatbot interface for users to report incorrect mappings, inaccurate information, or provide general suggestions and feedback on responses (FR27), **verifiable through local UI interaction to submit feedback.**
2.  **AC2:** All user feedback, interaction logs, and relevant conversational data are securely collected and stored for analysis and audit purposes (NFR11, NFR40), **verifiable by inspecting local storage/logs after submitting feedback.**
3.  **AC3:** A defined, automated, or semi-automated process exists for reviewing collected user feedback and systematically incorporating it into the chatbot's knowledge base, response logic, or underlying AI model for continuous improvement (FR18, NFR36).
4.  **AC4:** The system adheres to predefined data retention policies for all collected user data, feedback, and conversational history, ensuring compliance and privacy (NFR39).
5.  **AC5:** The ChatBot supports the export of mapped CWEs and user's conversational history in various common formats (e.g., Markdown, JSON) for external use or record-keeping (NFR45), **verifiable by locally triggering export functionality and confirming file format.**
