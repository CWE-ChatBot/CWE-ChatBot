# 3\. Non-User Requirements

## 3.1 Security & Privacy Requirements

  * The chatbot shall not leak private user data or vulnerability details provided in-session.
  * It shall be restricted to CWE mapping functions and prevent abuse (e.g., code/prompt injection, SSRF).
  * The system prompt and long-term memory must remain confidential; user context should be session-scoped.
  * Implement quotas and rate limits to prevent resource exhaustion and billing abuse.
  * Provide logging, auditing, and abuse reporting mechanisms.

## 3.2 Ease of Access & Openness

  * The solution should be easy to install and access (minimal setup for users).
  * Registration can be required; support open or invite-only access models.
  * Administrators must be able to disable or throttle access per user.
  * Define input/output token limits to balance performance and cost.
  * Ensure predictable operational costs for hosting entities.

## 3.3 Correctness

  * **CWE ID Handling:** No hallucinations; validate inputs (e.g., CWE-79 vs. CWE-89) and avoid made-up IDs.
  * **Recency:** Simple process to update to new CWE versions; always reflect the latest standard.
  * **Knowledge Base:** Include Mapping Notes, Alternate Terms, Previous Entry Names, Relationship Notes, Terminology Notes.
  * **Concept Clarity:** Educate users on commonly misunderstood terms (e.g., authentication vs. authorization).
  * Support deep-dive mode with adjustable token budgets for detailed explanations.

## 3.4 Mapping Suggestions

  * Present a concise list of prioritized CWE recommendations with confidence scores.
  * Limit the number of suggestions and avoid recommending Prohibited or Discouraged CWEs.
  * Offer explanations and mapping reasoning from CWE descriptions or notes.
  * Allow chaining relationships (e.g., parent/child CWEs) when relevant.
  * Provide guidance for users to refine inputs when suggestions lack confidence.

## 3.5 Guiding Users (Question/Response Flow)

  * Support common patterns: pasting vulnerability descriptions, CVE advisories, tool outputs.
  * Enable inquiries like "issues similar to CWE-XXX" or alternative proposals.
  * Adapt explanations to varying user expertise and clarify confusing concepts.

## 3.6 AI/ML Engine

  * Select and document the foundational model(s) used (e.g., open-source vs. commercial).
  * Ensure prompt templates and safety mechanisms guard against misuse.
