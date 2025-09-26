# CWE ChatBot — About & Help

This assistant focuses on MITRE CWE (Common Weakness Enumeration). Ask about specific CWEs (e.g., CWE-79, CWE-89), prevention guidance, examples, and relationships.

Quick tips:
- Try: "What is CWE-79?" or "How do I prevent SQL injection?"
- Select your role from the top bar (Developer, PSIRT Member, etc.) for tailored responses.
- Use the gear icon next to the input to adjust detail level, examples, and mitigations.

Security & scope:
- The assistant is security-first. Off-topic questions are gently redirected.
- Potentially unsafe inputs are sanitized and may receive a safe fallback.

Sources & retrieval:
- Hybrid RAG over PostgreSQL with vector + keyword search.
- Responses cite CWE context and relevant sections (Description, Examples, Mitigations, Relationships).

Feedback:
- Use the feedback controls to rate responses and help us improve.

More info in the repository README.

## Available Personas

*   **PSIRT Member** 🛡️ - Impact assessment and security advisory creation
*   **Developer** 💻 - Remediation steps and secure coding examples
*   **Academic Researcher** 🎓 - Comprehensive analysis and CWE relationships
*   **Bug Bounty Hunter** 🔍 - Exploitation patterns and testing techniques
*   **Product Manager** 📊 - Business impact and prevention strategies
*   **CWE Analyzer** 🔬 - CVE-to-CWE mapping analysis with confidence scoring
*   **CVE Creator** 📝 - Structured CVE vulnerability descriptions