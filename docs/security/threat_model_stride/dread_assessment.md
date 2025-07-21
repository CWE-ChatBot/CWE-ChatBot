| Threat Type | Scenario | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |
|------------|----------|------------------|-----------------|----------------|----------------|-----------------|------------|
| Spoofing | An attacker could perform a DNS spoofing or Man-in-the-Middle (MITM) attack against the CWE Data ... | 9 | 6 | 5 | 10 | 3 | 6.60 |
| Spoofing | A user leverages the 'Bring Your Own LLM' (BYO LLM) feature to configure a malicious endpoint the... | 4 | 10 | 10 | 1 | 9 | 6.80 |
| Spoofing | During the OAuth 2.0 authentication flow, if the application does not strictly validate the 'redi... | 8 | 9 | 6 | 7 | 7 | 7.40 |
| Tampering | A user submits a crafted query designed to manipulate the RAG process. For example, they inject c... | 7 | 7 | 6 | 8 | 8 | 7.20 |
| Tampering | An attacker with access to modify the IaC (Terraform) files in the monorepo could alter the confi... | 10 | 10 | 4 | 10 | 2 | 7.20 |
| Tampering | An attacker gains access to the PostgreSQL database and modifies a user's `llm_model_config` JSON... | 9 | 10 | 4 | 5 | 3 | 6.20 |
| Repudiation | A user with the 'Admin' role makes a malicious change using the `/user/config` API endpoint, such... | 7 | 10 | 8 | 7 | 5 | 7.40 |
| Repudiation | The application stores chat history in the `messages` table but does not digitally sign or create... | 8 | 8 | 5 | 6 | 4 | 6.20 |
| Repudiation | A user provides feedback on a chatbot response (FR27), but the system only records the feedback i... | 4 | 9 | 5 | 8 | 6 | 6.40 |
| Information Disclosure | A user crafts a malicious prompt that causes the LLM to ignore the retrieved CWE context and inst... | 7 | 6 | 7 | 9 | 8 | 7.40 |
| Information Disclosure | The `llm_api_key_id` is stored in the `users` table, and the actual API keys are stored elsewhere... | 8 | 10 | 5 | 10 | 5 | 7.60 |
| Information Disclosure | An error in the application logic, particularly in the NLP/AI Service, causes a detailed technica... | 6 | 4 | 5 | 7 | 7 | 5.80 |
| Denial of Service | An attacker, knowing the application uses a RAG architecture, submits a series of complex, comput... | 7 | 8 | 8 | 9 | 7 | 7.80 |
| Denial of Service | The CWE Data Ingestion Pipeline is triggered (e.g., via a webhook or scheduled job) but is fed a ... | 6 | 7 | 6 | 10 | 5 | 6.80 |
| Denial of Service | The application relies on Redis (Cloud Memorystore) for caching and session management. An attack... | 7 | 8 | 7 | 10 | 6 | 7.60 |
| Elevation of Privilege | A flaw exists in the `/user/config` PUT endpoint. A regular user discovers they can include an 'i... | 9 | 10 | 7 | 10 | 6 | 8.40 |
| Elevation of Privilege | The application defines multiple user roles (e.g., 'Developer', 'Admin') but the enforcement logi... | 8 | 5 | 6 | 7 | 4 | 6.00 |
| Elevation of Privilege | During the OAuth user creation process, the application correctly fetches the user's email from t... | 10 | 10 | 8 | 10 | 7 | 9.00 |

