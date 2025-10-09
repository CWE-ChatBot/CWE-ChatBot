run BMAD vuln agent - 6


WAF

Feedback (@cl.on_feedback): The feedback handler is great. Triggering a detailed feedback prompt (AskUserMessage) on a thumbs-down is a fantastic way to gather actionable insights.

Settings Panel (@cl.on_settings_update): Proper use of the native settings panel for UI preferences.



mcp context7




Buttons for the initial prompts
Readme content appearing periodically
Config buttons short/long calibrate
Branding 

Security review (also use llm tool)
Review n Refactor
GCP DAST run - need static IP 
    https://cloud.google.com/run/docs/samples/cloudrun-static-outbound-parent-tag
    https://cloud.google.com/vpc/network-pricing?hl=en Static and ephemeral IP addresses in use on standard VM instances: $3.65 / 1 month, per 1 month / account

Add BMAD Ops Persona
BMAD codex and gemini - security review
Define and Detail BYO model 
Add API ala FastAPI



====DONE======================================================

remove apps/chatbot/healthcheck.py
/ Ruff black pypi pre commit hook
semgrep
run all tests: unit, integration, e2e - but do not change the existing running cloudrun. deploy an alternative test one to verify AOK
