# Scripts Directory

This directory contains utility scripts for the CWE ChatBot project, including security infrastructure setup and documentation processing tools.

## Chat Formatting Scripts

These scripts were used to format the BMAD planning chat conversation for readability:

| Script | Description | Status |
|--------|-------------|--------|
| [format_chat.py](format_chat.py) | Initial attempt at automated chat formatting | Deprecated - had formatting issues |
| [process_chat_final.py](process_chat_final.py) | Improved version with better pattern matching | Deprecated - still had issues |
| [process_chat_precise.py](process_chat_precise.py) | Most precise automated attempt | Deprecated - manual processing was better |
| [update_chat_admonitions.py](update_chat_admonitions.py) | Converts user input to GitHub admonitions | Active - used to create final formatted version |

## Usage Notes

- The automated scripts had various issues with preserving formatting and correctly identifying user vs LLM content
- The final formatted chat file was created through manual processing by an AI agent
- Final result: `docs/bmad_planning_chat_with_admonitions.md` (properly formatted with GitHub admonitions for user input and preserved formatting for LLM responses)

## Security & Infrastructure Scripts (Story S-2)

### ⚠️ Note: Vertex AI Migration Required

**Most S-2 scripts have been archived** because the app uses Gemini API SDK (not Vertex AI). Model Armor and platform-level guardrails require Vertex AI endpoints.

**Archived scripts:** [docs/future/vertex-ai-migration/](../docs/future/vertex-ai-migration/)
- `s2_setup_model_armor.sh` - Requires Vertex AI
- `s2_setup_observability.sh` - Requires Vertex AI
- `S-2-guardrails-runbook.md` - Requires Model Armor

### Active S-2 Testing

**Smoke Testing** ([s2_smoke_test.py](s2_smoke_test.py))
```bash
# Test app-level defenses with attack payloads
poetry run python s2_smoke_test.py --endpoint http://localhost:8000 --verbose

# Or test production endpoint
poetry run python s2_smoke_test.py --endpoint https://cwe-chatbot-XXXXX-uc.a.run.app
```

**What this tests:**
- Input sanitization effectiveness
- SafetySetting behavior (BLOCK_NONE for security content)
- RAG grounding (prevents off-topic responses)

**Related Documentation:**
- [S-2 Story](../docs/stories/S-2.LLM-Input-Output-Guardrails.md) - Implementation status and findings
- [S-2 Reality Check](../docs/stories/S-2-REALITY-CHECK.md) - Architecture mismatch analysis
- [SafetySetting Documentation](../docs/runbooks/S-2-safety-settings.md) - Current configuration (still valid)
- [Vertex AI Migration Materials](../docs/future/vertex-ai-migration/) - Archived scripts for future use

## Running Scripts

All scripts are compatible with the project's Poetry environment:

```bash
# Shell scripts (infrastructure setup)
./script_name.sh

# Python scripts (testing and utilities)
poetry run python script_name.py
```