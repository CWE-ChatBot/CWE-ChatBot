# Scripts Directory

This directory contains utility scripts for processing project files.

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

## Running Scripts

All scripts are Python 3 compatible:

```bash
python3 scripts/script_name.py
```