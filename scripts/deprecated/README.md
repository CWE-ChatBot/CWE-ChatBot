# Deprecated Scripts and Files

This directory contains old scripts and files kept for reference.

## Deployment Scripts

### deploy_chatbot.sh
Old deployment script that used --update-secrets flag.
- **Replaced by**: `apps/chatbot/deploy.sh` (uses Secret Manager integration)
- **Deprecated**: 2025-10-08

## Chainlit Welcome Files

### chainlit.md, chainlit_en-US.md, chainlit_en_US.md
Old versions of Chainlit welcome screen markdown files.
- **Current file**: `apps/chatbot/chainlit.md` (64 lines, updated content)
- **These files**: Older/incomplete versions (21-41 lines)
- **Not used**: Dockerfile only copies `apps/chatbot/chainlit.md`
- **Deprecated**: 2025-10-08

