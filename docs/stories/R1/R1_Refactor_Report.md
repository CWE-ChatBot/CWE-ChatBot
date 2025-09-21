# R1 Refactor Report

This report summarizes the R1 refactor across chatbot, ingestion, tests, and docs.


## Highlights
- Gemini-only (3072‑D) alignment across chatbot; OpenAI references removed.
- Ingestion-aligned retrieval via PostgresChunkStore.query_hybrid (RRF over vector+FTS+alias).
- Prompt templates externalized to `apps/chatbot/src/prompts/` with file loading; fallbacks kept concise.
- Input sanitization no longer rewrites queries; only flags risky patterns and normalizes whitespace.
- Response cleaner only strips a leading role label; avoids removing legitimate content.
- Context builder guarded and bounded; no KeyErrors on missing metadata, hard cap on size.
- RoleManager now uses single source of truth: `cl.user_session["user_context"].persona`; legacy flags retained.
- ConversationManager stores per-user state in Chainlit `user_session` and relies on Chainlit message persistence.
- Removed legacy retrievers, formatters, and test suites; updated remaining tests to new architecture.
- Robust module imports: prefer package imports; fallback to `CWE_INGESTION_PATH` for ingestion modules.
- Docs updated to mark legacy components deprecated and reflect the new flow.

## AGENTS.md

- ??: `AGENTS.md`

## SECURITY.md

- ??: `SECURITY.md`

## apps

- M: `apps/chatbot/main.py`
- ??: `apps/chatbot/src/app_config.py`
- M: `apps/chatbot/src/config.py`
- M: `apps/chatbot/src/config/env_loader.py`
- M: `apps/chatbot/src/conversation.py`
- M: `apps/chatbot/src/file_processor.py`
- D: `apps/chatbot/src/formatting/__init__.py`
- D: `apps/chatbot/src/formatting/progressive_response_formatter.py`
- D: `apps/chatbot/src/formatting/response_formatter.py`
- M: `apps/chatbot/src/input_security.py`
- D: `apps/chatbot/src/processing/confidence_manager.py`
- D: `apps/chatbot/src/processing/contextual_responder.py`
- M: `apps/chatbot/src/processing/cwe_extractor.py`
- M: `apps/chatbot/src/processing/embedding_service.py`
- M: `apps/chatbot/src/processing/followup_processor.py`
- M: `apps/chatbot/src/processing/query_processor.py`
- D: `apps/chatbot/src/processing/role_aware_responder.py`
- ??: `apps/chatbot/src/prompts/academic_researcher.md`
- ??: `apps/chatbot/src/prompts/bug_bounty_hunter.md`
- ??: `apps/chatbot/src/prompts/cve_creator.md`
- ??: `apps/chatbot/src/prompts/cwe_analyzer.md`
- ??: `apps/chatbot/src/prompts/developer.md`
- ??: `apps/chatbot/src/prompts/product_manager.md`
- ??: `apps/chatbot/src/prompts/psirt_member.md`
- M: `apps/chatbot/src/prompts/role_templates.py`
- M: `apps/chatbot/src/query_handler.py`
- M: `apps/chatbot/src/response_generator.py`
- D: `apps/chatbot/src/retrieval/__init__.py`
- D: `apps/chatbot/src/retrieval/base_retriever.py`
- D: `apps/chatbot/src/retrieval/cwe_relationship_manager.py`
- D: `apps/chatbot/src/retrieval/dense_retriever.py`
- D: `apps/chatbot/src/retrieval/hybrid_rag_manager.py`
- D: `apps/chatbot/src/retrieval/secure_query_builder.py`
- D: `apps/chatbot/src/retrieval/sparse_retriever.py`
- D: `apps/chatbot/src/security/csrf_protection.py`
- D: `apps/chatbot/src/security/input_sanitizer.py`
- D: `apps/chatbot/src/security/rate_limiting.py`
- M: `apps/chatbot/src/security/secure_logging.py`
- D: `apps/chatbot/src/security/session_encryption.py`
- D: `apps/chatbot/src/session/__init__.py`
- D: `apps/chatbot/src/session/context_manager.py`
- D: `apps/chatbot/src/session/session_security.py`
- M: `apps/chatbot/src/user/role_manager.py`
- M: `apps/chatbot/src/user_context.py`
- D: `apps/chatbot/tests/README_REAL_INTEGRATION.md`
- D: `apps/chatbot/tests/security/test_role_response_sanitization.py`
- D: `apps/chatbot/tests/security/test_session_encryption.py`
- D: `apps/chatbot/tests/test_authentication_security.py`
- D: `apps/chatbot/tests/test_confidence_manager.py`
- D: `apps/chatbot/tests/test_database_simulation.py`
- M: `apps/chatbot/tests/test_embedding_service.py`
- D: `apps/chatbot/tests/test_followup_processing.py`
- D: `apps/chatbot/tests/test_integration_simple.py`
- M: `apps/chatbot/tests/test_prompt_injection_security.py`
- D: `apps/chatbot/tests/test_real_integration.py`
- D: `apps/chatbot/tests/test_real_openai_simple.py`
- D: `apps/chatbot/tests/test_response_formatter.py`
- D: `apps/chatbot/tests/test_role_aware_responder.py`
- M: `apps/chatbot/tests/test_role_manager.py`
- M: `apps/chatbot/tests/test_security.py`
- D: `apps/chatbot/tests/test_session_management.py`
- D: `apps/chatbot/tests/test_sql_injection_prevention.py`
- M: `apps/chatbot/tests/test_story_2_1_components.py`
- D: `apps/chatbot/tests/test_story_2_3_integration.py`
- M: `apps/cwe_ingestion/embedder.py`

## docs

- M: `docs/architecture.md`
- M: `docs/architecture/development-workflow.md`
- ??: `docs/design/`
- M: `docs/plans/1.1.Project-Repository-Setup.md`
- M: `docs/plans/2.2.Contextual-Retrieval-and-Follow-ups.md`
- M: `docs/plans/2.3.Role-Based-Context-and-Hallucination-Mitigation.md`
- M: `docs/plans/2.5.Detailed-Design-Documentation.md`
- M: `docs/plans/MED-Security-Remediation.md`
- M: `docs/research/EmbeddingModelChoiceforCWEChatbot.md`
- ??: `docs/security/cwe_ingestion_security_assessment.md`
- M: `docs/stories/2.1/2.1-Security-Assessment.md`
- M: `docs/stories/2.1/Vulnerability-Assessment-Report.md`
- M: `docs/stories/2.2/Comprehensive-Security-Assessment-Report.md`
- M: `docs/stories/2.2/Security-Implementation-Summary.md`
- M: `docs/stories/2.2/Security-Validation-Report.md`
- M: `docs/stories/2.3/2.3.Security-Vulnerability-Assessment-Report.md`
- ??: `docs/stories/R-1.Refactor_chatbot.md`
- ??: `docs/stories/R1/`
- ??: `docs/stories/S-10-cwe-ingestion-security-fixes.md`

## mypy.ini

- ??: `mypy.ini`

## pyproject.toml

- M: `pyproject.toml`

## tests

- D: `tests/scripts/test_contextual_responder.py`
- D: `tests/scripts/test_cwe_relationship_manager.py`
- D: `tests/scripts/test_progressive_formatter.py`
- D: `tests/scripts/test_sql_injection_prevention_simple.py`
