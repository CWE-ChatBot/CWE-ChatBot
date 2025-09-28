Here is the full, end-to-end refactoring plan, combining all previous advice into a single, comprehensive guide for your developer.

Objective 🎯
The goal is to refactor the CWE Chatbot into a more modular, maintainable, and robust application. We will achieve this by:

Consolidating configuration into a single, environment-aware system.

Centralizing all business logic within the ProcessingPipeline.

Simplifying the ConversationManager to be a pure orchestrator.

Implementing a modern UI using Chainlit's native Action buttons instead of slash commands.

Phase 1: Configuration Refactoring (The Foundation)
This phase creates a single, authoritative src/config.py module that handles local development, testing, and production (GCP) environments correctly.

Step 1.1: Add Dependency
Ensure python-dotenv is in your project's requirements.txt.

# requirements.txt
python-dotenv
Step 1.2: Create the Environment Loader
Replace the entire content of src/config/env_loader.py with this code. It uses a single local context for all development and testing activities.

File: src/config/env_loader.py

Python

import os
import logging
from pathlib import Path
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

def load_environments():
    """
    Loads .env file based on `ENV_CONTEXT`. Prioritizes existing env variables.
    - 'local': For all local development and testing.
    - Unset/Other: For production (GCP), loads no .env file.
    """
    context = os.getenv("ENV_CONTEXT", "production").lower()
    
    # Using a single '.env.local' in the repo root for all local dev.
    # This is simpler than pointing to an external file.
    # You can change this path if you prefer.
    path_map = {
        "local": Path(".env.local")
    }

    if context != "local":
        logger.info(f"ENV_CONTEXT is '{context}'. No .env file will be loaded.")
        return

    path = path_map[context].resolve()
    if not path.exists():
        logger.warning(f"ENV_CONTEXT is 'local', but .env.local file not found at: {path}")
        return

    # `override=False` (default) ensures GCP-injected variables are not overwritten.
    load_dotenv(dotenv_path=path)
    logger.info(f"✅ Loaded environment variables from: {path}")
Step 1.3: Create the Authoritative src/config.py
Rename the file src/app_config_extended.py to src/config.py.

Modify the top of this new file to use the new loader.

File: src/config.py

Python

import os
from dataclasses import dataclass
from typing import Optional, Dict, Any
from .config.env_loader import load_environments

# This function must be called BEFORE the Config class is defined.
load_environments()

@dataclass
class Config:
    # --- NO CHANGES ARE NEEDED TO THE REST OF THIS CLASS ---
    pg_host: str = os.getenv("POSTGRES_HOST", "localhost")
    # ... rest of the file
Step 1.4: Clean Up
Delete the now-redundant file src/app_config.py.

Perform a project-wide Find and Replace for from src.app_config... import config and from src.app_config_extended... import config, replacing all instances with from src.config import config.

Phase 1 Checklist ✅
[ ] python-dotenv is added to requirements.txt.

[ ] src/config/env_loader.py is updated with the new code.

[ ] src/app_config_extended.py is renamed to src/config.py and its header is updated.

[ ] src/app_config.py is deleted.

[ ] All configuration imports throughout the project now point to src.config.

Phase 2: Decoupling and Centralizing Logic
This phase moves all business logic into the ProcessingPipeline, making it the "brain" of the application.

Step 2.1: Simplify CWEQueryHandler
Refactor src/query_handler.py to be a pure data access layer. Remove all logic for boosting scores, force-injecting results, and any other data manipulation. Its process_query method should only execute the hybrid search and return raw chunks.

Step 2.2: Create the AnalyzerModeHandler
Create a new file to handle the specific, stateful logic of the "CWE Analyzer" persona.

File: src/processing/analyzer_handler.py

Python

from src.user_context import UserContext
from src.processing.pipeline import ProcessingPipeline, PipelineResult

class AnalyzerModeHandler:
    def __init__(self, pipeline: ProcessingPipeline):
        self.pipeline = pipeline

    async def process(self, query: str, context: UserContext) -> PipelineResult:
        """Handles all logic for the CWE Analyzer persona modes."""
        specialized_query = query
        
        if context.analyzer_mode == "question":
            prev_ids = [r.get('cwe_id') for r in context.last_recommendations if r.get('cwe_id')]
            specialized_query = (
                f"{query}\n\n[Follow-up Instruction]\n"
                f"Prior recommendations: {', '.join(prev_ids)}\n"
                "Task: Address the user’s follow-up by referencing and, if needed, revising prior recommendations with clear reasoning."
            )
        elif context.analyzer_mode == "compare":
            # Comparison logic would also create a specialized prompt
            pass

        # Execute the main pipeline with the specialized query
        result = await self.pipeline.process_user_request(specialized_query, context)
        
        # Add post-response hints for the user
        if context.analyzer_mode:
            result.final_response_text += f"\n\n*(In {context.analyzer_mode} mode. You can `/exit` this mode)*"
        else:
            # The prompt to show Actions will be handled by the UI layer
            pass

        return result
Step 2.3: Enhance ProcessingPipeline
This is the most critical change. The pipeline will now orchestrate the entire RAG and validation flow.

File: src/processing/pipeline.py

Python

# Add new imports and dataclass
from dataclasses import dataclass, field
from src.query_handler import CWEQueryHandler
from src.response_generator import ResponseGenerator
from src.user_context import UserContext
from src.utils.text_post import harmonize_cwe_names_in_table
import re

@dataclass
class PipelineResult:
    final_response_text: str
    recommendations: List[dict] = field(default_factory=list)
    retrieved_cwes: List[str] = field(default_factory=list)
    # ... other fields for the UI if needed

class ProcessingPipeline:
    def __init__(self, query_handler: CWEQueryHandler, response_generator: ResponseGenerator):
        self.query_handler = query_handler
        self.response_generator = response_generator
        # ... initialize other components like ConfidenceCalculator, CWEFilter etc.

    async def process_user_request(self, query: str, user_context: UserContext) -> PipelineResult:
        # Step 1: Retrieve raw chunks
        raw_chunks = await self.query_handler.process_query(query, user_context.get_persona_preferences())

        # Step 2: Apply boosting/injection logic (moved from QueryHandler)
        processed_chunks = self._apply_retrieval_business_logic(query, raw_chunks)
        user_context.last_chunks = processed_chunks # Persist for follow-ups

        # Step 3: Generate initial recommendations
        scored_recs = self._calculate_recommendations(query, processed_chunks)
        user_context.last_recommendations = scored_recs # Persist for follow-ups

        # Step 4: Fetch metadata and build LLM prompt
        llm_prompt = self._build_llm_prompt(query, processed_chunks, scored_recs)

        # Step 5: Generate raw response from LLM
        raw_llm_response = await self.response_generator.generate_response_full_once(
            llm_prompt, processed_chunks, user_context.persona
        )

        # Step 6: Harmonize and Validate the LLM's output
        final_text = self._harmonize_and_validate_response(raw_llm_response)

        return PipelineResult(final_response_text=final_text, recommendations=scored_recs)

    def _apply_retrieval_business_logic(self, query: str, chunks: List[Dict]) -> List[Dict]:
        # Implement the boosting and force-injection logic here
        # This is where the code from the old QueryHandler.process_query goes
        return chunks # Placeholder

    def _calculate_recommendations(self, query: str, chunks: List[Dict]) -> List[Dict]:
        # Implement the logic from the old generate_recommendations method here
        # (aggregation, confidence scoring, filtering)
        return [] # Placeholder

    def _build_llm_prompt(self, query: str, chunks: List[Dict], recs: List[Dict]) -> str:
        # Implement prompt building, including fetching/adding canonical metadata
        return query # Placeholder

    def _harmonize_and_validate_response(self, llm_response: str) -> str:
        # This method fetches metadata for ALL CWEs in the final LLM response
        # and corrects the table, as described in the previous detailed plan.
        all_cwe_ids = [f"CWE-{c}" for c in re.findall(r"CWE[-_\s]?(\d{1,5})", llm_response, re.I)]
        if not all_cwe_ids: return llm_response
        
        canon_data = self.query_handler.get_canonical_cwe_metadata(all_cwe_ids)
        # ... fetch policy labels too
        # ... call harmonize_cwe_names_in_table(...)
        return llm_response # Placeholder for harmonized text
Phase 2 Checklist ✅
[ ] CWEQueryHandler is refactored to a simple data-access class.

[ ] src/processing/analyzer_handler.py is created with the AnalyzerModeHandler class.

[ ] ProcessingPipeline is updated with the PipelineResult dataclass and the new process_user_request method.

[ ] Business logic (boosting, harmonization) is moved into private methods within the ProcessingPipeline.

Phase 3: Refactoring the UI and Control Flow
This final phase simplifies the ConversationManager and implements the modern Chainlit Action UI.

Step 3.1: Refactor ConversationManager
This class becomes a thin orchestrator that delegates tasks to the appropriate handlers.

File: src/conversation.py

Python

# Add new imports
from src.processing.pipeline import ProcessingPipeline
from src.processing.analyzer_handler import AnalyzerModeHandler

class ConversationManager:
    def __init__(self, database_url: str, gemini_api_key: str):
        self.input_sanitizer = InputSanitizer()
        self.security_validator = SecurityValidator()
        self.query_handler = CWEQueryHandler(database_url, gemini_api_key)
        self.response_generator = ResponseGenerator(gemini_api_key)
        
        # Instantiate the pipeline and handlers with their dependencies
        self.processing_pipeline = ProcessingPipeline(self.query_handler, self.response_generator)
        self.analyzer_handler = AnalyzerModeHandler(self.processing_pipeline)
    
    async def process_user_message_streaming(self, session_id: str, message_content: str, message_id: str):
        # ... (keep initial security and off-topic checks)
        
        context = self.get_user_context(session_id)
        
        # Handle mode exit
        if context.analyzer_mode and message_content.strip().lower() == '/exit':
            context.analyzer_mode = None
            # ... save context and send confirmation ...
            return { ... }
        
        # Delegate to the correct handler
        if context.persona == "CWE Analyzer":
            result = await self.analyzer_handler.process(sanitized_q, context)
        else:
            result = await self.processing_pipeline.process_user_request(sanitized_q, context)
        
        # Stream the final, validated response to the UI
        msg = cl.Message(content="")
        await msg.stream_token(result.final_response_text)
        
        # ... (update conversation history using result data)
        return { "response": result.final_response_text, ... }
Step 3.2: Implement Chainlit Actions in main.py
Your main application entrypoint (main.py or app.py) will now contain the UI logic for handling action buttons.

File: main.py

Python

import chainlit as cl
from src.conversation import ConversationManager
from src.config import config
from src.utils.session import get_user_context, set_user_context

# Initialize the manager once
conversation_manager = ConversationManager(
    database_url=f"postgresql://{config.pg_user}:{config.pg_password}@{config.pg_host}:{config.pg_port}/{config.pg_database}",
    gemini_api_key=config.gemini_api_key
)

@cl.on_chat_start
async def on_chat_start():
    # ... your existing chat start logic ...
    # Store conversation manager if needed, or just use the global instance
    cl.user_session.set("id", "some_unique_id") # Ensure session ID is set

@cl.on_message
async def on_message(message: cl.Message):
    # The on_message function now just calls the refactored manager
    result_dict = await conversation_manager.process_user_message_streaming(
        session_id=cl.user_session.get("id"),
        message_content=message.content,
        message_id=getattr(message, 'id', None)
    )

    # After the main response, check if we need to show actions
    context = get_user_context()
    if context.persona == "CWE Analyzer" and not context.analyzer_mode:
        actions = [
            cl.Action(name="ask_question", value="ask", label="❓ Ask a Question"),
            cl.Action(name="compare_cwes", value="compare", label="⚖️ Compare CWEs")
        ]
        await cl.Message(content="Next steps:", actions=actions, author="System").send()

@cl.on_action
async def on_action(action: cl.Action):
    """Handles all action button clicks."""
    context = get_user_context()

    if action.value == "ask":
        context.analyzer_mode = "question"
        await cl.Message(content="**Question mode activated.** Ask a follow-up about the analysis.").send()
    elif action.value == "compare":
        context.analyzer_mode = "compare"
        await cl.Message(content="**Comparison mode activated.** Provide CWE IDs to compare.").send()

    # CRITICAL: Save the updated state back to the session
    set_user_context(context)
Phase 3 Checklist ✅
[ ] ConversationManager is refactored into a thin orchestrator.

[ ] main.py is updated with the new on_message logic.

[ ] The @cl.on_action handler is implemented in main.py and correctly manages state.

[ ] The logic to send the actions is triggered from on_message after a response is complete.

[ ] Old slash command parsing (except for /exit) is removed from ConversationManager.