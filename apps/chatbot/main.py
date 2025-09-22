#!/usr/bin/env python3
"""
CWE ChatBot - Story 2.1 Implementation
Chainlit application with NLU, security sanitization, and RAG response generation.
Integrates with Story 1.5 production infrastructure.
"""

import asyncio
import logging
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional, Literal

import chainlit as cl
from pydantic import BaseModel, Field

# Add package root so `src.*` imports resolve
current_dir = Path(__file__).parent.absolute()
sys.path.insert(0, str(current_dir))

try:
    from src.user_context import UserPersona, UserContext
    from src.conversation import ConversationManager
    from src.input_security import InputSanitizer, SecurityValidator
    from src.file_processor import FileProcessor
except ImportError as e:
    logging.error(f"Failed to import Story 2.1 components: {e}")
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Pydantic Chat Settings for native UI
class UISettings(BaseModel):
    persona: Literal["PSIRT Member", "Developer", "Academic Researcher", "Bug Bounty Hunter", "Product Manager", "CWE Analyzer", "CVE Creator"] = Field(
        default="Developer",
        description="Your cybersecurity role - determines response focus and depth"
    )
    detail_level: Literal["basic", "standard", "detailed"] = Field(
        default="standard",
        description="Level of detail in responses"
    )
    include_examples: bool = Field(
        default=True,
        description="Include code examples and practical demonstrations"
    )
    include_mitigations: bool = Field(
        default=True,
        description="Include prevention and mitigation guidance"
    )

# Global components (initialized on startup)
conversation_manager: Optional[ConversationManager] = None
input_sanitizer: Optional[InputSanitizer] = None
security_validator: Optional[SecurityValidator] = None
file_processor: Optional[FileProcessor] = None


def initialize_components():
    """Initialize all Story 2.1 chatbot components with error handling."""
    global conversation_manager, input_sanitizer, security_validator, file_processor

    try:
        # Get required environment variables
        database_url = os.getenv('DATABASE_URL') or os.getenv('LOCAL_DATABASE_URL')
        gemini_api_key = os.getenv('GEMINI_API_KEY')

        if not database_url:
            raise ValueError("DATABASE_URL or LOCAL_DATABASE_URL environment variable required")
        if not gemini_api_key:
            raise ValueError("GEMINI_API_KEY environment variable required")

        logger.info(f"Initializing with database: {database_url[:50]}...")

        # Initialize security components
        input_sanitizer = InputSanitizer()
        security_validator = SecurityValidator()
        file_processor = FileProcessor()

        # Initialize conversation manager with all Story 2.1 components
        conversation_manager = ConversationManager(
            database_url=database_url,
            gemini_api_key=gemini_api_key
        )

        # Test database connection
        health = conversation_manager.get_system_health()
        if not health.get('database', False):
            raise RuntimeError("Database health check failed")

        logger.info(f"Story 2.1 components initialized successfully")
        logger.info(f"Database health: {health}")
        return True

    except Exception as e:
        logger.error(f"Component initialization failed: {e}")
        return False


@cl.on_chat_start
async def start():
    """Initialize the chat session with settings-based persona configuration."""
    global conversation_manager

    if not conversation_manager:
        await cl.Message(content="System is initializing. Please try again in a moment.").send()
        return

    # Initialize default settings
    default_settings = UISettings()
    cl.user_session.set("ui_settings", default_settings.dict())

    # Initialize per-user context in Chainlit with default persona
    session_id = cl.context.session.id
    await conversation_manager.update_user_persona(session_id, default_settings.persona)

    # Welcome message that guides users to the settings panel
    welcome_message = """Welcome to the CWE ChatBot! 🛡️

I'm here to help you with Common Weakness Enumeration (CWE) information.

**👆 Configure your experience using the Settings panel** (gear icon above) to:
• Select your cybersecurity role/persona
• Adjust detail level and preferences
• Customize response format

**Available Personas:**
• **PSIRT Member** - Impact assessment and advisory creation
• **Developer** - Remediation steps and code examples
• **Academic Researcher** - Comprehensive analysis and relationships
• **Bug Bounty Hunter** - Exploitation patterns and testing techniques
• **Product Manager** - Business impact and prevention strategies
• **CWE Analyzer** - CVE-to-CWE mapping analysis with confidence scoring
• **CVE Creator** - Structured CVE vulnerability descriptions

Once configured, ask me anything about cybersecurity weaknesses!"""

    await cl.Message(content=welcome_message).send()


@cl.on_message
async def main(message: cl.Message):
    """Handle incoming messages with Story 2.1 NLU and RAG pipeline."""

    # Check if components are initialized
    if not conversation_manager:
        await cl.Message(content="System is initializing. Please try again in a moment.").send()
        return

    # Get current settings and ensure session exists
    session_id = cl.context.session.id
    ui_settings = cl.user_session.get("ui_settings")

    if not ui_settings:
        # Initialize with defaults if missing
        default_settings = UISettings()
        ui_settings = default_settings.dict()
        cl.user_session.set("ui_settings", ui_settings)

    # Ensure conversation context exists with current persona (settings panel drives persona)
    context = conversation_manager.get_session_context(session_id)
    if not context or context.persona != ui_settings["persona"]:
        await conversation_manager.update_user_persona(session_id, ui_settings["persona"])

    try:
        user_query = message.content.strip()

        # Process file attachments if present (especially for CVE Creator)
        if hasattr(message, 'elements') and message.elements and file_processor:
            async with cl.Step(name="Process file attachments", type="tool") as file_step:
                file_step.input = f"Processing {len(message.elements)} file(s) for {ui_settings['persona']}"

                logger.info(f"Processing {len(message.elements)} file attachments for {ui_settings['persona']}")
                file_content = await file_processor.process_attachments(message)

                if file_content:
                    # Combine user query with file content
                    if user_query:
                        user_query = f"{user_query}\n\n--- Attached File Content ---\n{file_content}"
                    else:
                        user_query = f"--- Attached File Content ---\n{file_content}"

                    file_step.output = f"Extracted {len(file_content)} characters from file(s)"
                    logger.info(f"File content extracted: {len(file_content)} characters")
                else:
                    file_step.output = "No content extracted from file(s)"
                    logger.warning("File attachments found but no content extracted")

        logger.info(f"Processing user query: '{user_query[:100]}...' for persona: {ui_settings['persona']}")

        # Process message using conversation manager with streaming
        result = await conversation_manager.process_user_message_streaming(
            session_id=session_id,
            message_content=user_query,
            message_id=message.id
        )

        # Create source cards as Chainlit Elements if we have retrieved chunks
        elements = []
        if result.get("retrieved_cwes") and result.get("chunk_count", 0) > 0:
            # Get the retrieved chunks to create source elements
            retrieved_chunks = result.get("retrieved_chunks", [])

            # Group chunks by CWE and create source cards
            cwe_groups = {}
            for chunk in retrieved_chunks:
                cwe_id = chunk["metadata"]["cwe_id"]
                if cwe_id not in cwe_groups:
                    cwe_groups[cwe_id] = {
                        "name": chunk["metadata"]["name"],
                        "chunks": []
                    }
                cwe_groups[cwe_id]["chunks"].append(chunk)

            # Create source elements for each CWE
            for cwe_id, cwe_info in list(cwe_groups.items())[:3]:  # Limit to top 3 CWEs
                # Get best scoring chunk for this CWE
                best_chunk = max(cwe_info["chunks"], key=lambda x: x.get("scores", {}).get("hybrid", 0.0))
                score = best_chunk.get("scores", {}).get("hybrid", 0.0)

                # Create source content showing the CWE information
                source_content = f"**{cwe_id}: {cwe_info['name']}**\n\n"
                source_content += f"**Relevance Score:** {score:.3f}\n\n"

                # Add section content from the best chunk
                section = best_chunk["metadata"].get("section", "Content")
                source_content += f"**{section}:**\n"
                document_text = best_chunk["document"]

                # Truncate if too long
                if len(document_text) > 500:
                    source_content += document_text[:500] + "..."
                else:
                    source_content += document_text

                # Create Chainlit Text element for the source
                source_element = cl.Text(
                    name=f"Source: {cwe_id}",
                    content=source_content,
                    display="side"  # Display in sidebar
                )
                elements.append(source_element)

        # Add metadata for debugging if needed
        if not result.get("is_safe", True):
            logger.warning(f"Security flags detected: {result.get('security_flags', [])}")

        # The response was already streamed, just update the message with elements if needed
        if elements and result.get("message"):
            result["message"].elements = elements
            await result["message"].update()

        # Log successful interaction
        current_persona = ui_settings["persona"]
        logger.info(f"Successfully processed query for {current_persona}, retrieved {result.get('chunk_count', 0)} chunks")

    except Exception as e:
        # Secure error handling - never expose internal details
        logger.error(f"Error processing message: {e}")
        error_response = "I apologize, but I'm experiencing technical difficulties. Please try your question again in a moment."
        await cl.Message(content=error_response).send()


@cl.on_settings_update
async def on_settings_update(settings: Dict[str, Any]):
    """Handle settings updates from the native Chainlit settings panel."""
    global conversation_manager

    if not conversation_manager:
        return

    try:
        session_id = cl.context.session.id

        # Normalize settings to our UISettings model and persist
        model = UISettings(**settings) if isinstance(settings, dict) else UISettings()
        cl.user_session.set("ui_settings", model.dict())

        # Update persona in conversation manager if it changed
        current_context = conversation_manager.get_session_context(session_id)
        if current_context and current_context.persona != model.persona:
            success = await conversation_manager.update_user_persona(session_id, model.persona)
            if success:
                logger.info(f"Updated persona to {model.persona} for session {session_id}")

                # Send confirmation message
                await cl.Message(
                    content=f"✅ Settings updated! Now responding as **{model.persona}** with **{model.detail_level}** detail level.",
                    author="System"
                ).send()
            else:
                logger.error(f"Failed to update persona to {model.persona}")

    except Exception as e:
        logger.error(f"Settings update failed: {e}")


@cl.on_feedback
async def on_feedback(feedback):
    """Handle user feedback on messages."""
    global conversation_manager

    if not conversation_manager:
        logger.warning("Feedback received but conversation manager not initialized")
        return

    try:
        session_id = cl.context.session.id

        # Get message ID from feedback object
        # In current Chainlit, feedback has 'forId' attribute pointing to the message
        message_id = getattr(feedback, 'forId', getattr(feedback, 'for_id', None))

        if not message_id:
            logger.error("Feedback received but no message ID found")
            return

        # Convert Chainlit feedback to our rating system (1-5 scale)
        # Chainlit feedback.value is typically 1 (thumbs up) or 0 (thumbs down)
        feedback_value = getattr(feedback, 'value', None)
        if feedback_value is None:
            logger.error("Feedback received but no value found")
            return

        rating = 5 if feedback_value == 1 else 2  # Map thumbs up to 5, thumbs down to 2

        # Record feedback in conversation manager
        success = conversation_manager.record_feedback(session_id, message_id, rating)

        if success:
            logger.info(f"Recorded feedback for message {message_id}: rating {rating} (feedback value: {feedback_value})")
            # Optional: Send a brief acknowledgment (disabled to avoid noise)
            # await cl.Message(
            #     content="👍 Thank you for your feedback!",
            #     author="System"
            # ).send()
        else:
            logger.error(f"Failed to record feedback for message {message_id}")

    except Exception as e:
        logger.error(f"Error processing feedback: {e}")
        # Log feedback object structure for debugging
        logger.debug(f"Feedback object attributes: {dir(feedback) if feedback else 'None'}")




def main_cli():
    """CLI entry point for running the Story 2.1 application."""
    # Initialize components on startup
    if not initialize_components():
        logger.error("Failed to initialize Story 2.1 components. Exiting.")
        sys.exit(1)

    logger.info("CWE ChatBot Story 2.1 is ready to serve requests")


# Initialize components when module loads for Chainlit
initialize_components()

if __name__ == "__main__":
    # This allows running the app directly with: python main.py
    main_cli()

    # Note: Use 'poetry run chainlit run apps/chatbot/main.py' to start the application
    logger.info("To start the application, run: poetry run chainlit run apps/chatbot/main.py")
