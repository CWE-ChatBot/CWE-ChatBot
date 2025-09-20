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
from typing import Dict, Any, Optional

import chainlit as cl

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from user_context import UserContextManager, UserPersona, UserContext
    from conversation import ConversationManager
    from input_security import InputSanitizer, SecurityValidator
except ImportError as e:
    logging.error(f"Failed to import Story 2.1 components: {e}")
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global components (initialized on startup)
conversation_manager: Optional[ConversationManager] = None
input_sanitizer: Optional[InputSanitizer] = None
security_validator: Optional[SecurityValidator] = None


def initialize_components():
    """Initialize all Story 2.1 chatbot components with error handling."""
    global conversation_manager, input_sanitizer, security_validator

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
    """Initialize the chat session with persona selection."""
    global conversation_manager

    if not conversation_manager:
        await cl.Message(content="System is initializing. Please try again in a moment.").send()
        return

    # Create session and show persona selection
    welcome_message = """Welcome to the CWE ChatBot! 🛡️

I'm here to help you with Common Weakness Enumeration (CWE) information. To provide you with the most relevant responses, please select your role:

**Available Personas:**
• **PSIRT Member** - Impact assessment and advisory creation
• **Developer** - Remediation steps and code examples
• **Academic Researcher** - Comprehensive analysis and relationships
• **Bug Bounty Hunter** - Exploitation patterns and testing techniques
• **Product Manager** - Business impact and prevention strategies

Select your persona to get started:"""

    # Create persona selection actions (Chainlit 2.8.0 format)
    persona_actions = [
        cl.Action(name="persona_psirt", value="PSIRT Member", label="🚨 PSIRT Member", payload={}),
        cl.Action(name="persona_developer", value="Developer", label="💻 Developer", payload={}),
        cl.Action(name="persona_academic", value="Academic Researcher", label="🎓 Academic Researcher", payload={}),
        cl.Action(name="persona_bug_bounty", value="Bug Bounty Hunter", label="🔍 Bug Bounty Hunter", payload={}),
        cl.Action(name="persona_product_manager", value="Product Manager", label="📊 Product Manager", payload={})
    ]

    await cl.Message(content=welcome_message, actions=persona_actions).send()


@cl.on_message
async def main(message: cl.Message):
    """Handle incoming messages with Story 2.1 NLU and RAG pipeline."""

    # Check if components are initialized
    if not conversation_manager:
        await cl.Message(content="System is initializing. Please try again in a moment.").send()
        return

    # Check if user has selected a persona
    session_id = cl.context.session.id
    context = conversation_manager.get_session_context(session_id)

    if not context:
        await cl.Message(content="Please select your persona first using the buttons above before asking questions.").send()
        return

    try:
        user_query = message.content.strip()
        logger.info(f"Processing user query: '{user_query[:100]}...' for persona: {context.persona}")

        # Process message using conversation manager
        result = await conversation_manager.process_user_message(
            session_id=session_id,
            message_content=user_query,
            message_id=message.id
        )

        # Send response to user
        response_content = result["response"]

        # Add metadata for debugging if needed
        if not result.get("is_safe", True):
            logger.warning(f"Security flags detected: {result.get('security_flags', [])}")

        # Add action buttons for persona change
        actions = []
        if result.get("retrieved_cwes"):
            actions.append(cl.Action(name="change_persona", value="change_persona", label="Change Persona", payload={}))

        await cl.Message(content=response_content, actions=actions).send()

        # Log successful interaction
        logger.info(f"Successfully processed query for {context.persona}, retrieved {result.get('chunk_count', 0)} chunks")

    except Exception as e:
        # Secure error handling - never expose internal details
        logger.error(f"Error processing message: {e}")
        error_response = "I apologize, but I'm experiencing technical difficulties. Please try your question again in a moment."
        await cl.Message(content=error_response).send()


# Persona selection action callbacks

@cl.action_callback("persona_psirt")
async def on_select_psirt_persona(action):
    """Handle PSIRT Member persona selection."""
    await handle_persona_selection("PSIRT Member")

@cl.action_callback("persona_developer")
async def on_select_developer_persona(action):
    """Handle Developer persona selection."""
    await handle_persona_selection("Developer")

@cl.action_callback("persona_academic")
async def on_select_academic_persona(action):
    """Handle Academic Researcher persona selection."""
    await handle_persona_selection("Academic Researcher")

@cl.action_callback("persona_bug_bounty")
async def on_select_bug_bounty_persona(action):
    """Handle Bug Bounty Hunter persona selection."""
    await handle_persona_selection("Bug Bounty Hunter")

@cl.action_callback("persona_product_manager")
async def on_select_product_manager_persona(action):
    """Handle Product Manager persona selection."""
    await handle_persona_selection("Product Manager")

@cl.action_callback("change_persona")
async def on_change_persona(action):
    """Handle persona change request."""
    global conversation_manager

    if not conversation_manager:
        await cl.Message(content="System not available.").send()
        return

    # Show persona selection options
    welcome_message = "Please select your new persona:"

    persona_actions = [
        cl.Action(name="persona_psirt", value="PSIRT Member", label="🚨 PSIRT Member", payload={}),
        cl.Action(name="persona_developer", value="Developer", label="💻 Developer", payload={}),
        cl.Action(name="persona_academic", value="Academic Researcher", label="🎓 Academic Researcher", payload={}),
        cl.Action(name="persona_bug_bounty", value="Bug Bounty Hunter", label="🔍 Bug Bounty Hunter", payload={}),
        cl.Action(name="persona_product_manager", value="Product Manager", label="📊 Product Manager", payload={})
    ]

    await cl.Message(content=welcome_message, actions=persona_actions).send()


async def handle_persona_selection(persona: str):
    """Handle persona selection logic."""
    global conversation_manager

    if not conversation_manager:
        await cl.Message(content="System not available.").send()
        return

    try:
        session_id = cl.context.session.id

        # Update or create session with selected persona
        success = await conversation_manager.update_user_persona(session_id, persona)

        if not success:
            # Create new session if update failed - use Chainlit's session ID
            context = UserContext(session_id=session_id, persona=persona)
            conversation_manager.context_manager.active_sessions[session_id] = context
            success = True

        if success:
            # Get persona-specific welcome message
            persona_descriptions = {
                "PSIRT Member": "You'll receive responses focused on impact assessment, advisory creation, and CVSS considerations.",
                "Developer": "You'll receive responses focused on remediation steps, code examples, and prevention techniques.",
                "Academic Researcher": "You'll receive responses focused on comprehensive analysis, relationships, and taxonomies.",
                "Bug Bounty Hunter": "You'll receive responses focused on exploitation patterns, testing techniques, and detection methods.",
                "Product Manager": "You'll receive responses focused on business impact, prevention strategies, and trend analysis."
            }

            confirmation_message = f"""Great! Your persona has been set to **{persona}**.

{persona_descriptions.get(persona, "You'll receive responses tailored to your role.")}

I'm ready to help you with CWE information. You can:

• Ask about specific CWEs (e.g., "Tell me about CWE-79")
• Search for vulnerabilities by type (e.g., "SQL injection vulnerabilities")
• Get prevention guidance (e.g., "How to prevent buffer overflows")
• Learn about security concepts and relationships

What would you like to know about cybersecurity weaknesses?"""

            await cl.Message(content=confirmation_message).send()
            logger.info(f"Persona successfully set to {persona} for session {session_id}")
        else:
            await cl.Message(content="Sorry, there was an error setting your persona. Please try again.").send()
            logger.error(f"Failed to set persona to {persona}")

    except Exception as e:
        logger.error(f"Persona selection failed: {e}")
        await cl.Message(content="Sorry, there was an error with persona selection. Please try again.").send()


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